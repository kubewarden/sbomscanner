package enrichment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// nextUpdateFileName is the file in the cache dir where the last pulled artifact's
// nextUpdate annotation is persisted, so the common-case freshness check needs no
// registry contact at all.
const nextUpdateFileName = "nextUpdate"

// cacheDirName is the enrichment cache subdirectory under the worker run dir.
const cacheDirName = "enrichment"

// DefaultCacheDir returns the enrichment cache directory nested under runDir.
func DefaultCacheDir(runDir string) string {
	return filepath.Join(runDir, cacheDirName)
}

// CleanCache removes any enrichment cache left over from a previous run. When the
// worker's run directory is backed by a persistent volume, files such as the
// persisted nextUpdate horizon survive a pod restart and can make the store
// believe its cache is still fresh. Wiping the directory on startup forces a
// clean pull. A missing directory is not an error.
func CleanCache(runDir string, logger *slog.Logger) {
	dir := DefaultCacheDir(runDir)
	if err := os.RemoveAll(dir); err != nil {
		logger.Warn("Failed to clean up stale enrichment cache", "dir", dir, "error", err)
		return
	}
	logger.Info("Cleaned up stale enrichment cache", "dir", dir)
}

// Enrichment is the auxiliary context looked up for a single CVE.
// The zero value means "no enrichment data" (unknown CVE or no cache).
type Enrichment struct {
	// KnownExploited is true when the CVE is in the CISA KEV catalog.
	KnownExploited bool
	// EPSSScore is the exploit-probability score; valid only when EPSSFound.
	EPSSScore float64
	// EPSSPercentile is the score's percentile; valid only when EPSSFound.
	EPSSPercentile float64
	// EPSSFound reports whether the CVE had an EPSS row.
	EPSSFound bool
}

// Store owns the local enrichment cache: it pulls the DB artifact lazily, unpacks it,
// and holds in-memory indices keyed by CVE ID for cheap lookups during scans.
// A nil *Store is a valid no-op (feature disabled) and returns empty enrichments.
type Store struct {
	ref      string
	cacheDir string
	remote   *oci.Remote
	logger   *slog.Logger

	mu   sync.RWMutex
	kev  map[string]struct{}
	epss map[string]datafeed.EPSSScore
	// nextUpdate is the freshness horizon of the currently loaded cache; while
	// now < nextUpdate the store serves from memory without touching the registry.
	nextUpdate time.Time
	loaded     bool
}

// New returns a Store that pulls the artifact at ref into cacheDir.
// It does not contact the registry; call Refresh to populate the cache.
func New(ref, cacheDir string, cfg oci.Config, logger *slog.Logger) *Store {
	return &Store{
		ref:      ref,
		cacheDir: cacheDir,
		remote:   oci.NewRemote(cfg, logger),
		logger:   logger,
		kev:      map[string]struct{}{},
		epss:     map[string]datafeed.EPSSScore{},
	}
}

// Update ensures the local cache is reasonably fresh, contacting the registry only
// when the persisted nextUpdate horizon has passed. A registry failure is never
// fatal: the store keeps serving whatever it already has (possibly nothing) and the
// error is logged, so scans continue with stale-or-absent enrichment data.
func (s *Store) Update(ctx context.Context) {
	if s == nil {
		return
	}

	// On first Update, adopt any cache left on disk from a previous run so a
	// registry outage at startup still yields enrichment data.
	if !s.loaded {
		s.bootstrapFromDisk(ctx)
	}

	// If the current time is before the freshness horizon, no update is needed.
	if time.Now().Before(s.horizon()) {
		return
	}

	view, err := s.remote.Inspect(ctx, s.ref)
	if err != nil {
		s.logger.WarnContext(ctx, "enrichment DB inspect failed, serving existing cache", "ref", s.ref, "error", err)
		return
	}

	remoteNext, err := parseNextUpdate(view.Annotations[oci.AnnotationNextUpdate])
	if err != nil {
		s.logger.WarnContext(ctx, "enrichment DB has no usable nextUpdate annotation, pulling anyway", "ref", s.ref, "error", err)
	} else if s.loaded && !remoteNext.After(s.horizon()) {
		// Registry has nothing newer than what we already serve; refresh the horizon
		// so we don't re-inspect on every scan until the next window.
		s.setHorizon(remoteNext)
		return
	}

	if err := os.MkdirAll(s.cacheDir, 0o750); err != nil {
		s.logger.WarnContext(ctx, "failed to create enrichment cache dir, serving existing cache", "dir", s.cacheDir, "error", err)
		return
	}
	if _, err := s.remote.Pull(ctx, s.ref, s.cacheDir); err != nil {
		s.logger.WarnContext(ctx, "enrichment DB pull failed, serving existing cache", "ref", s.ref, "error", err)
		return
	}

	if err := s.load(ctx); err != nil {
		s.logger.WarnContext(ctx, "failed to load pulled enrichment DB, serving existing cache", "error", err)
		return
	}
	s.setHorizon(remoteNext)
	s.persistNextUpdate(ctx, remoteNext)
	s.logger.InfoContext(ctx, "enrichment DB refreshed", "ref", s.ref, "kev", len(s.kev), "epss", len(s.epss), "nextUpdate", remoteNext)
}

// Lookup returns the enrichment for cve, or a zero Enrichment when the CVE is absent
// or no cache is loaded.
func (s *Store) Lookup(cve string) Enrichment {
	if s == nil {
		return Enrichment{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var e Enrichment
	if _, ok := s.kev[cve]; ok {
		e.KnownExploited = true
	}
	if score, ok := s.epss[cve]; ok {
		e.EPSSScore = score.EPSS
		e.EPSSPercentile = score.Percentile
		e.EPSSFound = true
	}
	return e
}

// bootstrapFromDisk loads a cache directory that already holds feed files (e.g. left
// by a prior run) and its persisted nextUpdate, so the store is usable before any
// successful registry contact.
func (s *Store) bootstrapFromDisk(ctx context.Context) {
	if err := s.load(ctx); err != nil {
		// No usable on-disk cache yet; that's expected on a truly first run.
		s.logger.DebugContext(ctx, "no existing enrichment cache to bootstrap", "dir", s.cacheDir, "error", err)
		return
	}
	if next, err := readNextUpdate(s.cacheDir); err == nil {
		s.setHorizon(next)
	}
	s.logger.InfoContext(ctx, "bootstrapped enrichment DB from disk cache", "kev", len(s.kev), "epss", len(s.epss))
}

// load parses the KEV and EPSS files from the cache dir and swaps in fresh indices.
// It fails only when neither feed can be read; a single missing/unparseable feed is
// tolerated so the other still enriches.
func (s *Store) load(ctx context.Context) error {
	kev, kevErr := loadKEV(filepath.Join(s.cacheDir, datafeed.KEVFileName))
	if kevErr != nil {
		s.logger.DebugContext(ctx, "KEV feed unavailable", "error", kevErr)
	}
	epss, epssErr := loadEPSS(filepath.Join(s.cacheDir, datafeed.EPSSFileName))
	if epssErr != nil {
		s.logger.DebugContext(ctx, "EPSS feed unavailable", "error", epssErr)
	}
	if kevErr != nil && epssErr != nil {
		return errors.New("no enrichment feeds could be loaded")
	}

	s.mu.Lock()
	s.kev = kev
	s.epss = epss
	s.loaded = true
	s.mu.Unlock()
	return nil
}

func loadKEV(path string) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return map[string]struct{}{}, fmt.Errorf("open KEV catalog %s: %w", path, err)
	}
	defer file.Close()

	catalog, err := datafeed.ParseKEVCatalog(file)
	if err != nil {
		return map[string]struct{}{}, fmt.Errorf("parse KEV catalog %s: %w", path, err)
	}
	index := make(map[string]struct{}, len(catalog.Vulnerabilities))
	for _, vuln := range catalog.Vulnerabilities {
		index[vuln.CVEID] = struct{}{}
	}
	return index, nil
}

func loadEPSS(path string) (map[string]datafeed.EPSSScore, error) {
	file, err := os.Open(path)
	if err != nil {
		return map[string]datafeed.EPSSScore{}, fmt.Errorf("open EPSS scores %s: %w", path, err)
	}
	defer file.Close()

	scores, err := datafeed.ParseEPSSScores(file)
	if err != nil {
		return map[string]datafeed.EPSSScore{}, fmt.Errorf("parse EPSS scores %s: %w", path, err)
	}
	index := make(map[string]datafeed.EPSSScore, len(scores.Scores))
	for _, score := range scores.Scores {
		index[score.CVE] = score
	}
	return index, nil
}

func (s *Store) horizon() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextUpdate
}

func (s *Store) setHorizon(t time.Time) {
	s.mu.Lock()
	s.nextUpdate = t
	s.mu.Unlock()
}

func (s *Store) persistNextUpdate(ctx context.Context, t time.Time) {
	if t.IsZero() {
		return
	}
	path := filepath.Join(s.cacheDir, nextUpdateFileName)
	if err := os.WriteFile(path, []byte(t.UTC().Format(time.RFC3339)), 0o600); err != nil {
		s.logger.WarnContext(ctx, "failed to persist enrichment nextUpdate", "path", path, "error", err)
	}
}

func readNextUpdate(cacheDir string) (time.Time, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, nextUpdateFileName))
	if err != nil {
		return time.Time{}, fmt.Errorf("read nextUpdate file: %w", err)
	}
	return parseNextUpdate(string(data))
}

func parseNextUpdate(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("empty nextUpdate")
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse nextUpdate %q: %w", value, err)
	}
	return t, nil
}
