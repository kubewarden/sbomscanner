package sbomscannerdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// cacheDirName is the database directory under the worker run dir.
const cacheDirName = "sbomscannerdb"

// ociDirName is the OCI image layout under the cache dir that holds the pulled artifact.
const ociDirName = "oci"

// Record is the database entry of one CVE. The zero value means no data.
type Record struct {
	// KEV is the CISA KEV catalog entry, nil when the CVE is not in the catalog.
	KEV *storagev1alpha1.KEV
	// EPSS is the EPSS score, nil when the CVE has no score.
	EPSS *storagev1alpha1.EPSS
}

// DB is the local copy of the sbomscanner database, indexed in memory by CVE.
// A nil *DB is disabled: Update does nothing and Lookup returns empty records.
type DB struct {
	ref      string
	cacheDir string
	local    *oci.Store
	remote   *oci.Remote
	logger   *slog.Logger

	mu   sync.RWMutex
	kev  map[string]storagev1alpha1.KEV
	epss map[string]storagev1alpha1.EPSS
	// digest is the manifest digest of the loaded artifact, empty until the first load.
	digest string
	// horizon is the nextUpdate of the loaded artifact. Before it, Update skips the registry.
	horizon time.Time
}

// New returns a DB for the artifact at ref, stored under runDir/sbomscannerdb.
// It does not contact the registry. Call Update to load the data.
func New(ref, runDir string, cfg oci.Config, logger *slog.Logger) *DB {
	cacheDir := filepath.Join(runDir, cacheDirName)
	return &DB{
		ref:      ref,
		cacheDir: cacheDir,
		local:    oci.NewStore(filepath.Join(cacheDir, ociDirName), logger),
		remote:   oci.NewRemote(cfg, logger),
		logger:   logger,
		kev:      map[string]storagev1alpha1.KEV{},
		epss:     map[string]storagev1alpha1.EPSS{},
	}
}

// Update pulls a newer artifact when the loaded one is past its nextUpdate.
// It returns an error when the database cannot be updated.
func (db *DB) Update(ctx context.Context) error {
	if db == nil {
		return nil
	}

	// On the first call, load what a previous run left in the local store.
	if db.loadedDigest() == "" {
		if view, err := db.local.Inspect(ctx, db.ref); err == nil {
			if err := db.reload(ctx, view); err != nil {
				return fmt.Errorf("load sbomscanner DB from local store: %w", err)
			}
			db.logger.InfoContext(ctx, "loaded sbomscanner DB from local store", "ref", db.ref, "digest", view.Digest, "kev", len(db.kev), "epss", len(db.epss))
		}
	}

	if time.Now().Before(db.freshUntil()) {
		return nil
	}

	pulled, err := db.remote.Pull(ctx, db.local, db.ref)
	if err != nil {
		return fmt.Errorf("pull sbomscanner DB %s: %w", db.ref, err)
	}
	view, err := db.local.Inspect(ctx, db.ref)
	if err != nil {
		return fmt.Errorf("inspect sbomscanner DB %s: %w", db.ref, err)
	}

	if pulled.Digest == db.loadedDigest() {
		db.setHorizon(nextHorizon(view))
		return nil
	}

	if err := db.reload(ctx, view); err != nil {
		return fmt.Errorf("load sbomscanner DB: %w", err)
	}
	db.logger.InfoContext(ctx, "sbomscanner DB refreshed", "ref", db.ref, "digest", view.Digest, "kev", len(db.kev), "epss", len(db.epss), "nextUpdate", view.Annotations[oci.AnnotationNextUpdate])
	return nil
}

// Lookup returns the record of cve, or a zero Record when there is none.
func (db *DB) Lookup(cve string) Record {
	if db == nil {
		return Record{}
	}
	db.mu.RLock()
	defer db.mu.RUnlock()

	var record Record
	if kev, ok := db.kev[cve]; ok {
		record.KEV = &kev
	}
	if epss, ok := db.epss[cve]; ok {
		record.EPSS = &epss
	}
	return record
}

// reload exports the artifact in view from the local store and loads its feeds.
func (db *DB) reload(ctx context.Context, view oci.ManifestView) error {
	if _, err := db.local.Export(ctx, db.ref, db.cacheDir); err != nil {
		return fmt.Errorf("export sbomscanner DB: %w", err)
	}
	if err := db.load(ctx); err != nil {
		return err
	}
	db.mu.Lock()
	db.digest = view.Digest
	db.horizon = nextHorizon(view)
	db.mu.Unlock()
	return nil
}

// load parses the KEV and EPSS files from the cache dir.
// It fails only when neither feed can be read.
func (db *DB) load(ctx context.Context) error {
	kev, kevErr := loadKEV(filepath.Join(db.cacheDir, datafeed.KEVFileName))
	if kevErr != nil {
		db.logger.DebugContext(ctx, "KEV feed unavailable", "error", kevErr)
	}
	epss, epssErr := loadEPSS(filepath.Join(db.cacheDir, datafeed.EPSSFileName))
	if epssErr != nil {
		db.logger.DebugContext(ctx, "EPSS feed unavailable", "error", epssErr)
	}
	if kevErr != nil && epssErr != nil {
		return errors.New("no feeds could be loaded")
	}

	db.mu.Lock()
	db.kev = kev
	db.epss = epss
	db.mu.Unlock()
	return nil
}

func (db *DB) loadedDigest() string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.digest
}

func (db *DB) freshUntil() time.Time {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.horizon
}

func (db *DB) setHorizon(t time.Time) {
	db.mu.Lock()
	db.horizon = t
	db.mu.Unlock()
}

// nextHorizon reads the nextUpdate annotation of view. A bad value yields the zero time.
func nextHorizon(view oci.ManifestView) time.Time {
	next, err := time.Parse(time.RFC3339, view.Annotations[oci.AnnotationNextUpdate])
	if err != nil {
		return time.Time{}
	}
	return next
}

func loadKEV(path string) (map[string]storagev1alpha1.KEV, error) {
	file, err := os.Open(path)
	if err != nil {
		return map[string]storagev1alpha1.KEV{}, fmt.Errorf("open KEV catalog %s: %w", path, err)
	}
	defer file.Close()

	catalog, err := datafeed.ParseKEVCatalog(file)
	if err != nil {
		return map[string]storagev1alpha1.KEV{}, fmt.Errorf("parse KEV catalog %s: %w", path, err)
	}
	index := make(map[string]storagev1alpha1.KEV, len(catalog.Vulnerabilities))
	for _, vuln := range catalog.Vulnerabilities {
		index[vuln.CVEID] = storagev1alpha1.KEV{
			DateAdded:                  vuln.DateAdded,
			DueDate:                    vuln.DueDate,
			KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUse(vuln.KnownRansomwareCampaignUse),
		}
	}
	return index, nil
}

func loadEPSS(path string) (map[string]storagev1alpha1.EPSS, error) {
	file, err := os.Open(path)
	if err != nil {
		return map[string]storagev1alpha1.EPSS{}, fmt.Errorf("open EPSS scores %s: %w", path, err)
	}
	defer file.Close()

	scores, err := datafeed.ParseEPSSScores(file)
	if err != nil {
		return map[string]storagev1alpha1.EPSS{}, fmt.Errorf("parse EPSS scores %s: %w", path, err)
	}
	scoreDate, err := time.Parse(time.RFC3339, scores.ScoreDate)
	if err != nil {
		return map[string]storagev1alpha1.EPSS{}, fmt.Errorf("parse EPSS score_date %q in %s: %w", scores.ScoreDate, path, err)
	}
	index := make(map[string]storagev1alpha1.EPSS, len(scores.Scores))
	for _, score := range scores.Scores {
		index[score.CVE] = storagev1alpha1.EPSS{
			Score:      strconv.FormatFloat(score.EPSS, 'f', -1, 64),
			Percentile: strconv.FormatFloat(score.Percentile, 'f', -1, 64),
			Date:       metav1.NewTime(scoreDate),
		}
	}
	return index, nil
}
