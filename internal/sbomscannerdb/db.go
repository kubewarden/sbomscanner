package sbomscannerdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// schemaVersion is the tag of the artifact that this worker reads.
// It changes only when an older worker cannot read the new layout.
const schemaVersion = 1

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

// DB is the local copy of the sbomscanner database, queried per CVE.
// A nil *DB is disabled: Update does nothing and Lookup returns empty records.
// DB is not safe for concurrent use. The worker handles one scan at a time.
type DB struct {
	ref      string
	cacheDir string
	local    *oci.Store
	remote   *oci.Remote
	logger   *slog.Logger

	kev  *datafeed.Database
	epss *datafeed.Database
	// digest is the manifest digest of the loaded artifact, empty until the first load.
	digest string
}

// Open returns a DB for the artifact at repository, tagged with the schema version.
// The local copy lives under runDir/sbomscannerdb.
// It does not contact the registry or open any file. The first Update does both,
// and the databases stay open until Close.
func Open(repository, runDir string, cfg oci.Config, logger *slog.Logger) *DB {
	cacheDir := filepath.Join(runDir, cacheDirName)
	return &DB{
		ref:      repository + ":" + strconv.Itoa(schemaVersion),
		cacheDir: cacheDir,
		local:    oci.NewStore(filepath.Join(cacheDir, ociDirName), logger),
		remote:   oci.NewRemote(cfg, logger),
		logger:   logger,
	}
}

// Update pulls the artifact when the local copy is missing or past its nextUpdate,
// then loads it when it differs from the loaded one.
// It returns an error when the database cannot be updated.
func (db *DB) Update(ctx context.Context) error {
	if db == nil {
		return nil
	}

	view, err := db.local.Inspect(ctx, db.ref)
	if err != nil {
		db.logger.WarnContext(ctx, "cannot read the local sbomscanner DB, pulling", "ref", db.ref, "error", err)
	}
	stale := err != nil || !time.Now().Before(nextHorizon(view))
	if stale {
		if _, err := db.remote.Pull(ctx, db.local, db.ref); err != nil {
			return fmt.Errorf("pull sbomscanner DB %s: %w", db.ref, err)
		}
		if view, err = db.local.Inspect(ctx, db.ref); err != nil {
			return fmt.Errorf("inspect sbomscanner DB %s: %w", db.ref, err)
		}
	}

	if view.Digest == db.digest {
		return nil
	}
	if err := db.reload(ctx, view); err != nil {
		return fmt.Errorf("load sbomscanner DB: %w", err)
	}
	db.logger.InfoContext(ctx, "sbomscanner DB loaded", "ref", db.ref, "digest", view.Digest, "nextUpdate", view.Annotations[oci.AnnotationNextUpdate])
	return nil
}

// Lookup returns the record of cve, or a zero Record when there is none.
func (db *DB) Lookup(ctx context.Context, cve string) (Record, error) {
	if db == nil || db.kev == nil {
		return Record{}, nil
	}

	var record Record
	var kev datafeed.KEVVulnerability
	found, err := lookup(ctx, db.kev, cve, &kev)
	if err != nil {
		return Record{}, fmt.Errorf("look up %s in KEV: %w", cve, err)
	}
	if found {
		record.KEV = &storagev1alpha1.KEV{
			DateAdded:                  kev.DateAdded,
			DueDate:                    kev.DueDate,
			KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUse(kev.KnownRansomwareCampaignUse),
		}
	}
	var epss datafeed.EPSSEntry
	found, err = lookup(ctx, db.epss, cve, &epss)
	if err != nil {
		return Record{}, fmt.Errorf("look up %s in EPSS: %w", cve, err)
	}
	if found {
		record.EPSS = &storagev1alpha1.EPSS{
			Score:      strconv.FormatFloat(epss.EPSS, 'f', -1, 64),
			Percentile: strconv.FormatFloat(epss.Percentile, 'f', -1, 64),
			Date:       metav1.NewTime(epss.Date),
		}
	}
	return record, nil
}

// Close releases the open databases.
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	return db.closeFeeds()
}

// reload exports the artifact in view from the local store and opens its databases.
// On failure the previously opened databases stay in use.
func (db *DB) reload(ctx context.Context, view oci.ManifestView) error {
	if _, err := db.local.Export(ctx, db.ref, db.cacheDir); err != nil {
		return fmt.Errorf("export sbomscanner DB: %w", err)
	}
	kev, err := datafeed.OpenDatabase(ctx, filepath.Join(db.cacheDir, datafeed.KEVDBFileName))
	if err != nil {
		return fmt.Errorf("open KEV database: %w", err)
	}
	epss, err := datafeed.OpenDatabase(ctx, filepath.Join(db.cacheDir, datafeed.EPSSDBFileName))
	if err != nil {
		return errors.Join(fmt.Errorf("open EPSS database: %w", err), kev.Close())
	}

	if err := db.closeFeeds(); err != nil {
		db.logger.WarnContext(ctx, "failed to close the previous sbomscanner DB", "error", err)
	}
	db.kev = kev
	db.epss = epss
	db.digest = view.Digest
	return nil
}

func (db *DB) closeFeeds() error {
	var kevErr, epssErr error
	if db.kev != nil {
		kevErr = db.kev.Close()
		db.kev = nil
	}
	if db.epss != nil {
		epssErr = db.epss.Close()
		db.epss = nil
	}
	return errors.Join(kevErr, epssErr)
}

// lookup decodes the entry of cve from database into out.
// It returns false when the CVE has no entry.
func lookup(ctx context.Context, database *datafeed.Database, cve string, out any) (bool, error) {
	entry, err := database.Lookup(ctx, cve)
	if errors.Is(err, datafeed.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query entry: %w", err)
	}
	if err := json.Unmarshal(entry, out); err != nil {
		return false, fmt.Errorf("decode entry: %w", err)
	}
	return true, nil
}

// nextHorizon reads the nextUpdate annotation of view. A bad value yields the zero time,
// so the artifact counts as stale.
func nextHorizon(view oci.ManifestView) time.Time {
	next, err := time.Parse(time.RFC3339, view.Annotations[oci.AnnotationNextUpdate])
	if err != nil {
		return time.Time{}
	}
	return next
}
