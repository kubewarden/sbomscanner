package datafeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// KEVSourceFileName is the file name of the KEV catalog as downloaded from CISA.
const KEVSourceFileName = "known_exploited_vulnerabilities.json"

// KEVDBFileName is the file name of the KEV database built from the catalog.
const KEVDBFileName = "kev.sqlite"

// defaultKEVURL is the CISA KEV catalog feed.
const defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVCatalog is the CISA Known Exploited Vulnerabilities catalog document.
type KEVCatalog struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    time.Time          `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []KEVVulnerability `json:"vulnerabilities"`
}

// KEVVulnerability is one KEV catalog entry.
type KEVVulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"` // date-only (e.g. 2021-12-10)
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"` // date-only
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`

	// raw is the entry as CISA published it, kept so the database stores
	// fields this struct does not know yet.
	raw json.RawMessage
}

// ParseKEVCatalog parses and sanity-checks a KEV catalog JSON document:
// it must decode into a KEVCatalog with at least one vulnerability entry,
// each carrying a CVE ID (the field consumers key on).
func ParseKEVCatalog(reader io.Reader) (*KEVCatalog, error) {
	var document struct {
		KEVCatalog

		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(reader).Decode(&document); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	if len(document.Vulnerabilities) == 0 {
		return nil, errors.New("KEV catalog has no vulnerability entries")
	}
	catalog := document.KEVCatalog
	catalog.Vulnerabilities = make([]KEVVulnerability, 0, len(document.Vulnerabilities))
	for i, raw := range document.Vulnerabilities {
		var vulnerability KEVVulnerability
		if err := json.Unmarshal(raw, &vulnerability); err != nil {
			return nil, fmt.Errorf("parse KEV catalog: vulnerability entry %d: %w", i, err)
		}
		if vulnerability.CVEID == "" {
			return nil, fmt.Errorf("KEV catalog: vulnerability entry %d has an empty cveID", i)
		}
		vulnerability.raw = raw
		catalog.Vulnerabilities = append(catalog.Vulnerabilities, vulnerability)
	}
	return &catalog, nil
}

// KEVDownloader downloads the CISA Known Exploited Vulnerabilities catalog.
type KEVDownloader struct {
	http   *HTTPDownloader
	logger *slog.Logger
	url    string
}

// NewKEVDownloader returns a KEVDownloader fetching from the official CISA feed.
func NewKEVDownloader(httpDownloader *HTTPDownloader, logger *slog.Logger) *KEVDownloader {
	return &KEVDownloader{
		http:   httpDownloader,
		logger: logger,
		url:    defaultKEVURL,
	}
}

// Name is the short feed id.
func (d *KEVDownloader) Name() string { return "kev" }

// Download fetches the KEV catalog (JSON) into dir.
func (d *KEVDownloader) Download(ctx context.Context, dir string) error {
	d.logger.InfoContext(ctx, "downloading KEV catalog", "url", d.url)
	size, err := d.http.Download(ctx, d.url, filepath.Join(dir, KEVSourceFileName))
	if err != nil {
		return fmt.Errorf("download KEV: %w", err)
	}
	d.logger.InfoContext(ctx, "downloaded KEV catalog", "bytes", size)
	return nil
}

// BuildSQLite parses srcDir/KEVSourceFileName and writes dstDir/KEVDBFileName.
// Each entry is stored as CISA published it.
func (d *KEVDownloader) BuildSQLite(ctx context.Context, srcDir, dstDir string) (string, error) {
	catalog, err := parseKEVFile(filepath.Join(srcDir, KEVSourceFileName))
	if err != nil {
		return "", fmt.Errorf("validate KEV: %w", err)
	}
	entries := make([]Entry, 0, len(catalog.Vulnerabilities))
	for _, vulnerability := range catalog.Vulnerabilities {
		entries = append(entries, Entry{CVE: vulnerability.CVEID, JSON: vulnerability.raw})
	}
	if err := writeDatabase(ctx, filepath.Join(dstDir, KEVDBFileName), entries); err != nil {
		return "", fmt.Errorf("build KEV database: %w", err)
	}
	d.logger.InfoContext(ctx, "built KEV database", "file", KEVDBFileName, "entries", len(entries))
	return KEVDBFileName, nil
}

// parseKEVFile opens the file at path and parses it as a KEV catalog.
func parseKEVFile(path string) (*KEVCatalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	return ParseKEVCatalog(file)
}
