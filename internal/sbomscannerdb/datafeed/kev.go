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

// KEVFileName is the file name of the KEV catalog in the destination directory.
const KEVFileName = "known_exploited_vulnerabilities.json"

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
}

// ParseKEVCatalog parses and sanity-checks a KEV catalog JSON document:
// it must decode into a KEVCatalog with at least one vulnerability entry,
// each carrying a CVE ID (the field consumers key on).
func ParseKEVCatalog(reader io.Reader) (*KEVCatalog, error) {
	var catalog KEVCatalog
	if err := json.NewDecoder(reader).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil, errors.New("KEV catalog has no vulnerability entries")
	}
	for i, vulnerability := range catalog.Vulnerabilities {
		if vulnerability.CVEID == "" {
			return nil, fmt.Errorf("KEV catalog: vulnerability entry %d has an empty cveID", i)
		}
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

// Download fetches the KEV catalog (JSON) into dir/KEVFileName
// and validates that it parses as a usable catalog.
func (d *KEVDownloader) Download(ctx context.Context, dir string) error {
	dst := filepath.Join(dir, KEVFileName)
	d.logger.InfoContext(ctx, "downloading KEV catalog", "url", d.url)
	size, err := d.http.Download(ctx, d.url, dst)
	if err != nil {
		return fmt.Errorf("download KEV: %w", err)
	}

	catalog, err := parseKEVFile(dst)
	if err != nil {
		return fmt.Errorf("validate KEV: %w", err)
	}

	d.logger.InfoContext(ctx, "downloaded KEV catalog", "file", KEVFileName, "bytes", size, "entries", len(catalog.Vulnerabilities))
	return nil
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
