package datafeed

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// EPSSFileName is the file name of the EPSS scores in the destination directory.
const EPSSFileName = "epss_scores.csv"

// defaultEPSSURL is the daily EPSS bulk feed (gzipped CSV).
const defaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// epssHeader is the expected CSV header of the EPSS bulk feed.
var epssHeader = []string{"cve", "epss", "percentile"}

// EPSSScores is the parsed FIRST EPSS daily bulk feed.
type EPSSScores struct {
	// ModelVersion comes from the leading "#model_version:..." metadata line (e.g. v2026.06.15).
	ModelVersion string
	// ScoreDate comes from the same metadata line (RFC3339).
	ScoreDate string
	Scores    []EPSSScore
}

// EPSSScore is one CVE row of the feed.
type EPSSScore struct {
	CVE        string
	EPSS       float64
	Percentile float64
}

// ParseEPSSScores parses and sanity-checks an EPSS bulk feed CSV:
// it must carry the cve,epss,percentile header and at least one row,
// each with a CVE ID and numeric scores.
func ParseEPSSScores(reader io.Reader) (*EPSSScores, error) {
	buffered := bufio.NewReader(reader)
	scores := &EPSSScores{}

	// The feed opens with a "#model_version:...,score_date:..." comment line.
	// It is informational: capture it when present, without requiring it.
	if peeked, err := buffered.Peek(1); err == nil && peeked[0] == '#' {
		line, err := buffered.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read EPSS metadata line: %w", err)
		}
		scores.ModelVersion, scores.ScoreDate = parseEPSSMetadata(line)
	}

	csvReader := csv.NewReader(buffered)
	csvReader.Comment = '#'

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("read EPSS header: %w", err)
	}
	if !slices.Equal(header, epssHeader) {
		return nil, fmt.Errorf("unexpected EPSS header %v, want %v", header, epssHeader)
	}

	for {
		// The csv reader enforces the header's field count on every row.
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read EPSS row %d: %w", len(scores.Scores)+1, err)
		}
		score, err := parseEPSSRecord(record)
		if err != nil {
			return nil, fmt.Errorf("EPSS row %d: %w", len(scores.Scores)+1, err)
		}
		scores.Scores = append(scores.Scores, score)
	}
	if len(scores.Scores) == 0 {
		return nil, errors.New("EPSS feed has no score rows")
	}
	return scores, nil
}

// parseEPSSRecord converts one cve,epss,percentile record into an EPSSScore.
func parseEPSSRecord(record []string) (EPSSScore, error) {
	if record[0] == "" {
		return EPSSScore{}, errors.New("empty cve")
	}
	epss, err := strconv.ParseFloat(record[1], 64)
	if err != nil {
		return EPSSScore{}, fmt.Errorf("invalid epss score %q: %w", record[1], err)
	}
	percentile, err := strconv.ParseFloat(record[2], 64)
	if err != nil {
		return EPSSScore{}, fmt.Errorf("invalid percentile %q: %w", record[2], err)
	}
	return EPSSScore{CVE: record[0], EPSS: epss, Percentile: percentile}, nil
}

// parseEPSSMetadata extracts model_version and score_date from the leading
// comment line; keys that are absent simply yield empty strings.
func parseEPSSMetadata(line string) (string, string) {
	var modelVersion, scoreDate string
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	for pair := range strings.SplitSeq(line, ",") {
		key, value, found := strings.Cut(pair, ":")
		if !found {
			continue
		}
		switch key {
		case "model_version":
			modelVersion = value
		case "score_date":
			scoreDate = value
		}
	}
	return modelVersion, scoreDate
}

// EPSSDownloader downloads the EPSS scores feed.
type EPSSDownloader struct {
	http   *HTTPDownloader
	logger *slog.Logger
	url    string
}

// NewEPSSDownloader returns an EPSSDownloader fetching from the official EPSS bulk feed.
func NewEPSSDownloader(httpDownloader *HTTPDownloader, logger *slog.Logger) *EPSSDownloader {
	return &EPSSDownloader{
		http:   httpDownloader,
		logger: logger,
		url:    defaultEPSSURL,
	}
}

// Download fetches the EPSS scores (gzipped CSV, decompressed on the fly)
// into dir/EPSSFileName and validates that it parses as a usable feed.
func (d *EPSSDownloader) Download(ctx context.Context, dir string) error {
	dst := filepath.Join(dir, EPSSFileName)
	d.logger.InfoContext(ctx, "downloading EPSS scores", "url", d.url)
	size, err := d.http.Download(ctx, d.url, dst)
	if err != nil {
		return fmt.Errorf("download EPSS: %w", err)
	}

	scores, err := parseEPSSFile(dst)
	if err != nil {
		return fmt.Errorf("validate EPSS: %w", err)
	}

	d.logger.InfoContext(ctx, "downloaded EPSS scores", "file", EPSSFileName, "bytes", size, "rows", len(scores.Scores), "modelVersion", scores.ModelVersion)
	return nil
}

// parseEPSSFile opens the file at path and parses it as an EPSS feed.
func parseEPSSFile(path string) (*EPSSScores, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	return ParseEPSSScores(file)
}
