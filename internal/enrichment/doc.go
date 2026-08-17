// Package enrichment consumes the sbomscanner enrichment vulnerability database
// (an OCI artifact carrying KEV, EPSS, … feeds) and serves per-CVE lookups from a
// local cache. It reuses the OCI pull/inspect primitives and feed parsers from the
// internal/sbomscannerdb packages; the enrichment data is optional, so a missing or
// stale cache degrades gracefully to unenriched lookups rather than blocking scans.
package enrichment
