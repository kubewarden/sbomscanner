package skippatterns

import "strings"

// ParseResult holds the classified skip patterns for trivy flags.
type ParseResult struct {
	SkipDirs  []string
	SkipFiles []string
}

// Parse classifies gitignore-style patterns into directory and file patterns.
// Patterns ending with "/" are directory patterns (trivy --skip-dirs).
// All other patterns are file patterns (trivy --skip-files).
// The trailing "/" is stripped from directory patterns.
func Parse(patterns []string) ParseResult {
	var result ParseResult

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if dir, ok := strings.CutSuffix(p, "/"); ok {
			result.SkipDirs = append(result.SkipDirs, dir)
		} else {
			result.SkipFiles = append(result.SkipFiles, p)
		}
	}

	return result
}
