// Package skippatterns classifies gitignore-style skip patterns into
// directory and file categories for use with trivy's --skip-dirs and
// --skip-files flags.
//
// Patterns ending with "/" are treated as directories; all others are
// treated as files. Glob syntax (e.g. "**/vendor/", "*.min.js") is
// passed through as-is since trivy handles expansion natively.
package skippatterns
