package skippatterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantDirs []string
		wantFiles []string
	}{
		{
			name:     "nil input",
			patterns: nil,
		},
		{
			name:     "empty slice",
			patterns: []string{},
		},
		{
			name:      "directory pattern",
			patterns:  []string{"node_modules/"},
			wantDirs:  []string{"node_modules"},
		},
		{
			name:      "file pattern",
			patterns:  []string{"package-lock.json"},
			wantFiles: []string{"package-lock.json"},
		},
		{
			name:      "mixed patterns",
			patterns:  []string{"node_modules/", "*.min.js", ".git/", "package-lock.json"},
			wantDirs:  []string{"node_modules", ".git"},
			wantFiles: []string{"*.min.js", "package-lock.json"},
		},
		{
			name:      "glob directory pattern",
			patterns:  []string{"**/vendor/"},
			wantDirs:  []string{"**/vendor"},
		},
		{
			name:      "glob file pattern",
			patterns:  []string{"*.min.js"},
			wantFiles: []string{"*.min.js"},
		},
		{
			name:     "whitespace-only patterns are skipped",
			patterns: []string{"  ", "", "\t"},
		},
		{
			name:      "nested directory path",
			patterns:  []string{"foo/bar/"},
			wantDirs:  []string{"foo/bar"},
		},
		{
			name:      "absolute path without trailing slash is file",
			patterns:  []string{"/tmp"},
			wantFiles: []string{"/tmp"},
		},
		{
			name:      "absolute path with trailing slash is dir",
			patterns:  []string{"/tmp/"},
			wantDirs:  []string{"/tmp"},
		},
		{
			name:      "pattern with leading double star",
			patterns:  []string{"**/node_modules/"},
			wantDirs:  []string{"**/node_modules"},
		},
		{
			name:      "whitespace around pattern is trimmed",
			patterns:  []string{"  node_modules/  ", "  *.log  "},
			wantDirs:  []string{"node_modules"},
			wantFiles: []string{"*.log"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Parse(tt.patterns)
			assert.Equal(t, tt.wantDirs, result.SkipDirs)
			assert.Equal(t, tt.wantFiles, result.SkipFiles)
		})
	}
}
