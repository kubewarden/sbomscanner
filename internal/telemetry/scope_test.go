package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestScopeName_Empty returns the bare module root,
// so callers that don't want a sub-scope get the project-level identifier.
func TestScopeName_Empty(t *testing.T) {
	assert.Equal(t, "github.com/kubewarden/sbomscanner", scopeName(""))
}

// TestScopeName_PkgPath prefixes the module root onto the repo-relative path,
// producing the full Go import path expected by the OTel spec.
func TestScopeName_PkgPath(t *testing.T) {
	assert.Equal(t, "github.com/kubewarden/sbomscanner/internal/handlers", scopeName("internal/handlers"))
}

// TestTracerMeter_NonNil simply checks that the helpers wire up without panicking,
// and return non-nil providers under the default global no-op SDK.
func TestTracerMeter_NonNil(t *testing.T) {
	assert.NotNil(t, Tracer(""))
	assert.NotNil(t, Tracer("internal/handlers"))
	assert.NotNil(t, Meter(""))
	assert.NotNil(t, Meter("internal/handlers"))
}
