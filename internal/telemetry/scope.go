package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/kubewarden/sbomscanner/internal/version"
)

// moduleRoot is the Go module path of this repository.
// It is the prefix added to every instrumentation scope,
// so the wire format stays spec-conformant (full import path) even though call sites pass a short, repo-relative name.
const moduleRoot = "github.com/kubewarden/sbomscanner"

// Tracer returns a trace.Tracer whose instrumentation scope is moduleRoot joined with pkgPath,
// and whose instrumentation version is internal/version.Version.
// pkgPath is the repo-relative directory of the calling package (e.g. "internal/handlers"); "" scopes at the module root.
func Tracer(pkgPath string) trace.Tracer {
	return otel.Tracer(scopeName(pkgPath), trace.WithInstrumentationVersion(version.Version))
}

// Meter returns a metric.Meter whose instrumentation scope is moduleRoot joined with pkgPath,
// and whose instrumentation version is internal/version.Version.
// pkgPath is the repo-relative directory of the calling package (e.g. "internal/handlers"); "" scopes at the module root.
func Meter(pkgPath string) metric.Meter {
	return otel.Meter(scopeName(pkgPath), metric.WithInstrumentationVersion(version.Version))
}

func scopeName(pkgPath string) string {
	if pkgPath == "" {
		return moduleRoot
	}
	return moduleRoot + "/" + pkgPath
}
