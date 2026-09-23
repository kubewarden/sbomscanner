package apiserver

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/endpoints/responsewriter"

	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// Instrumentation bundles the metric instruments shared by the storage API server.
// Disabled telemetry is represented by no-op providers.
type Instrumentation struct {
	requestDuration metric.Float64Histogram
}

// NewInstrumentation creates a new Instrumentation.
func NewInstrumentation(meter metric.Meter) (*Instrumentation, error) {
	requestDuration, err := meter.Float64Histogram(
		"storage.apiserver.request.duration",
		metric.WithDescription("Duration of resource requests served by the storage API server."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating storage.apiserver.request.duration histogram: %w", err)
	}

	return &Instrumentation{
		requestDuration: requestDuration,
	}, nil
}

// requestDurationFilter records the request duration histogram (verb, resource, code),
// skipping non-resource and long-running requests.
// Resources outside servedResources are recorded as "unknown": the resource label
// is parsed from the request path, and arbitrary values would grow the series count.
func (i *Instrumentation) requestDurationFilter(
	handler http.Handler,
	longRunning apirequest.LongRunningRequestCheck,
	servedResources sets.Set[string],
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestInfo, ok := apirequest.RequestInfoFrom(req.Context())
		if !ok || !requestInfo.IsResourceRequest || (longRunning != nil && longRunning(req, requestInfo)) {
			handler.ServeHTTP(w, req)
			return
		}

		resource := requestInfo.Resource
		if !servedResources.Has(resource) {
			resource = "unknown"
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		handler.ServeHTTP(responsewriter.WrapForHTTP1Or2(recorder), req)

		i.requestDuration.Record(req.Context(), time.Since(start).Seconds(), metric.WithAttributes(
			attribute.String("verb", requestInfo.Verb),
			attribute.String("resource", resource),
			attribute.Int("code", recorder.status),
		))
	})
}

// isMachineryRequest reports whether the request is API machinery polling
// (health probes, OpenAPI aggregation, discovery) rather than a resource request.
func isMachineryRequest(req *http.Request) bool {
	path := req.URL.Path
	for _, root := range []string{"/healthz", "/readyz", "/livez", "/openapi"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}

	switch path {
	case "/apis",
		"/apis/" + v1alpha1.GroupName,
		fmt.Sprintf("/apis/%s/%s", v1alpha1.GroupName, v1alpha1.SchemeGroupVersion.Version):
		return true
	}
	return false
}

// statusRecorder captures the response status code.
type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Unwrap returns the original ResponseWriter, as required by responsewriter.UserProvidedDecorator.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
