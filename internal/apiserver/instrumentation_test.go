package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

var testServedResources = sets.New("images")

func newTestInstrumentation(t *testing.T) (*Instrumentation, *sdkmetric.ManualReader) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, meterProvider.Shutdown(context.Background()))
	})

	instrumentation, err := NewInstrumentation(meterProvider.Meter("test"))
	require.NoError(t, err)
	return instrumentation, reader
}

func requestDurationDataPoints(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.HistogramDataPoint[float64] {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &resourceMetrics))

	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "storage.apiserver.request.duration" {
				continue
			}
			histogram, ok := m.Data.(metricdata.Histogram[float64])
			require.True(t, ok, "unexpected data type %T", m.Data)
			return histogram.DataPoints
		}
	}
	return nil
}

func resourceGetRequest(t *testing.T) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/apis/storage.sbomscanner.kubewarden.io/v1alpha1/namespaces/default/images/my-image", nil)
	return req.WithContext(apirequest.WithRequestInfo(req.Context(), &apirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		Resource:          "images",
	}))
}

// TestRequestDurationFilter asserts one histogram point labeled with the verb,
// the resource, and the response code.
func TestRequestDurationFilter(t *testing.T) {
	instrumentation, reader := newTestInstrumentation(t)

	handler := instrumentation.requestDurationFilter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), nil, testServedResources)
	handler.ServeHTTP(httptest.NewRecorder(), resourceGetRequest(t))

	points := requestDurationDataPoints(t, reader)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)

	verb, ok := points[0].Attributes.Value("verb")
	require.True(t, ok)
	assert.Equal(t, "get", verb.AsString())
	resource, ok := points[0].Attributes.Value("resource")
	require.True(t, ok)
	assert.Equal(t, "images", resource.AsString())
	code, ok := points[0].Attributes.Value("code")
	require.True(t, ok)
	assert.Equal(t, int64(http.StatusNotFound), code.AsInt64())
}

// TestRequestDurationFilter_SkipsNonResourceRequests asserts that requests
// without resource semantics (healthz, openapi) are not recorded.
func TestRequestDurationFilter_SkipsNonResourceRequests(t *testing.T) {
	instrumentation, reader := newTestInstrumentation(t)

	handler := instrumentation.requestDurationFilter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil, testServedResources)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req = req.WithContext(apirequest.WithRequestInfo(req.Context(), &apirequest.RequestInfo{
		IsResourceRequest: false,
		Path:              "/healthz",
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, requestDurationDataPoints(t, reader))
}

// TestRequestDurationFilter_SkipsLongRunningRequests asserts that watch-style
// requests are not recorded: their duration is a connection lifetime, not a latency.
func TestRequestDurationFilter_SkipsLongRunningRequests(t *testing.T) {
	instrumentation, reader := newTestInstrumentation(t)

	longRunning := func(*http.Request, *apirequest.RequestInfo) bool { return true }
	handler := instrumentation.requestDurationFilter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), longRunning, testServedResources)
	handler.ServeHTTP(httptest.NewRecorder(), resourceGetRequest(t))

	assert.Empty(t, requestDurationDataPoints(t, reader))
}

// TestRequestDurationFilter_NormalizesUnknownResources asserts that resources
// outside the served set are recorded as "unknown", so arbitrary request paths
// cannot grow the resource label cardinality.
func TestRequestDurationFilter_NormalizesUnknownResources(t *testing.T) {
	instrumentation, reader := newTestInstrumentation(t)

	handler := instrumentation.requestDurationFilter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), nil, testServedResources)

	req := httptest.NewRequest(http.MethodGet, "/apis/storage.sbomscanner.kubewarden.io/v1alpha1/namespaces/default/bogus/my-name", nil)
	req = req.WithContext(apirequest.WithRequestInfo(req.Context(), &apirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		Resource:          "bogus",
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	points := requestDurationDataPoints(t, reader)
	require.Len(t, points, 1)

	resource, ok := points[0].Attributes.Value("resource")
	require.True(t, ok)
	assert.Equal(t, "unknown", resource.AsString())
}
