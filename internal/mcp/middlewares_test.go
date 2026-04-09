package mcp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestRequireBasicAuth(t *testing.T) {
	const username = "admin"
	const password = "secret"

	tests := []struct {
		name           string
		username       string
		password       string
		setAuth        bool
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "valid credentials",
			username:       "admin",
			password:       "secret",
			setAuth:        true,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "wrong password",
			username:       "admin",
			password:       "wrong",
			setAuth:        true,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name:           "wrong username",
			username:       "wrong",
			password:       "secret",
			setAuth:        true,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name:           "no auth header",
			setAuth:        false,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name:           "empty credentials",
			username:       "",
			password:       "",
			setAuth:        true,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			middleware := requireBasicAuth(username, password, slog.Default())
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.setAuth {
				req.SetBasicAuth(test.username, test.password)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			require.Equal(t, test.wantStatus, rec.Code)
			require.Equal(t, test.wantNextCalled, nextCalled)

			if test.wantStatus == http.StatusUnauthorized {
				require.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func newStubHandler() (mcp.MethodHandler, *int) {
	callCount := 0
	return func(_ context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
		callCount++
		return nil, nil
	}, &callCount
}

func TestRateLimitMiddleware_UnderLimit(t *testing.T) {
	limiter := rate.NewLimiter(10, 10)
	next, callCount := newStubHandler()
	handler := rateLimitMiddleware(limiter)(next)

	_, err := handler(t.Context(), "tools/call", nil)

	require.NoError(t, err)
	require.Equal(t, 1, *callCount)
}

func TestRateLimitMiddleware_OverLimit(t *testing.T) {
	// burst=0 means no requests allowed
	limiter := rate.NewLimiter(0, 0)
	next, callCount := newStubHandler()
	handler := rateLimitMiddleware(limiter)(next)

	_, err := handler(t.Context(), "tools/call", nil)

	require.ErrorContains(t, err, "rate limit exceeded")
	require.Equal(t, 0, *callCount)
}

func TestRateLimitMiddleware_BurstThenReject(t *testing.T) {
	// Allow burst of 2, then reject
	limiter := rate.NewLimiter(0, 2)
	next, callCount := newStubHandler()
	handler := rateLimitMiddleware(limiter)(next)

	for i := range 2 {
		_, err := handler(t.Context(), "tools/call", nil)
		require.NoError(t, err, "request %d should succeed", i)
	}

	_, err := handler(t.Context(), "tools/call", nil)
	require.ErrorContains(t, err, "rate limit exceeded")
	require.Equal(t, 2, *callCount)
}
