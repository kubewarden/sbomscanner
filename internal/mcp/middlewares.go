package mcp

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"
)

// rateLimitMiddleware returns an MCP middleware that enforces a global request rate limit.
func rateLimitMiddleware(limiter *rate.Limiter) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !limiter.Allow() {
				return nil, errors.New("rate limit exceeded")
			}
			return next(ctx, method, req)
		}
	}
}

// requireBasicAuth returns HTTP middleware that enforces Basic Authentication.
func requireBasicAuth(username, password string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			// Use constant-time comparison to prevent timing attacks where
			// an attacker measures response times to guess correct bytes one at a time.
			if !ok ||
				subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
				logger.Warn("Unauthorized request", "remote", r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", `Basic realm="sbomscanner-mcp"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
