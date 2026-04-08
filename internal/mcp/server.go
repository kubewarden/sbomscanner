package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const serverInstructions = `This server manages container image scanning in Kubernetes using sbomscanner CRDs.

Resource relationships:
- Create a Registry (namespaced) to define a container registry to scan.
- Create a ScanJob (namespaced) referencing a Registry by name. Both must be in the same namespace. Use get_scanjob to check its status.
- The system automatically produces VulnerabilityReport resources from scans. These are read-only.
- WorkloadScanReports aggregate vulnerability data for all containers in a workload. Read-only.

Cluster-scoped resources:
- WorkloadScanConfiguration is a singleton named "default" that controls automatic workload scanning.
- VEXHub configures VEX repositories. When enabled, VulnerabilityReports are enriched with VEX suppression data.

Tool guidance:
- list_images and list_workloads both return vulnerability severity counts per item. Use these to answer questions about security posture, most vulnerable images/workloads, or namespace/cluster-wide risk.
- PRIORITY: Workloads represent containers actively running in the cluster and should always be prioritized over registry-scanned images. When reporting security posture or remediation priorities, present workload vulnerabilities first — these are the live attack surface. Registry-only images (not running in any workload) are lower priority.
- For security posture questions: call list_workloads first, then list_images. Present workload results first, sorted by total vulnerability count. If recommending remediation, always prioritize fixing workloads before registry-only images. No need to call summary tools for each item individually.
- Use get_image_vulnerability_summary (DEFAULT) with the name and namespace from list_images to get a severity overview and top CVEs for a specific image.
- Use get_workload_vulnerability_summary (DEFAULT) with the name and namespace from list_workloads to get per-container severity overview and top CVEs for a specific workload.
- NEVER use get_image_vulnerabilities or get_workload_vulnerabilities unless the user explicitly asks for the full raw CVE data. These return very large responses.`

// Server wraps the MCP server with a Kubernetes client.
type Server struct {
	mcpServer *mcp.Server
	client    client.Client
	logger    *slog.Logger
	readOnly  bool
}

// NewServer creates a new MCP server with all sbomscanner tools registered.
// When readOnly is true, only read tools (list/get) are registered.
func NewServer(c client.Client, logger *slog.Logger, readOnly bool) *Server {
	logger = logger.With("component", "mcp-server")

	s := &Server{
		client:   c,
		logger:   logger,
		readOnly: readOnly,
		mcpServer: mcp.NewServer(&mcp.Implementation{
			Name: "sbomscanner",
		}, &mcp.ServerOptions{
			Instructions: serverInstructions,
			Logger:       logger,
		}),
	}

	s.mcpServer.AddReceivingMiddleware(rateLimitMiddleware(rate.NewLimiter(10, 50)))
	s.registerReadTools()
	if !readOnly {
		s.registerWriteTools()
	}
	s.logger.Info("Registered MCP tools", "readOnly", readOnly)

	return s
}

// Run starts the MCP server using the Streamable HTTP transport.
func (s *Server) Run(ctx context.Context, addr, credentialsDir, certFile, keyFile string, disableTLS bool) error {
	s.logger.InfoContext(ctx, "Loading credentials", "dir", credentialsDir)
	username, password, err := readCredentials(credentialsDir)
	if err != nil {
		return fmt.Errorf("reading credentials: %w", err)
	}

	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return s.mcpServer },
		nil,
	)

	srv := &http.Server{
		Addr:              addr,
		Handler:           requireBasicAuth(username, password, s.logger)(handler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdownTimeout := 10 * time.Second

	go func() { //nolint:gosec // ctx is already cancelled here; context.Background is intentional
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		s.logger.InfoContext(ctx, "Shutting down HTTP server", "timeout", shutdownTimeout)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			if shutdownCtx.Err() == context.DeadlineExceeded {
				s.logger.ErrorContext(ctx, "Timed out shutting down HTTP server", "error", err, "timeout", shutdownTimeout)
			} else {
				s.logger.ErrorContext(ctx, "Error shutting down HTTP server", "error", err)
			}
		}
	}()

	s.logger.InfoContext(ctx, "Listening", "addr", addr, "tls", !disableTLS)
	if disableTLS {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
	} else {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
	}
	return nil
}

// readCredentials reads username and password from files in the given directory.
func readCredentials(dir string) (string, string, error) {
	username, err := os.ReadFile(dir + "/username")
	if err != nil {
		return "", "", fmt.Errorf("failed to read username: %w", err)
	}
	password, err := os.ReadFile(dir + "/password")
	if err != nil {
		return "", "", fmt.Errorf("failed to read password: %w", err)
	}
	return strings.TrimSpace(string(username)), strings.TrimSpace(string(password)), nil
}
