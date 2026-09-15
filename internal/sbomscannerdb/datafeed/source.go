package datafeed

import (
	"context"
	"log/slog"
)

// Source is one upstream vulnerability data feed.
// Implementations fetch the upstream feed and build a SQLite database from it.
type Source interface {
	// Name is the short feed id (e.g. "kev"); it names the OCI layer.
	Name() string
	// Download fetches the upstream feed file into dir.
	Download(ctx context.Context, dir string) error
	// BuildSQLite parses the upstream feed file in srcDir, writes the database into dstDir,
	// and returns the database file name.
	BuildSQLite(ctx context.Context, srcDir, dstDir string) (string, error)
}

// AllSources returns every data feed packed into the DB artifact.
// Adding a new source means implementing Source and registering it here.
func AllSources(httpDownloader *HTTPDownloader, logger *slog.Logger) []Source {
	return []Source{
		NewKEVDownloader(httpDownloader, logger),
		NewEPSSDownloader(httpDownloader, logger),
	}
}
