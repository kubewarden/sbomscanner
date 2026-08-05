package datafeed

import (
	"context"
	"log/slog"
)

// Source is one upstream vulnerability data feed. Implementations know how to
// fetch and validate their feed into a data directory and describe how it
// should be packed as an OCI layer (name + on-disk file + file format).
type Source interface {
	// Name is the short feed id (e.g. "kev"); it names the OCI layer.
	Name() string
	// FileName is the feed's file name within the data directory.
	FileName() string
	// Format is the feed's file format / extension (e.g. "json", "csv");
	// it is carried in the layer media type.
	Format() string
	// Download fetches and validates the feed into dir/FileName().
	Download(ctx context.Context, dir string) error
}

// AllSources returns every data feed packed into the DB artifact.
// Adding a new source means implementing Source and registering it here.
func AllSources(httpDownloader *HTTPDownloader, logger *slog.Logger) []Source {
	return []Source{
		NewKEVDownloader(httpDownloader, logger),
		NewEPSSDownloader(httpDownloader, logger),
	}
}
