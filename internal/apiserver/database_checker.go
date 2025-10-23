package apiserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apiserver/pkg/server/healthz"
)

// databaseChecker implements a healthz.HealthChecker to verify database connectivity.
type databaseChecker struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

var _ healthz.HealthChecker = &databaseChecker{}

func newDatabaseChecker(db *pgxpool.Pool, logger *slog.Logger) *databaseChecker {
	return &databaseChecker{
		db:     db,
		logger: logger,
	}
}

func (d *databaseChecker) Name() string {
	return "database"
}

// Check verifies the database connectivity by pinging the database.
func (d *databaseChecker) Check(req *http.Request) error {
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()

	if err := d.db.Ping(ctx); err != nil {
		d.logger.Debug("database ping failed", "error", err)
		return fmt.Errorf("database not reachable: %w", err)
	}

	return nil
}
