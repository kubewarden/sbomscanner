package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resourceVersionSequenceName is the name of the PostgreSQL sequence used
// to generate globally unique resource versions across all resources.
const resourceVersionSequenceName = "resource_version_seq"

// createResourceVersionSequenceSQL creates a sequence for resource versions.
// This sequence is used to generate globally unique, monotonically increasing
// resource versions for all Kubernetes resources stored in the database.
const createResourceVersionSequenceSQL = `CREATE SEQUENCE IF NOT EXISTS resource_version_seq`

func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, createResourceVersionSequenceSQL); err != nil {
		return fmt.Errorf("creating resource version sequence: %w", err)
	}
	if _, err := db.Exec(ctx, createImageTableSQL); err != nil {
		return fmt.Errorf("creating image table: %w", err)
	}
	if _, err := db.Exec(ctx, createSBOMTableSQL); err != nil {
		return fmt.Errorf("creating sbom table: %w", err)
	}
	if _, err := db.Exec(ctx, createVulnerabilityReportTableSQL); err != nil {
		return fmt.Errorf("creating vulnerability report table: %w", err)
	}
	if _, err := db.Exec(ctx, createWorkloadScanReportTableSQL); err != nil {
		return fmt.Errorf("creating workload scan report table: %w", err)
	}

	return nil
}
