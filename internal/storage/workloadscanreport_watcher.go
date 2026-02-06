package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/watch"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

// WorkloadScanReportWatcher watches VulnerabilityReport events and generates
// synthetic WorkloadScanReport events for any WorkloadScanReport that references
// the changed VulnerabilityReport.
type WorkloadScanReportWatcher struct {
	nc                      *nats.Conn
	db                      *pgxpool.Pool
	repo                    *repository.WorkloadScanReportRepository
	workloadBroadcaster     *natsBroadcaster
	workloadScanReportStore *store
	logger                  *slog.Logger
}

func newWorkloadScanReportWatcher(
	nc *nats.Conn,
	db *pgxpool.Pool,
	repo *repository.WorkloadScanReportRepository,
	workloadBroadcaster *natsBroadcaster,
	workloadScanReportStore *store,
	logger *slog.Logger,
) *WorkloadScanReportWatcher {
	return &WorkloadScanReportWatcher{
		nc:                      nc,
		db:                      db,
		repo:                    repo,
		workloadBroadcaster:     workloadBroadcaster,
		workloadScanReportStore: workloadScanReportStore,
		logger:                  logger.With("component", "workloadscanreport-watcher"),
	}
}

// Start subscribes to VulnerabilityReport events and generates WorkloadScanReport events.
func (w *WorkloadScanReportWatcher) Start(ctx context.Context) error {
	subject := "watch." + vulnerabilityReportResourcePluralName

	sub, err := w.nc.Subscribe(subject, func(msg *nats.Msg) {
		if err := w.handleVulnerabilityReportEvent(ctx, msg); err != nil {
			w.logger.ErrorContext(ctx, "Failed to handle VulnerabilityReport event",
				"error", err,
				"subject", msg.Subject,
			)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to NATS subject %s: %w", subject, err)
	}

	w.logger.InfoContext(ctx, "Watcher started", "subject", subject)

	<-ctx.Done()

	w.logger.InfoContext(ctx, "Shutting down watcher", "subject", subject)
	if err := sub.Unsubscribe(); err != nil {
		w.logger.ErrorContext(ctx, "Failed to unsubscribe from NATS", "error", err)
	}

	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("context error while shutting down watcher: %w", err)
	}

	return nil
}

func (w *WorkloadScanReportWatcher) handleVulnerabilityReportEvent(ctx context.Context, msg *nats.Msg) error {
	var payload event
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	var vulnReport storagev1alpha1.VulnerabilityReport
	if err := json.Unmarshal(payload.Object.Raw, &vulnReport); err != nil {
		return fmt.Errorf("failed to decode VulnerabilityReport: %w", err)
	}

	// Find all WorkloadScanReports that reference this VulnerabilityReport
	ref := storagev1alpha1.ImageRef{
		Registry:   vulnReport.ImageMetadata.Registry,
		Namespace:  vulnReport.Namespace,
		Repository: vulnReport.ImageMetadata.Repository,
		Tag:        vulnReport.ImageMetadata.Tag,
	}

	workloadReports, err := w.repo.FindByImageRef(ctx, w.db, ref)
	if err != nil {
		return fmt.Errorf("failed to find related WorkloadScanReports: %w", err)
	}

	if len(workloadReports) == 0 {
		w.logger.DebugContext(ctx, "No WorkloadScanReports reference this VulnerabilityReport",
			"registry", ref.Registry,
			"namespace", ref.Namespace,
			"repository", ref.Repository,
			"tag", ref.Tag,
		)
		return nil
	}

	// Broadcast MODIFIED events for each related WorkloadScanReport
	for _, report := range workloadReports {
		metaAccessor, err := meta.Accessor(&report)
		if err != nil {
			w.logger.ErrorContext(ctx, "Failed to get meta accessor for WorkloadScanReport",
				"error", err,
			)
			continue
		}

		w.logger.DebugContext(ctx, "Broadcasting MODIFIED event for WorkloadScanReport",
			"name", metaAccessor.GetName(),
			"namespace", metaAccessor.GetNamespace(),
			"vulnReportEvent", payload.EventType,
		)

		if err := w.workloadBroadcaster.Action(watch.Modified, &report); err != nil {
			w.logger.ErrorContext(ctx, "Failed to broadcast WorkloadScanReport event",
				"error", err,
				"name", metaAccessor.GetName(),
				"namespace", metaAccessor.GetNamespace(),
			)
		}
	}

	return nil
}
