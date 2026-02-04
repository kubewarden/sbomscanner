package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// registryScanRunnerPeriod is the interval between registry scan checks.
// Since the client is cached, we can afford a relatively short period.
const registryScanRunnerPeriod = 10 * time.Second

// RegistryScanRunner handles periodic scanning of registries based on their scan intervals.
type RegistryScanRunner struct {
	client.Client
}

// Start implements the Runnable interface.
func (r *RegistryScanRunner) Start(ctx context.Context) error {
	log := log.FromContext(ctx)
	log.Info("Starting registry scan runner")

	ticker := time.NewTicker(registryScanRunnerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping registry scan runner")

			return nil
		case <-ticker.C:
			if err := r.scanRegistries(ctx); err != nil {
				log.Error(err, "Failed to scan registries")
			}
		}
	}
}

// scanRegistries checks all registries and creates ScanJobs for those that need scanning.
func (r *RegistryScanRunner) scanRegistries(ctx context.Context) error {
	log := log.FromContext(ctx)

	var registries v1alpha1.RegistryList
	if err := r.List(ctx, &registries); err != nil {
		return fmt.Errorf("failed to list registries: %w", err)
	}

	log.V(1).Info("Checking registries for scanning", "count", len(registries.Items))

	for _, registry := range registries.Items {
		if err := r.checkRegistryForScan(ctx, &registry); err != nil {
			log.Error(err, "Failed to check registry for scan", "registry", registry.Name, "namespace", registry.Namespace)

			continue
		}
	}

	return nil
}

// checkRegistryForScan determines if a registry needs scanning and creates a ScanJob if needed.
func (r *RegistryScanRunner) checkRegistryForScan(ctx context.Context, registry *v1alpha1.Registry) error {
	log := log.FromContext(ctx)

	rescanRequested := registry.Annotations[v1alpha1.AnnotationRescanRequestedKey]

	lastScanJob, err := r.getLastScanJob(ctx, registry)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get last scan job for registry %s: %w", registry.Name, err)
	}
	// If a job is running wait the next cycle
	if lastScanJob != nil && !lastScanJob.IsComplete() && !lastScanJob.IsFailed() {
		log.V(1).Info("Registry has a running ScanJob, skipping", "registry", registry.Name, "scanJob", lastScanJob.Name)

		return nil
	}

	if !r.shouldCreateScanJob(ctx, registry, lastScanJob, rescanRequested) {
		return nil
	}

	if err := r.createScanJob(ctx, registry); err != nil {
		return fmt.Errorf("failed to create scan job for registry %s: %w", registry.Name, err)
	}

	log.Info("Created scan job for registry", "registry", registry.Name, "namespace", registry.Namespace)

	if rescanRequested != "" {
		if err := r.removeRescanAnnotation(ctx, registry, rescanRequested); err != nil {
			return fmt.Errorf("failed to remove rescan annotation for registry %s: %w", registry.Name, err)
		}
	}

	return nil
}

// shouldCreateScanJob determines if a scan job should be created.
func (r *RegistryScanRunner) shouldCreateScanJob(ctx context.Context, registry *v1alpha1.Registry, lastScanJob *v1alpha1.ScanJob, rescanRequested string) bool {
	log := log.FromContext(ctx)

	// If rescan was requested, always create a new scan job
	if rescanRequested != "" {
		if lastScanJob != nil {
			log.Info("Rescan requested for registry", "registry", registry.Name, "namespace", registry.Namespace, "requestedAt", rescanRequested)
		}
		return true
	}

	// No scan interval configured means no automatic scanning
	if registry.Spec.ScanInterval == nil || registry.Spec.ScanInterval.Duration == 0 {
		if lastScanJob != nil {
			log.V(1).Info("Skipping registry with disabled scan interval", "registry", registry.Name)
		}
		return false
	}

	// No previous scan job, create initial scan
	if lastScanJob == nil {
		return true
	}

	// Check if enough time has passed since last scan
	if lastScanJob.Status.CompletionTime != nil {
		timeSinceLastScan := time.Since(lastScanJob.Status.CompletionTime.Time)
		if timeSinceLastScan < registry.Spec.ScanInterval.Duration {
			log.V(1).Info("Registry doesn't need scanning yet", "registry", registry.Name, "timeSinceLastScan", timeSinceLastScan)
			return false
		}
	}

	return true
}

// removeRescanAnnotation removes the rescan annotation if it matches the expected value.
func (r *RegistryScanRunner) removeRescanAnnotation(ctx context.Context, registry *v1alpha1.Registry, expectedValue string) error {
	log := log.FromContext(ctx)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current v1alpha1.Registry
		if err := r.Get(ctx, types.NamespacedName{
			Name:      registry.Name,
			Namespace: registry.Namespace,
		}, &current); err != nil {
			return fmt.Errorf("failed to get current registry: %w", err)
		}

		currentAnnotation := current.Annotations[v1alpha1.AnnotationRescanRequestedKey]

		// Only remove the annotation if it's the same one we processed.
		// If the annotation changed (newer timestamp), another rescan was requested
		// and we should leave it for the next cycle.
		if currentAnnotation != expectedValue {
			log.V(1).Info("Rescan annotation changed, not removing",
				"registry", registry.Name,
				"processed", expectedValue,
				"current", currentAnnotation)

			return nil
		}

		delete(current.Annotations, v1alpha1.AnnotationRescanRequestedKey)

		if err := r.Update(ctx, &current); err != nil {
			return fmt.Errorf("failed to update registry: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to remove rescan annotation: %w", err)
	}

	return nil
}

// getLastScanJob finds the most recent ScanJob for a registry (any status).
func (r *RegistryScanRunner) getLastScanJob(ctx context.Context, registry *v1alpha1.Registry) (*v1alpha1.ScanJob, error) {
	var scanJobs v1alpha1.ScanJobList

	listOpts := []client.ListOption{
		client.InNamespace(registry.Namespace),
		client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
	}
	if err := r.List(ctx, &scanJobs, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list scan jobs: %w", err)
	}

	if len(scanJobs.Items) == 0 {
		return nil, apierrors.NewNotFound(
			v1alpha1.GroupVersion.WithResource("scanjobs").GroupResource(),
			fmt.Sprintf("for registry %s", registry.Name),
		)
	}

	// Sort by creation time (most recent first)
	sort.Slice(scanJobs.Items, func(i, j int) bool {
		return scanJobs.Items[i].CreationTimestamp.After(scanJobs.Items[j].CreationTimestamp.Time)
	})

	return &scanJobs.Items[0], nil
}

// createScanJob creates a new ScanJob for the given registry.
func (r *RegistryScanRunner) createScanJob(ctx context.Context, registry *v1alpha1.Registry) error {
	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", registry.Name),
			Namespace:    registry.Namespace,
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobTriggerKey: "runner",
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: registry.Name,
		},
	}

	if err := r.Create(ctx, scanJob); err != nil {
		return fmt.Errorf("failed to create ScanJob: %w", err)
	}

	return nil
}

// NeedLeaderElection implements the LeaderElectionRunnable interface.
func (r *RegistryScanRunner) NeedLeaderElection() bool {
	return true
}

func (r *RegistryScanRunner) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed to create RegistryScanRunner: %w", err)
	}

	return nil
}
