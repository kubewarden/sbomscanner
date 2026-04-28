package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
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

	rescanRequests, mergedTargets, scanEverything := collectRescanRequests(ctx, registry)
	hasRescanRequest := len(rescanRequests) > 0

	lastScanJob, err := r.getLastScanJob(ctx, registry)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get last scan job for registry %s: %w", registry.Name, err)
	}
	// If a job is running wait the next cycle
	if lastScanJob != nil && !lastScanJob.IsComplete() && !lastScanJob.IsFailed() {
		log.V(1).Info("Registry has a running ScanJob, skipping", "registry", registry.Name, "scanJob", lastScanJob.Name)

		return nil
	}

	if !r.shouldCreateScanJob(ctx, registry, lastScanJob, hasRescanRequest) {
		return nil
	}

	var targets []v1alpha1.ScanJobRepository
	if hasRescanRequest && !scanEverything {
		targets = mergedTargets
	}

	if err := r.createScanJob(ctx, registry, targets); err != nil {
		return fmt.Errorf("failed to create scan job for registry %s: %w", registry.Name, err)
	}

	log.Info("Created scan job for registry", "registry", registry.Name, "namespace", registry.Namespace)

	if hasRescanRequest {
		if err := r.removeRescanAnnotations(ctx, registry, rescanRequests); err != nil {
			return fmt.Errorf("failed to remove rescan annotations for registry %s: %w", registry.Name, err)
		}
	}

	return nil
}

// collectRescanRequests gathers every rescan-requested annotation on the Registry and merges their targeting payloads.
// Returns the annotation keys that were observed, the union of repositories/match conditions across all parsed payloads,
// and a flag indicating that at least one payload requested a full-registry scan (no targeting).
// Malformed annotations are logged and skipped.
func collectRescanRequests(ctx context.Context, registry *v1alpha1.Registry) ([]string, []v1alpha1.ScanJobRepository, bool) {
	log := log.FromContext(ctx)

	rescanRequests := make([]string, 0)
	for key := range registry.Annotations {
		if strings.HasPrefix(key, v1alpha1.AnnotationRescanRequestedKeyPrefix) {
			rescanRequests = append(rescanRequests, key)
		}
	}
	if len(rescanRequests) == 0 {
		return nil, nil, false
	}

	scanEverything := false
	wildcardRepos := sets.New[string]()
	condsByRepo := map[string]sets.Set[string]{}

	for _, rescanRequest := range rescanRequests {
		raw := registry.Annotations[rescanRequest]
		var req v1alpha1.RescanRequest
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &req); err != nil {
				log.Error(err, "Ignoring malformed rescan annotation",
					"registry", registry.Name, "key", rescanRequest, "value", raw)
				continue
			}
		}

		if mergeRescanRequest(req, wildcardRepos, condsByRepo) {
			scanEverything = true
		}
	}

	if scanEverything {
		return rescanRequests, nil, true
	}

	return rescanRequests, buildMergedTargets(wildcardRepos, condsByRepo), false
}

// mergeRescanRequest merges a single RescanRequest into the tracking sets.
// Returns true if the request targets the entire registry (no repository filtering).
func mergeRescanRequest(req v1alpha1.RescanRequest, wildcardRepos sets.Set[string], condsByRepo map[string]sets.Set[string]) bool {
	if len(req.Repositories) == 0 {
		return true
	}
	for _, repo := range req.Repositories {
		if wildcardRepos.Has(repo.Name) {
			continue // already wildcarded; narrower entries have no effect
		}
		if len(repo.MatchConditions) == 0 {
			wildcardRepos.Insert(repo.Name)
			delete(condsByRepo, repo.Name) // wildcard subsumes any specific conditions
			continue
		}
		if condsByRepo[repo.Name] == nil {
			condsByRepo[repo.Name] = sets.New[string]()
		}
		condsByRepo[repo.Name].Insert(repo.MatchConditions...)
	}
	return false
}

// buildMergedTargets produces a sorted list of ScanJobRepositories from the merged tracking sets.
func buildMergedTargets(wildcardRepos sets.Set[string], condsByRepo map[string]sets.Set[string]) []v1alpha1.ScanJobRepository {
	repoNamesSet := wildcardRepos.Clone()
	for name := range condsByRepo {
		repoNamesSet.Insert(name)
	}

	repoNames := repoNamesSet.UnsortedList()
	sort.Strings(repoNames)

	mergedTargets := make([]v1alpha1.ScanJobRepository, 0, len(repoNames))
	for _, name := range repoNames {
		var condNames []string
		if conds := condsByRepo[name]; conds != nil {
			condNames = conds.UnsortedList()
			sort.Strings(condNames)
		}
		mergedTargets = append(mergedTargets, v1alpha1.ScanJobRepository{
			Name:            name,
			MatchConditions: condNames,
		})
	}
	return mergedTargets
}

// shouldCreateScanJob determines if a scan job should be created.
func (r *RegistryScanRunner) shouldCreateScanJob(ctx context.Context, registry *v1alpha1.Registry, lastScanJob *v1alpha1.ScanJob, hasRescanRequest bool) bool {
	log := log.FromContext(ctx)

	// If rescan was requested, always create a new scan job
	if hasRescanRequest {
		if lastScanJob != nil {
			log.Info("Rescan requested for registry", "registry", registry.Name, "namespace", registry.Namespace)
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

// removeRescanAnnotations removes the given rescan annotation keys from the Registry.
// Keys added concurrently after we observed the registry are preserved and will be picked up in the next cycle.
func (r *RegistryScanRunner) removeRescanAnnotations(ctx context.Context, registry *v1alpha1.Registry, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current v1alpha1.Registry
		if err := r.Get(ctx, types.NamespacedName{
			Name:      registry.Name,
			Namespace: registry.Namespace,
		}, &current); err != nil {
			return fmt.Errorf("failed to get current registry: %w", err)
		}

		changed := false
		for _, key := range keys {
			if _, ok := current.Annotations[key]; ok {
				delete(current.Annotations, key)
				changed = true
			}
		}
		if !changed {
			return nil
		}

		if err := r.Update(ctx, &current); err != nil {
			return fmt.Errorf("failed to update registry: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to remove rescan annotations: %w", err)
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
// When repositories is non-empty, the ScanJob targets only that subset.
func (r *RegistryScanRunner) createScanJob(ctx context.Context, registry *v1alpha1.Registry, repositories []v1alpha1.ScanJobRepository) error {
	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", registry.Name),
			Namespace:    registry.Namespace,
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobTriggerKey: "runner",
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry:     registry.Name,
			Repositories: repositories,
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
