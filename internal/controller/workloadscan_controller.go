package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

type WorkloadScanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=workloadscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="apps",resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=workloadscanconfigurations,verbs=get;list;watch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=registries,verbs=get;list;watch;create;update;patch;delete

func (r *WorkloadScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.WorkloadScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("WorkloadScanConfiguration not found, scanning disabled")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get WorkloadScanConfiguration: %w", err)
	}

	matches, err := r.checkNamespaceSelector(ctx, req.Namespace, config.Spec.NamespaceSelector)
	if err != nil {
		logger.Error(err, "Invalid namespace selector")
		return ctrl.Result{}, nil // don't requeue on bad selector
	}

	if !matches {
		logger.V(1).Info("Namespace does not match selector, cleaning up", "namespace", req.Namespace)
		// We pass an empty set of images to trigger cleanup of all registries for this namespace
		if err := r.reconcileRegistries(ctx, req.Namespace, sets.New[string](), &config); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup registries: %w", err)
		}
		// We pass nil pods to trigger cleanup of all WorkloadScanReports for this namespace
		if err := r.reconcileWorkloadScanReports(ctx, req.Namespace, nil, &config); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup WorkloadScanReports: %w", err)
		}
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling namespace", "namespace", req.Namespace)

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(req.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list pods in namespace %s: %w", req.Namespace, err)
	}

	logger.V(1).Info("Found pods", "count", len(pods.Items))

	images := sets.New[string]()
	for _, pod := range pods.Items {
		images.Insert(extractImagesFromPodSpec(pod.Spec)...)
	}

	if err := r.reconcileRegistries(ctx, req.Namespace, images, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile registries: %w", err)
	}

	if err := r.reconcileWorkloadScanReports(ctx, req.Namespace, pods.Items, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile WorkloadScanReports: %w", err)
	}

	logger.Info("Successfully reconciled namespace", "namespace", req.Namespace)

	return ctrl.Result{}, nil
}

// checkNamespaceSelector returns true if the namespace matches the selector (or no selector is configured).
// Returns false if the namespace should be skipped, along with any error encountered.
func (r *WorkloadScanReconciler) checkNamespaceSelector(ctx context.Context, namespace string, selector *metav1.LabelSelector) (bool, error) {
	if selector == nil {
		return true, nil
	}

	var ns metav1.PartialObjectMetadata
	ns.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get namespace %s: %w", namespace, err)
	}

	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}

	return labelSelector.Matches(labels.Set(ns.Labels)), nil
}

// reconcileRegistries creates, updates, or deletes Registry resources based on the discovered images.
// When a target namespace is configured, registries aggregate images from all source namespaces
// by using labels on MatchConditions to track which namespaces use each condition.
func (r *WorkloadScanReconciler) reconcileRegistries(ctx context.Context, workloadNamespace string, images sets.Set[string], config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	registryNamespace := workloadNamespace
	if config.Spec.TargetNamespace != "" {
		logger.V(1).Info("Using target namespace from configuration", "namespace", config.Spec.TargetNamespace)
		registryNamespace = config.Spec.TargetNamespace
	}

	// Group images by registry host for this namespace
	registriesByHost := groupImagesByRegistry(images)

	// List all existing managed registries
	var existingRegistries v1alpha1.RegistryList
	if err := r.List(ctx, &existingRegistries,
		client.InNamespace(registryNamespace),
		client.MatchingLabels{
			api.LabelManagedByKey:    api.LabelManagedByValue,
			api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list registries: %w", err)
	}

	// Track which hosts we've processed
	processedHosts := sets.New[string]()

	// Update existing registries
	for i := range existingRegistries.Items {
		registry := &existingRegistries.Items[i]
		host := registry.Spec.URI
		processedHosts.Insert(host)

		newRepos := registriesByHost[host] // may be nil if this namespace no longer uses this host

		shouldDelete, err := r.updateRegistryMatchConditions(ctx, registry, workloadNamespace, host, newRepos, config)
		if err != nil {
			return err
		}

		if shouldDelete {
			logger.Info("Deleting registry with no matchConditions", "registry", registry.Name)
			if err := r.Delete(ctx, registry); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete registry %s: %w", registry.Name, err)
			}
		}
	}

	for host, repos := range registriesByHost {
		if processedHosts.Has(host) {
			continue
		}

		if err := r.createRegistry(ctx, host, workloadNamespace, registryNamespace, repos, config); err != nil {
			return err
		}
	}

	logger.V(1).Info("Reconciled registries", "count", len(registriesByHost))

	return nil
}

// conditionKey uniquely identifies a match condition within a repository.
type conditionKey struct {
	repository string
	expression string
}

// updateRegistryMatchConditions updates a registry with this namespace's match conditions.
// Returns true if the registry should be deleted (no conditions remain).
func (r *WorkloadScanReconciler) updateRegistryMatchConditions(
	ctx context.Context,
	registry *v1alpha1.Registry,
	sourceNamespace, host string,
	newRepos map[string]sets.Set[string],
	config *v1alpha1.WorkloadScanConfiguration,
) (bool, error) {
	logger := log.FromContext(ctx)

	// Build set of conditions this namespace needs
	neededConditions := make(map[conditionKey]bool)
	for repoName, tags := range newRepos {
		for tag := range tags {
			neededConditions[conditionKey{
				repository: repoName,
				expression: fmt.Sprintf("tag == %q", tag),
			}] = true
		}
	}

	// Track existing conditions for detecting new ones
	oldConditions := extractConditionKeys(registry)

	// Build updated repository map
	repoConditions := make(map[string][]v1alpha1.MatchCondition)

	// Process existing conditions
	for _, repository := range registry.Spec.Repositories {
		for _, condition := range repository.MatchConditions {
			key := conditionKey{repository: repository.Name, expression: condition.Expression}

			if condition.Labels == nil {
				condition.Labels = make(map[string]string)
			}

			if neededConditions[key] {
				// This namespace needs this condition, add its label
				condition.Labels[sourceNamespace] = "true"
				delete(neededConditions, key) // mark as processed
			} else {
				// This namespace doesn't need this condition, remove its label
				delete(condition.Labels, sourceNamespace)
			}

			// Keep condition only if at least one namespace still uses it
			if len(condition.Labels) > 0 {
				repoConditions[repository.Name] = append(repoConditions[repository.Name], condition)
			}
		}
	}

	// Add new conditions that didn't exist before
	for key := range neededConditions {
		tag := extractTagFromExpression(key.expression)
		repoConditions[key.repository] = append(repoConditions[key.repository], v1alpha1.MatchCondition{
			Name:       fmt.Sprintf("tag-%s", tag),
			Expression: key.expression,
			Labels: map[string]string{
				sourceNamespace: "true",
			},
		})
	}

	// Remove repos with no conditions
	for name, conditions := range repoConditions {
		if len(conditions) == 0 {
			delete(repoConditions, name)
		}
	}

	// If no repos remain, signal deletion
	if len(repoConditions) == 0 {
		return true, nil
	}

	// Build sorted spec
	registry.Spec = buildRegistrySpecFromConditions(host, repoConditions, config)

	// Check if new conditions were added (expressions that didn't exist before)
	newConditions := extractConditionKeys(registry)
	hasNewConditions := newConditions.Difference(oldConditions).Len() > 0

	// Set rescan annotation if needed
	if config.Spec.ScanOnChange && hasNewConditions {
		if registry.Annotations == nil {
			registry.Annotations = make(map[string]string)
		}
		registry.Annotations[v1alpha1.AnnotationRescanRequestedKey] = time.Now().UTC().Format(time.RFC3339)
		logger.V(1).Info("Conditions changed, marking registry for rescan", "registry", registry.Name)
	}

	if err := r.Update(ctx, registry); err != nil {
		return false, fmt.Errorf("failed to update registry %s: %w", registry.Name, err)
	}

	logger.V(1).Info("Updated registry matchConditions",
		"registry", registry.Name,
		"sourceNamespace", sourceNamespace,
		"repositories", len(repoConditions))

	return false, nil
}

// createRegistry creates a new registry with this namespace's contributions.
func (r *WorkloadScanReconciler) createRegistry(
	ctx context.Context,
	host, sourceNamespace, registryNamespace string,
	repos map[string]sets.Set[string],
	config *v1alpha1.WorkloadScanConfiguration,
) error {
	logger := log.FromContext(ctx)
	registryName := computeRegistryName(host)

	// Build conditions with namespace label
	repoConditions := make(map[string][]v1alpha1.MatchCondition)
	for repoName, tags := range repos {
		for _, tag := range sets.List(tags) {
			repoConditions[repoName] = append(repoConditions[repoName], v1alpha1.MatchCondition{
				Name:       fmt.Sprintf("tag-%s", tag),
				Expression: fmt.Sprintf("tag == %q", tag),
				Labels: map[string]string{
					sourceNamespace: "true",
				},
			})
		}
	}

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      registryName,
			Namespace: registryNamespace,
			Labels: map[string]string{
				api.LabelManagedByKey:    api.LabelManagedByValue,
				api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
			},
		},
		Spec: buildRegistrySpecFromConditions(host, repoConditions, config),
	}

	// Set rescan annotation on creation if ScanOnChange is enabled
	if config.Spec.ScanOnChange {
		registry.Annotations = map[string]string{
			v1alpha1.AnnotationRescanRequestedKey: time.Now().UTC().Format(time.RFC3339),
		}
	}

	if err := r.Create(ctx, registry); err != nil {
		return fmt.Errorf("failed to create registry %s: %w", registryName, err)
	}

	logger.V(1).Info("Created registry",
		"registry", registryName,
		"sourceNamespace", sourceNamespace,
		"repositories", len(repos))

	return nil
}

// extractConditionKeys returns a set of condition keys from the registry's match conditions.
func extractConditionKeys(registry *v1alpha1.Registry) sets.Set[conditionKey] {
	keys := sets.New[conditionKey]()
	for _, repository := range registry.Spec.Repositories {
		for _, condition := range repository.MatchConditions {
			keys.Insert(conditionKey{
				repository: repository.Name,
				expression: condition.Expression,
			})
		}
	}

	return keys
}

// extractTagFromExpression extracts the tag value from an expression like `tag == "v1"`.
func extractTagFromExpression(expression string) string {
	// Expression format: tag == "value"
	start := strings.Index(expression, `"`)
	end := strings.LastIndex(expression, `"`)
	if start != -1 && end != -1 && start < end {
		return expression[start+1 : end]
	}
	return expression
}

// buildRegistrySpecFromConditions creates a RegistrySpec from a map of repo name -> conditions.
func buildRegistrySpecFromConditions(host string, repoConditions map[string][]v1alpha1.MatchCondition, config *v1alpha1.WorkloadScanConfiguration) v1alpha1.RegistrySpec {
	// Sort repository names for deterministic output
	repoNames := make([]string, 0, len(repoConditions))
	for name := range repoConditions {
		repoNames = append(repoNames, name)
	}
	slices.Sort(repoNames)

	repos := make([]v1alpha1.Repository, 0, len(repoConditions))
	for _, repoName := range repoNames {
		conditions := repoConditions[repoName]

		// Sort conditions by name for deterministic output
		slices.SortFunc(conditions, func(a, b v1alpha1.MatchCondition) int {
			return strings.Compare(a.Name, b.Name)
		})

		repos = append(repos, v1alpha1.Repository{
			Name:            repoName,
			MatchConditions: conditions,
			Operator:        v1alpha1.MatchConditionOpOr,
		})
	}

	return v1alpha1.RegistrySpec{
		URI:          host,
		Repositories: repos,
		AuthSecret:   config.Spec.AuthSecret,
		CABundle:     config.Spec.CABundle,
		Insecure:     config.Spec.Insecure,
		ScanInterval: config.Spec.ScanInterval,
		Platforms:    config.Spec.Platforms,
	}
}

// reconcileWorkloadScanReports creates or updates WorkloadScanReport resources for each workload.
// It also deletes stale reports that no longer have corresponding workloads.
func (r *WorkloadScanReconciler) reconcileWorkloadScanReports(ctx context.Context, namespace string, pods []corev1.Pod, config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	// Build set of expected report names from current pods
	expectedReports := sets.New[string]()
	podsByReport := make(map[string]*corev1.Pod)

	for i := range pods {
		pod := &pods[i]
		ownerRef, err := r.resolveWorkloadOwner(ctx, pod)
		if err != nil {
			logger.Error(err, "failed to resolve workload owner", "pod", pod.Name)
			continue
		}

		reportName := computeWorkloadScanReportName(ownerRef.Kind, ownerRef.Name)
		expectedReports.Insert(reportName)
		if _, exists := podsByReport[reportName]; !exists {
			podsByReport[reportName] = pod
		}
	}

	// List existing managed WorkloadScanReports
	var existingReports storagev1alpha1.WorkloadScanReportList
	if err := r.List(ctx, &existingReports,
		client.InNamespace(namespace),
		client.MatchingLabels{api.LabelManagedByKey: api.LabelManagedByValue},
	); err != nil {
		return fmt.Errorf("failed to list WorkloadScanReports: %w", err)
	}

	// Delete stale WorkloadScanReports
	for _, report := range existingReports.Items {
		if expectedReports.Has(report.Name) {
			continue
		}

		logger.Info("Deleting stale WorkloadScanReport", "report", report.Name)
		if err := r.Delete(ctx, &report); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete stale WorkloadScanReport %s: %w", report.Name, err)
		}
	}

	// Create or update reports for current workloads
	for reportName, pod := range podsByReport {
		ownerRef, err := r.resolveWorkloadOwner(ctx, pod)
		if err != nil {
			continue // already logged above
		}

		report := &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      reportName,
				Namespace: namespace,
			},
		}

		operation, err := controllerutil.CreateOrPatch(ctx, r.Client, report, func() error {
			if report.Labels == nil {
				report.Labels = make(map[string]string)
			}
			report.Labels[api.LabelManagedByKey] = api.LabelManagedByValue
			report.OwnerReferences = []metav1.OwnerReference{*ownerRef}
			imageRefNamespace := namespace
			if config.Spec.TargetNamespace != "" {
				imageRefNamespace = config.Spec.TargetNamespace
			}
			report.Spec.Containers = buildContainerRefs(imageRefNamespace, pod.Spec)

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update workload scan report %s: %w", reportName, err)
		}

		logger.V(1).Info("Reconciled workload scan report",
			"report", reportName,
			"workload", ownerRef.Name,
			"kind", ownerRef.Kind,
			"operation", operation)
	}

	return nil
}

// computeRegistryName converts a registry hostname to a valid Kubernetes resource name
// Example: "ghcr.io" becomes "workloadscan-ghcr-io"
// Example: "localhost:5000" becomes "workloadscan-localhost-5000"
func computeRegistryName(registry string) string {
	// Replace dots and colons with hyphens
	sanitized := strings.ReplaceAll(registry, ".", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")

	return "workloadscan-" + sanitized
}

// groupImagesByRegistry parses images and groups them by registry host -> repo -> tags
func groupImagesByRegistry(images sets.Set[string]) map[string]map[string]sets.Set[string] {
	result := make(map[string]map[string]sets.Set[string])

	for image := range images {
		if image == "" {
			continue
		}

		ref, err := name.ParseReference(image)
		if err != nil {
			continue
		}

		host := ref.Context().RegistryStr()
		repo := ref.Context().RepositoryStr()

		var tag string
		switch v := ref.(type) {
		case name.Tag:
			tag = v.TagStr()
		case name.Digest:
			tag = v.DigestStr()
		default:
			// Shouldn't happen, but fallback to "latest"
			tag = "latest"
		}

		if result[host] == nil {
			result[host] = make(map[string]sets.Set[string])
		}
		if result[host][repo] == nil {
			result[host][repo] = sets.New[string]()
		}
		result[host][repo].Insert(tag)
	}

	return result
}

// resolveWorkloadOwner walks up the owner reference chain to find the top-level workload.
// If the pod has no owner, it returns an OwnerReference pointing to the pod itself.
func (r *WorkloadScanReconciler) resolveWorkloadOwner(ctx context.Context, pod *corev1.Pod) (*metav1.OwnerReference, error) {
	ownerRef := metav1.GetControllerOf(pod)

	if ownerRef == nil {
		return &metav1.OwnerReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       pod.Name,
			UID:        pod.UID,
		}, nil
	}

	if ownerRef.Kind == "ReplicaSet" {
		rs := &metav1.PartialObjectMetadata{}
		rs.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))

		if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: ownerRef.Name}, rs); err != nil {
			if apierrors.IsNotFound(err) {
				return ownerRef, nil
			}
			return nil, fmt.Errorf("failed to get ReplicaSet %s/%s: %w", pod.Namespace, ownerRef.Name, err)
		}

		if deployRef := metav1.GetControllerOf(rs); deployRef != nil && deployRef.Kind == "Deployment" {
			return deployRef, nil
		}
	}

	return ownerRef, nil
}

// computeWorkloadScanReportName generates a name for a WorkloadScanReport
func computeWorkloadScanReportName(kind, name string) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(kind), name)
}

// buildContainerRefs builds ContainerRef entries with ImageRef from a PodSpec
func buildContainerRefs(namespace string, podSpec corev1.PodSpec) []storagev1alpha1.ContainerRef {
	result := make([]storagev1alpha1.ContainerRef, 0, len(podSpec.InitContainers)+len(podSpec.Containers))

	for _, container := range podSpec.InitContainers {
		ref, err := parseImageToImageRef(namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.ContainerRef{
			Name:     container.Name,
			ImageRef: ref,
		})
	}

	for _, container := range podSpec.Containers {
		ref, err := parseImageToImageRef(namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.ContainerRef{
			Name:     container.Name,
			ImageRef: ref,
		})
	}

	slices.SortFunc(result, func(a, b storagev1alpha1.ContainerRef) int {
		return strings.Compare(a.Name, b.Name)
	})

	return result
}

// parseImageToImageRef parses an image reference into an ImageRef
func parseImageToImageRef(namespace, image string) (storagev1alpha1.ImageRef, error) {
	if image == "" {
		return storagev1alpha1.ImageRef{}, errors.New("empty image reference")
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return storagev1alpha1.ImageRef{}, fmt.Errorf("failed to parse image %q: %w", image, err)
	}

	host := ref.Context().RegistryStr()
	repo := ref.Context().RepositoryStr()

	var tag string
	switch v := ref.(type) {
	case name.Tag:
		tag = v.TagStr()
	case name.Digest:
		tag = v.DigestStr()
	default:
		tag = "latest"
	}

	return storagev1alpha1.ImageRef{
		Registry:   computeRegistryName(host),
		Namespace:  namespace,
		Repository: repo,
		Tag:        tag,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	registryLabelPredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			api.LabelManagedByKey:    api.LabelManagedByValue,
			api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create registry label predicate: %w", err)
	}

	err = ctrl.NewControllerManagedBy(mgr).
		Named("workloadscan-controller").
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.WithPredicates(podImagesChangedPredicate())).
		// Reconcile when managed Registry resources change.
		Watches(&v1alpha1.Registry{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.WithPredicates(registryLabelPredicate),
		).
		// Reconcile when WorkloadScanReport spec changes (e.g., user modifications).
		Watches(&storagev1alpha1.WorkloadScanReport{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// Reconcile all matching namespaces when config changes.
		Watches(&v1alpha1.WorkloadScanConfiguration{},
			handler.EnqueueRequestsFromMapFunc(mapConfigToNamespaces(mgr.GetClient())),
		).
		// Reconcile when namespaces change (labels may affect selection).
		// It uses OnlyMetadata to avoid fetching the full object.
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(mapNamespace), builder.OnlyMetadata).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create workloadscan controller: %w", err)
	}
	return nil
}
