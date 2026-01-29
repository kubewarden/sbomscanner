package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
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

func (r *WorkloadScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch config - if not found, scanning is disabled
	var config v1alpha1.WorkloadScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, &config); err != nil {
		if errors.IsNotFound(err) {
			logger.V(1).Info("WorkloadScanConfiguration not found, scanning disabled")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check namespace selector
	if config.Spec.NamespaceSelector != nil {
		var ns metav1.PartialObjectMetadata
		ns.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
		if err := r.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}

		selector, err := metav1.LabelSelectorAsSelector(config.Spec.NamespaceSelector)
		if err != nil {
			logger.Error(err, "Invalid namespace selector")
			return ctrl.Result{}, nil // don't requeue on bad selector
		}

		if !selector.Matches(labels.Set(ns.Labels)) {
			logger.V(1).Info("Namespace does not match selector, skipping", "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
	}

	logger.Info("Reconciling namespace", "namespace", req.Namespace)

	// Collect all images from all pods in the namespace
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(req.Namespace)); err != nil {
		logger.Error(err, "failed to list pods")
		return ctrl.Result{}, err
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

// reconcileRegistries creates, updates, or deletes Registry resources based on the discovered images.
func (r *WorkloadScanReconciler) reconcileRegistries(ctx context.Context, workloadNamespace string, images sets.Set[string], config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	registryNamespace := workloadNamespace
	if config.Spec.TargetNamespace != "" {
		logger.V(1).Info("Using target namespace from configuration", "namespace", config.Spec.TargetNamespace)
		registryNamespace = config.Spec.TargetNamespace
	}

	// Group images by registry host
	registriesByHost := groupImagesByRegistry(images)

	// List all existing managed Registry resources
	var existingRegistryList v1alpha1.RegistryList
	if err := r.List(ctx, &existingRegistryList,
		client.InNamespace(registryNamespace),
		client.MatchingLabels{api.LabelManagedByKey: api.LabelManagedByValue},
	); err != nil {
		return fmt.Errorf("failed to list registries: %w", err)
	}

	expectedRegistryNames := sets.New[string]()
	for host := range registriesByHost {
		expectedRegistryNames.Insert(computeRegistryName(host))
	}

	// Delete registries that are no longer in use
	for _, registry := range existingRegistryList.Items {
		if !expectedRegistryNames.Has(registry.Name) {
			logger.Info("Deleting unused registry", "registry", registry.Name)

			if err := r.Delete(ctx, &registry); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete unused registry %s: %w", registry.Name, err)
			}
		}
	}

	// Create or update registries
	for host, repositories := range registriesByHost {
		registryName := computeRegistryName(host)

		registry := &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      registryName,
				Namespace: registryNamespace,
			},
		}

		operation, err := controllerutil.CreateOrUpdate(ctx, r.Client, registry, func() error {
			if registry.Labels == nil {
				registry.Labels = make(map[string]string)
			}
			registry.Labels[api.LabelManagedByKey] = api.LabelManagedByValue
			registry.Spec = buildRegistrySpec(host, repositories, config)

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update registry %s: %w", registryName, err)
		}

		if config.Spec.ScanOnChange && (operation == controllerutil.OperationResultCreated || operation == controllerutil.OperationResultUpdated) {
			scanJob := &v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: fmt.Sprintf("%s-", registryName),
					Namespace:    registryNamespace,
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: registryName,
				},
			}

			if err := r.Create(ctx, scanJob); err != nil {
				// TODO: check if the error is due to an existing ScanJob for the same registry already running
				logger.Error(err, "failed to create ScanJob for registry", "registry", registryName)
			}
		}

		logger.V(1).Info("Reconciled registry",
			"registry", registryName,
			"operation", operation,
			"repositories", len(repositories))
	}

	logger.V(1).Info("Reconciled registries", "count", len(registriesByHost))

	return nil
}

// reconcileWorkloadScanReports creates or updates WorkloadScanReport resources for each workload
func (r *WorkloadScanReconciler) reconcileWorkloadScanReports(ctx context.Context, namespace string, pods []corev1.Pod, config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	processedWorkloads := sets.New[string]()

	for _, pod := range pods {
		ownerRef, err := r.resolveWorkloadOwner(ctx, &pod)
		if err != nil {
			logger.Error(err, "failed to resolve workload owner", "pod", pod.Name)
			continue
		}

		reportName := computeWorkloadScanReportName(ownerRef.Kind, ownerRef.Name)
		if processedWorkloads.Has(reportName) {
			continue
		}
		processedWorkloads.Insert(reportName)

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
			vulnReportNamespace := namespace
			if config.Spec.TargetNamespace != "" {
				vulnReportNamespace = config.Spec.TargetNamespace
			}
			report.Containers = buildWorkloadContainers(vulnReportNamespace, pod.Spec)

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
// Example: "ghcr.io" becomes "workload-scan-ghcr-io"
// Example: "localhost:5000" becomes "workload-scan-localhost-5000"
func computeRegistryName(registry string) string {
	// Replace dots and colons with hyphens
	sanitized := strings.ReplaceAll(registry, ".", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")

	return "workload-scan-" + sanitized
}

// buildRegistrySpec creates a RegistrySpec with deterministic ordering
func buildRegistrySpec(host string, repositories map[string]sets.Set[string], config *v1alpha1.WorkloadScanConfiguration) v1alpha1.RegistrySpec {
	// Sort repository names for deterministic output.
	// This is important to avoid unnecessary updates to the Registry resource due to map iteration order.
	repoNames := make([]string, 0, len(repositories))
	for repoName := range repositories {
		repoNames = append(repoNames, repoName)
	}
	slices.Sort(repoNames)

	repos := make([]v1alpha1.Repository, 0, len(repositories))
	for _, repoName := range repoNames {
		tags := repositories[repoName]

		matchConditions := make([]v1alpha1.MatchCondition, 0, len(tags))
		// sets.List returns a sorted list.
		// This is important to avoid unnecessary updates to the Registry resource due to map iteration order.
		for _, tag := range sets.List(tags) {
			matchConditions = append(matchConditions, v1alpha1.MatchCondition{
				Name:       fmt.Sprintf("tag-%s", tag),
				Expression: fmt.Sprintf("tag == %q", tag),
			})
		}

		repos = append(repos, v1alpha1.Repository{
			Name:            repoName,
			MatchConditions: matchConditions,
		})
	}

	spec := v1alpha1.RegistrySpec{
		URI:          host,
		Repositories: repos,
		AuthSecret:   config.Spec.AuthSecret,
		CABundle:     config.Spec.CABundle,
		Insecure:     config.Spec.Insecure,
	}

	spec.ScanInterval = config.Spec.ScanInterval
	spec.Platforms = config.Spec.Platforms

	return spec
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
			if errors.IsNotFound(err) {
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

// buildWorkloadContainers builds Container entries with VulnerabilityReportRef from a PodSpec
func buildWorkloadContainers(namespace string, podSpec corev1.PodSpec) []storagev1alpha1.Container {
	result := make([]storagev1alpha1.Container, 0, len(podSpec.InitContainers)+len(podSpec.Containers))

	for _, container := range podSpec.InitContainers {
		ref, err := parseImageToVulnerabilityReportRef(namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.Container{
			Name:                   container.Name,
			VulnerabilityReportRef: ref,
		})
	}

	for _, container := range podSpec.Containers {
		ref, err := parseImageToVulnerabilityReportRef(namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.Container{
			Name:                   container.Name,
			VulnerabilityReportRef: ref,
		})
	}

	slices.SortFunc(result, func(a, b storagev1alpha1.Container) int {
		return strings.Compare(a.Name, b.Name)
	})

	return result
}

// parseImageToVulnerabilityReportRef parses an image reference into a VulnerabilityReportRef
func parseImageToVulnerabilityReportRef(namespace, image string) (storagev1alpha1.VulnerabilityReportRef, error) {
	if image == "" {
		return storagev1alpha1.VulnerabilityReportRef{}, fmt.Errorf("empty image")
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return storagev1alpha1.VulnerabilityReportRef{}, fmt.Errorf("failed to parse image %q: %w", image, err)
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

	return storagev1alpha1.VulnerabilityReportRef{
		Registry:   computeRegistryName(host),
		Namespace:  namespace,
		Repository: repo,
		Tag:        tag,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		Named("workload-scan-controller").
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.WithPredicates(podImagesChangedPredicate())).
		// Reconcile when managed Registry resources change.
		// It uses OnlyMetadata to avoid fetching the full object.
		Watches(&v1alpha1.Registry{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.OnlyMetadata,
			builder.WithPredicates(registryManagedBySbomscannerPredicate()),
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
		return fmt.Errorf("failed to create workload-scan controller: %w", err)
	}
	return nil
}

// mapObjToNamespace maps any object to a reconciliation request for its namespace
func mapObjToNamespace(ctx context.Context, obj client.Object) []ctrl.Request {
	// Trigger reconciliation for the entire namespace
	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: obj.GetNamespace(),
				Name:      "", // Empty name for namespace-level reconciliation
			},
		},
	}
}

// mapConfigToNamespaces returns a handler that enqueues all namespaces matching the selector when config changes
func mapConfigToNamespaces(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		logger := log.FromContext(ctx)

		config, ok := obj.(*v1alpha1.WorkloadScanConfiguration)
		if !ok {
			return nil
		}

		var namespaces metav1.PartialObjectMetadataList
		namespaces.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("NamespaceList"))
		if err := c.List(ctx, &namespaces); err != nil {
			logger.Error(err, "failed to list namespaces")
			return nil
		}

		var selector labels.Selector
		if config.Spec.NamespaceSelector != nil {
			var err error
			selector, err = metav1.LabelSelectorAsSelector(config.Spec.NamespaceSelector)
			if err != nil {
				logger.Error(err, "invalid namespace selector")
				return nil
			}
		}

		var requests []ctrl.Request
		for _, ns := range namespaces.Items {
			if selector == nil || selector.Matches(labels.Set(ns.Labels)) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{Namespace: ns.Name},
				})
			}
		}

		logger.Info("config changed, enqueuing namespaces", "count", len(requests))

		return requests
	}
}

// mapNamespace maps any object to a reconciliation request for its namespace
func mapNamespace(ctx context.Context, obj client.Object) []ctrl.Request {
	// Trigger reconciliation for the entire namespace
	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: obj.GetName(),
				Name:      "", // Empty name for namespace-level reconciliation
			},
		},
	}
}

// podImagesChangedPredicate filters events to only trigger when container images change
func podImagesChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, ok := e.ObjectOld.(*corev1.Pod)
			if !ok {
				return false
			}
			newPod, ok := e.ObjectNew.(*corev1.Pod)
			if !ok {
				return false
			}
			oldImages := extractImagesFromPodSpec(oldPod.Spec)
			newImages := extractImagesFromPodSpec(newPod.Spec)
			return !reflect.DeepEqual(oldImages, newImages)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
	}
}

// extractImagesFromPodSpec returns all container images in a PodSpec
func extractImagesFromPodSpec(podSpec corev1.PodSpec) []string {
	images := make([]string, 0, len(podSpec.InitContainers)+len(podSpec.Containers))

	for _, container := range podSpec.InitContainers {
		images = append(images, container.Image)
	}

	for _, container := range podSpec.Containers {
		images = append(images, container.Image)
	}

	return images
}

// registryManagedBySbomscannerPredicate filters Registry resources managed by sbomscanner
func registryManagedBySbomscannerPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()[api.LabelManagedByKey] == api.LabelManagedByValue
	})
}
