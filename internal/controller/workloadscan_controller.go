package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

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

func (r *WorkloadScanReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.WorkloadScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("WorkloadScanConfiguration not found, cleaning up all managed resources")
			if err := r.cleanupAllManagedResources(ctx); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup managed resources: %w", err)
			}
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to get WorkloadScanConfiguration: %w", err)
	}

	if !config.Spec.Enabled {
		logger.V(1).Info("Workload scanning is disabled, cleaning up all managed resources")
		if err := r.cleanupAllManagedResources(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup managed resources: %w", err)
		}

		return ctrl.Result{}, nil
	}

	matches, err := r.checkNamespaceSelector(ctx, request.Namespace, config.Spec.NamespaceSelector)
	if err != nil {
		logger.Error(err, "Invalid namespace selector")
		return ctrl.Result{}, nil // don't requeue on bad selector
	}

	if !matches {
		logger.V(1).Info("Namespace does not match selector, cleaning up", "namespace", request.Namespace)
		// Clean-up by reconciling with an empty pod list
		if err := r.reconcileRegistries(ctx, request.Namespace, []corev1.Pod{}, &config); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup registries: %w", err)
		}

		// Clean-up by reconciling with an empty pod list
		if err := r.reconcileWorkloadScanReports(ctx, request.Namespace, []corev1.Pod{}, &config); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup WorkloadScanReports: %w", err)
		}
		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling namespace", "namespace", request.Namespace)

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(request.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list pods in namespace %s: %w", request.Namespace, err)
	}

	logger.V(1).Info("Found pods", "count", len(pods.Items))

	if err := r.reconcileRegistries(ctx, request.Namespace, pods.Items, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile registries: %w", err)
	}

	if err := r.reconcileWorkloadScanReports(ctx, request.Namespace, pods.Items, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile WorkloadScanReports: %w", err)
	}

	logger.Info("Successfully reconciled namespace", "namespace", request.Namespace)

	return ctrl.Result{}, nil
}

// cleanupAllManagedResources deletes all Registry and WorkloadScanReport resources
// managed by the workload scan controller across all namespaces.
func (r *WorkloadScanReconciler) cleanupAllManagedResources(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var registries v1alpha1.RegistryList
	if err := r.List(ctx, &registries,
		client.MatchingLabels{
			api.LabelManagedByKey:    api.LabelManagedByValue,
			api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed registries: %w", err)
	}

	for i := range registries.Items {
		registry := &registries.Items[i]
		logger.Info("Deleting managed registry", "registry", registry.Name, "namespace", registry.Namespace)
		if err := r.Delete(ctx, registry); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete registry %s/%s: %w", registry.Namespace, registry.Name, err)
		}
	}

	var reports storagev1alpha1.WorkloadScanReportList
	if err := r.List(ctx, &reports,
		client.MatchingLabels{
			api.LabelManagedByKey: api.LabelManagedByValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed WorkloadScanReports: %w", err)
	}

	for i := range reports.Items {
		report := &reports.Items[i]
		logger.Info("Deleting managed WorkloadScanReport", "report", report.Name, "namespace", report.Namespace)
		if err := r.Delete(ctx, report); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete WorkloadScanReport %s/%s: %w", report.Namespace, report.Name, err)
		}
	}

	return nil
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
		return false, fmt.Errorf("invalid label selector: %w", err)
	}

	return labelSelector.Matches(labels.Set(ns.Labels)), nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadScanReconciler) SetupWithManager(manager ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(manager).
		Named("workloadscan-controller").
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(mapObjToNamespace),
			builder.WithPredicates(podImagesChangedPredicate())).
		// Reconcile all matching namespaces when config changes.
		Watches(&v1alpha1.WorkloadScanConfiguration{},
			handler.EnqueueRequestsFromMapFunc(mapConfigToNamespaces(manager.GetClient())),
		).
		// Reconcile when namespaces change (labels may affect selection).
		// It uses OnlyMetadata to avoid fetching the full object.
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(mapNamespace),
			builder.OnlyMetadata).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create workloadscan controller: %w", err)
	}
	return nil
}
