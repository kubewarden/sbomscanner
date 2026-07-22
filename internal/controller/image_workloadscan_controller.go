package controller

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=images,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=workloadscanreports,verbs=get;list;watch

// ImageWorkloadScanReconciler reconciles Image status based on WorkloadScanReport references.
type ImageWorkloadScanReconciler struct {
	client.Client

	Instrumentation *Instrumentation
}

func (r *ImageWorkloadScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var image storagev1alpha1.Image
	if err := r.Get(ctx, req.NamespacedName, &image); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get image: %w", err)
		}
		return ctrl.Result{}, nil
	}

	workloadScanReports, err := r.findWorkloadScanReportsByImage(ctx, &image)
	if err != nil {
		logger.Error(err, "Failed to find workloads for image")
		return ctrl.Result{}, fmt.Errorf("failed to find workload scan reports: %w", err)
	}

	newReports := make([]storagev1alpha1.ImageWorkloadScanReports, 0, len(workloadScanReports))
	for _, w := range workloadScanReports {
		newReports = append(newReports, storagev1alpha1.ImageWorkloadScanReports{
			Name:      w.Name,
			Namespace: w.Namespace,
		})
	}

	slices.SortFunc(newReports, func(a, b storagev1alpha1.ImageWorkloadScanReports) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	if slices.Equal(image.Status.WorkloadScanReports, newReports) {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFrom(image.DeepCopy())
	image.Status.WorkloadScanReports = newReports

	if err := r.Patch(ctx, &image, patch); err != nil {
		logger.Error(err, "Failed to patch image status")
		return ctrl.Result{}, fmt.Errorf("failed to patch image status: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *ImageWorkloadScanReconciler) findWorkloadScanReportsByImage(ctx context.Context, image *storagev1alpha1.Image) ([]storagev1alpha1.WorkloadScanReport, error) {
	indexKey := imageRefIndexKey(storagev1alpha1.ImageRef{
		Registry:   image.ImageMetadata.Registry,
		Namespace:  image.Namespace,
		Repository: image.ImageMetadata.Repository,
		Tag:        image.ImageMetadata.Tag,
	})

	var workloadList storagev1alpha1.WorkloadScanReportList
	if err := r.List(ctx, &workloadList,
		client.MatchingFields{storagev1alpha1.IndexWorkloadScanReportImageRef: indexKey},
	); err != nil {
		return nil, fmt.Errorf("failed to list workload scan reports: %w", err)
	}

	return workloadList.Items, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageWorkloadScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		Named("image-workloadscan").
		For(&storagev1alpha1.Image{},
			builder.WithPredicates(workloadScanPredicate()),
		).
		Watches(
			&storagev1alpha1.WorkloadScanReport{},
			handler.EnqueueRequestsFromMapFunc(mapWorkloadScanReportToImages(mgr.GetClient())),
		).
		Complete(instrumentReconciler(r.Instrumentation, "ImageWorkloadScan", "Image", r))
	if err != nil {
		return fmt.Errorf("failed to setup image-workloadscan controller: %w", err)
	}

	return nil
}
