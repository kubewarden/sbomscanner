package controller

import (
	"context"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// workloadScanPredicate filters Images with the workloadscan label
func workloadScanPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()[api.LabelWorkloadScanKey] == api.LabelWorkloadScanValue
	})
}

// mapWorkloadScanReportToImages returns reconcile requests for all Images referenced by a WorkloadScanReport.
func mapWorkloadScanReportToImages(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		workload, ok := obj.(*storagev1alpha1.WorkloadScanReport)
		if !ok {
			return nil
		}

		logger := log.FromContext(ctx)

		seen := sets.New[storagev1alpha1.ImageRef]()
		var requests []reconcile.Request

		for _, container := range workload.Spec.Containers {
			if seen.Has(container.ImageRef) {
				continue
			}
			seen.Insert(container.ImageRef)

			var imageList storagev1alpha1.ImageList
			if err := c.List(ctx, &imageList,
				client.InNamespace(container.ImageRef.Namespace),
				client.MatchingFields{storagev1alpha1.IndexImageMetadataComposite: imageMetadataIndexKey(storagev1alpha1.ImageMetadata{
					Registry:   container.ImageRef.Registry,
					Repository: container.ImageRef.Repository,
					Tag:        container.ImageRef.Tag,
				})},
			); err != nil {
				logger.Error(err, "Failed to list images by metadata index", "imageRef", container.ImageRef)
				continue
			}

			for _, image := range imageList.Items {
				requests = append(requests, reconcile.Request{
					Name:      image.Name,
					Namespace: image.Namespace,
				})
			}
		}

		return requests
	}
}
