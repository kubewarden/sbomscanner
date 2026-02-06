package controller

import (
	"context"
	"encoding/json"
	"maps"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

const (
	// WorkloadAnnotationPrefix is the annotation key prefix for workloads using an image.
	// Full key format: sbomscanner.kubewarden.io/workloadscan-<uid>
	// Value format: JSON {"name": "<name>", "namespace": "<namespace>", "containers": <count>, "summary": {...}}
	WorkloadAnnotationPrefix = "sbomscanner.kubewarden.io/workloadscan-"

	ImageByMetadataIndex    = "imageMetadata.composite"
	WorkloadByImageRefIndex = "spec.containers.imageRef.composite"
)

// WorkloadAnnotationValue represents the JSON value stored in workload annotations
type WorkloadAnnotationValue struct {
	Name       string                  `json:"name"`
	Namespace  string                  `json:"namespace"`
	Containers int                     `json:"containers"`
	Summary    storagev1alpha1.Summary `json:"summary,omitempty"`
}

// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=images,verbs=get;list;watch;patch

// ImageAnnotationReconciler reconciles Image annotations based on WorkloadScanReport references.
type ImageAnnotationReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=images,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=workloadscanreports,verbs=get;list;watch

func (r *ImageAnnotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var image storagev1alpha1.Image
	if err := r.Get(ctx, req.NamespacedName, &image); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Find all workloads referencing this image
	workloads, err := r.findWorkloadsForImage(ctx, &image)
	if err != nil {
		logger.Error(err, "Failed to find workloads for image")
		return ctrl.Result{}, err
	}

	// Build expected annotations map: annotation key -> value
	expectedAnnotations := make(map[string]string, len(workloads))
	for _, w := range workloads {
		key := WorkloadAnnotationPrefix + string(w.UID)
		value, err := json.Marshal(WorkloadAnnotationValue{
			Name:       w.Name,
			Namespace:  w.Namespace,
			Containers: w.Containers,
			Summary:    w.Summary,
		})
		if err != nil {
			logger.Error(err, "Failed to marshal workload annotation value")
			continue
		}
		expectedAnnotations[key] = string(value)
	}

	// Get current workload annotations from the image
	currentAnnotations := r.getWorkloadAnnotations(image.Annotations)

	// Check if any changes are needed
	if maps.Equal(currentAnnotations, expectedAnnotations) {
		return ctrl.Result{}, nil
	}

	// Patch annotations
	patch := client.MergeFrom(image.DeepCopy())

	if image.Annotations == nil {
		image.Annotations = make(map[string]string)
	}

	// Remove stale annotations
	for key := range currentAnnotations {
		if _, exists := expectedAnnotations[key]; !exists {
			delete(image.Annotations, key)
		}
	}

	// Add or update annotations
	for key, value := range expectedAnnotations {
		image.Annotations[key] = value
	}

	if err := r.Patch(ctx, &image, patch); err != nil {
		logger.Error(err, "Failed to patch image annotations")
		return ctrl.Result{}, err
	}

	logger.V(1).Info("Updated workload annotations",
		"added", len(expectedAnnotations)-len(currentAnnotations),
		"removed", len(currentAnnotations)-len(expectedAnnotations),
		"total", len(expectedAnnotations),
	)

	return ctrl.Result{}, nil
}

// workloadInfo holds workload identity information
type workloadInfo struct {
	UID        types.UID
	Name       string
	Namespace  string
	Containers int
	Summary    storagev1alpha1.Summary
}

func (r *ImageAnnotationReconciler) findWorkloadsForImage(ctx context.Context, image *storagev1alpha1.Image) ([]workloadInfo, error) {
	indexKey := imageRefIndexKey(storagev1alpha1.ImageRef{
		Registry:   image.ImageMetadata.Registry,
		Namespace:  image.Namespace,
		Repository: image.ImageMetadata.Repository,
		Tag:        image.ImageMetadata.Tag,
	})

	var workloadList storagev1alpha1.WorkloadScanReportList
	if err := r.List(ctx, &workloadList,
		client.MatchingFields{WorkloadByImageRefIndex: indexKey},
	); err != nil {
		return nil, err
	}

	workloads := make([]workloadInfo, 0, len(workloadList.Items))
	for _, workload := range workloadList.Items {
		workloads = append(workloads, workloadInfo{
			UID:        workload.UID,
			Name:       workload.Name,
			Namespace:  workload.Namespace,
			Containers: len(workload.Spec.Containers),
			Summary:    workload.Summary,
		})
	}

	return workloads, nil
}

// getWorkloadAnnotations extracts all workload annotations from the annotations map
func (r *ImageAnnotationReconciler) getWorkloadAnnotations(annotations map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range annotations {
		if strings.HasPrefix(key, WorkloadAnnotationPrefix) {
			result[key] = value
		}
	}
	return result
}

// findImagesForWorkload returns reconcile requests for all Images referenced by a WorkloadScanReport.
func (r *ImageAnnotationReconciler) findImagesForWorkload(ctx context.Context, obj client.Object) []reconcile.Request {
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

		images, err := r.findImagesByRef(ctx, container.ImageRef)
		if err != nil {
			logger.Error(err, "Failed to find images by ref", "imageRef", container.ImageRef)
			continue
		}

		for _, image := range images {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      image.Name,
					Namespace: image.Namespace,
				},
			})
		}
	}

	return requests
}

func (r *ImageAnnotationReconciler) findImagesByRef(ctx context.Context, ref storagev1alpha1.ImageRef) ([]storagev1alpha1.Image, error) {
	var imageList storagev1alpha1.ImageList
	if err := r.List(ctx, &imageList,
		client.InNamespace(ref.Namespace),
		client.MatchingFields{ImageByMetadataIndex: imageMetadataIndexKey(ref)},
	); err != nil {
		return nil, err
	}

	return imageList.Items, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageAnnotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()

	// Register indexers
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&storagev1alpha1.Image{},
		ImageByMetadataIndex,
		indexImageByMetadata,
	); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&storagev1alpha1.WorkloadScanReport{},
		WorkloadByImageRefIndex,
		indexWorkloadByImageRef,
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("image-annotation-controller").
		For(&storagev1alpha1.Image{},
			builder.WithPredicates(managedByPredicate()),
		).
		Watches(
			&storagev1alpha1.WorkloadScanReport{},
			handler.EnqueueRequestsFromMapFunc(r.findImagesForWorkload),
			builder.WithPredicates(managedByPredicate()),
		).
		Complete(r)
}

// indexImageByMetadata indexes Images by registry/repository/tag
func indexImageByMetadata(obj client.Object) []string {
	image, ok := obj.(*storagev1alpha1.Image)
	if !ok {
		return nil
	}

	return []string{imageMetadataIndexKey(storagev1alpha1.ImageRef{
		Registry:   image.ImageMetadata.Registry,
		Repository: image.ImageMetadata.Repository,
		Tag:        image.ImageMetadata.Tag,
	})}
}

// indexWorkloadByImageRef indexes WorkloadScanReports by their container image refs
func indexWorkloadByImageRef(obj client.Object) []string {
	workload, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return nil
	}

	seen := sets.New[string]()
	var keys []string

	for _, container := range workload.Spec.Containers {
		key := imageRefIndexKey(container.ImageRef)
		if seen.Has(key) {
			continue
		}
		seen.Insert(key)
		keys = append(keys, key)
	}

	return keys
}

// imageMetadataIndexKey generates an index key for image metadata (without namespace)
func imageMetadataIndexKey(ref storagev1alpha1.ImageRef) string {
	return ref.Registry + "/" + ref.Repository + ":" + ref.Tag
}

// imageRefIndexKey generates an index key for a full image ref (with namespace)
func imageRefIndexKey(ref storagev1alpha1.ImageRef) string {
	return ref.Namespace + "/" + ref.Registry + "/" + ref.Repository + ":" + ref.Tag
}

// managedByPredicate filters resources managed by sbomscanner
func managedByPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()[api.LabelManagedByKey] == api.LabelManagedByValue
	})
}
