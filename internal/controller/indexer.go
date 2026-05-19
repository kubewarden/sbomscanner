package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func SetupIndexer(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &v1alpha1.ScanJob{}, v1alpha1.IndexScanJobSpecRegistry, func(rawObj client.Object) []string {
		scanJob, ok := rawObj.(*v1alpha1.ScanJob)
		if !ok {
			panic(fmt.Sprintf("Expected ScanJob, got %T", rawObj))
		}
		return []string{scanJob.Spec.Registry}
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer for spec.registry: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &v1alpha1.ScanJob{}, v1alpha1.IndexScanJobMetadataUID, func(rawObj client.Object) []string {
		scanJob, ok := rawObj.(*v1alpha1.ScanJob)
		if !ok {
			panic(fmt.Sprintf("Expected ScanJob, got %T", rawObj))
		}
		return []string{string(scanJob.UID)}
	}); err != nil {
		return fmt.Errorf("unable to create field indexer: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &v1alpha1.NodeScanJob{}, v1alpha1.IndexNodeScanJobSpecNodeName, func(rawObj client.Object) []string {
		nodeScanJob, ok := rawObj.(*v1alpha1.NodeScanJob)
		if !ok {
			panic(fmt.Sprintf("Expected NodeScanJob, got %T", rawObj))
		}
		return []string{nodeScanJob.Spec.NodeName}
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer for spec.nodeName: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataComposite, indexImageByMetadata); err != nil {
		return fmt.Errorf("failed to setup field indexer for %s: %w", storagev1alpha1.IndexImageMetadataComposite, err)
	}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &storagev1alpha1.WorkloadScanReport{}, storagev1alpha1.IndexWorkloadScanReportImageRef, indexWorkloadByImageRef); err != nil {
		return fmt.Errorf("failed to setup field indexer for %s: %w", storagev1alpha1.IndexWorkloadScanReportImageRef, err)
	}

	return nil
}

// indexImageByMetadata indexes Images by registry/repository:tag
func indexImageByMetadata(obj client.Object) []string {
	image, ok := obj.(*storagev1alpha1.Image)
	if !ok {
		return nil
	}

	return []string{imageMetadataIndexKey(image.ImageMetadata)}
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

// imageMetadataIndexKey generates an index key for image metadata: registry/repository:tag
func imageMetadataIndexKey(m storagev1alpha1.ImageMetadata) string {
	return fmt.Sprintf("%s/%s:%s", m.Registry, m.Repository, m.Tag)
}

// imageRefIndexKey generates an index key for a full image ref: namespace/registry/repository:tag
func imageRefIndexKey(ref storagev1alpha1.ImageRef) string {
	return fmt.Sprintf("%s/%s/%s:%s", ref.Namespace, ref.Registry, ref.Repository, ref.Tag)
}
