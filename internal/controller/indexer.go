package controller

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

	return nil
}
