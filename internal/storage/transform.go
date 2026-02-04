package storage

import (
	"fmt"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// TransformStripImage strips the Image object of its Layers field and managed fields.
// This is useful for caching scenarios where the Layers data is not needed, reducing memory usage.
func TransformStripImage(obj interface{}) (interface{}, error) {
	image, ok := obj.(*storagev1alpha1.Image)
	if !ok {
		return obj, fmt.Errorf("expected Image object, got %T", obj)
	}

	image.Layers = nil

	return cache.TransformStripManagedFields()(image)
}

// TransformStripSBOM strips the SBOM object of its SPDX field and managed fields.
// This is useful for caching scenarios where the SPDX data is not needed, reducing memory usage.
func TransformStripSBOM(obj interface{}) (interface{}, error) {
	sbom, ok := obj.(*storagev1alpha1.SBOM)
	if !ok {
		return nil, fmt.Errorf("expected SBOM object, got %T", obj)
	}

	sbom.SPDX = runtime.RawExtension{}

	return cache.TransformStripManagedFields()(sbom)
}

// TransformStripVulnerabilityReport strips the VulnerabilityReport object of its Results field and managed fields.
// This is useful for caching scenarios where the Results data is not needed, reducing memory usage.
func TransformStripVulnerabilityReport(obj interface{}) (interface{}, error) {
	vulnerabilityReport, ok := obj.(*storagev1alpha1.VulnerabilityReport)
	if !ok {
		return obj, fmt.Errorf("expected VulnerabilityReport object, got %T", obj)
	}

	vulnerabilityReport.Report.Results = nil

	return cache.TransformStripManagedFields()(vulnerabilityReport)
}

// TransformStripWorkloadScanReport strips the WorkloadScanReport object of its status.
// This is useful for caching scenarios where the Reports data is not needed, reducing memory usage.
func TransformStripWorkloadScanReport(object interface{}) (interface{}, error) {
	report, ok := object.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return object, fmt.Errorf("expected WorkloadScanReport object, got %T", object)
	}

	report.Containers = nil
	report.Status = storagev1alpha1.WorkloadScanReportStatus{}

	return cache.TransformStripManagedFields()(report)
}
