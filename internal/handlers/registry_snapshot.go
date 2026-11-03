package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// registryFromScanJob returns the Registry snapshot that the controller stored on the ScanJob.
// The snapshot must name the Registry that the ScanJob references, in the namespace of the ScanJob.
// The worker uses the namespace of the snapshot to look up the auth secret and the CA bundle,
// so a snapshot that names another Registry or another namespace is rejected.
func registryFromScanJob(scanJob *v1alpha1.ScanJob) (*v1alpha1.Registry, error) {
	registryData, ok := scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]
	if !ok {
		return nil, fmt.Errorf("scan job %s/%s does not have a registry annotation", scanJob.Namespace, scanJob.Name)
	}

	registry := &v1alpha1.Registry{}
	if err := json.Unmarshal([]byte(registryData), registry); err != nil {
		return nil, fmt.Errorf("cannot unmarshal registry data from scan job %s/%s: %w", scanJob.Namespace, scanJob.Name, err)
	}

	if registry.Namespace != scanJob.Namespace || registry.Name != scanJob.Spec.Registry {
		return nil, fmt.Errorf("registry annotation of scan job %s/%s refers to registry %s/%s, expected %s/%s",
			scanJob.Namespace, scanJob.Name,
			registry.Namespace, registry.Name,
			scanJob.Namespace, scanJob.Spec.Registry)
	}

	return registry, nil
}
