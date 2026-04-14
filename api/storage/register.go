package storage

import (
	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the group name used in this package
const GroupName = "storage.sbomscanner.kubewarden.io"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: runtime.APIVersionInternal}

// Kind takes an unqualified kind and returns back a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// Resource takes an unqualified resource and returns back a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is the scheme builder with scheme init functions to run for this API package
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme is a common registration function for mapping packaged scoped group & version keys to a scheme
	AddToScheme = SchemeBuilder.AddToScheme
)

// Adds the list of known types to the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&v1alpha1.Image{},
		&v1alpha1.ImageList{},

		&v1alpha1.SBOM{},
		&v1alpha1.SBOMList{},

		&v1alpha1.VulnerabilityReport{},
		&v1alpha1.VulnerabilityReportList{},

		&v1alpha1.NodeSBOM{},
		&v1alpha1.NodeSBOMList{},

		&v1alpha1.NodeVulnerabilityReport{},
		&v1alpha1.NodeVulnerabilityReportList{},
	)
	return nil
}
