package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// +kubebuilder:object:generate=true
// +groupName=sbomscanner.kubewarden.io

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "sbomscanner.kubewarden.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = runtime.NewSchemeBuilder()

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func register(objects ...runtime.Object) {
	SchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(GroupVersion, objects...)
		metav1.AddToGroupVersion(scheme, GroupVersion)
		return nil
	})
}
