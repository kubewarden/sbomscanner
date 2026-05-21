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
	SchemeBuilder = newObjectSchemeBuilder()

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

type objectSchemeBuilder struct {
	builder runtime.SchemeBuilder
}

func newObjectSchemeBuilder() *objectSchemeBuilder {
	return &objectSchemeBuilder{
		builder: runtime.NewSchemeBuilder(),
	}
}

func (b *objectSchemeBuilder) AddToScheme(scheme *runtime.Scheme) error {
	return b.builder.AddToScheme(scheme)
}

func (b *objectSchemeBuilder) Register(objects ...runtime.Object) {
	b.builder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(GroupVersion, objects...)
		metav1.AddToGroupVersion(scheme, GroupVersion)
		return nil
	})
}

func register(objects ...runtime.Object) {
	SchemeBuilder.Register(objects...)
}
