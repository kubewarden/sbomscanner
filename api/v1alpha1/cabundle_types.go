package v1alpha1

const (
	// CABundleDefaultKey is the default key holding the PEM-encoded CA bundle in a referenced ConfigMap or Secret.
	CABundleDefaultKey = "ca.crt"
)

// CABundleKeySelector selects a key of a ConfigMap or Secret containing a PEM-encoded CA bundle.
type CABundleKeySelector struct {
	// Name of the referenced object.
	Name string `json:"name"`
	// Key holding the PEM-encoded CA bundle. Defaults to "ca.crt".
	// +kubebuilder:default=ca.crt
	// +optional
	Key string `json:"key,omitempty"`
}

// CABundleSource references a PEM-encoded CA bundle stored in a ConfigMap or Secret.
// Exactly one of the fields must be set.
// +kubebuilder:validation:XValidation:rule="has(self.configMap) != has(self.secret)",message="exactly one of configMap or secret must be set"
type CABundleSource struct {
	// ConfigMap references a key of a ConfigMap.
	// +optional
	ConfigMap *CABundleKeySelector `json:"configMap,omitempty"`
	// Secret references a key of a Secret.
	// +optional
	Secret *CABundleKeySelector `json:"secret,omitempty"`
}
