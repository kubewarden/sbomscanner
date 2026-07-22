package v1alpha1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// TestDefaultSkipPatternsMatchCRD guards against drift between DefaultSkipPatterns
// and the +kubebuilder:default marker on NodeScanConfigurationSpec.SkipPatterns.
// It parses the generated CRD and asserts its schema default equals the Go slice,
// which also fails if the CRD was not regenerated after a marker change.
// Path is relative to this package; update it if the chart layout moves.
func TestDefaultSkipPatternsMatchCRD(t *testing.T) {
	data, err := os.ReadFile("../../charts/sbomscanner/templates/crd/sbomscanner.kubewarden.io_nodescanconfigurations.yaml")
	require.NoError(t, err)

	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))

	require.Len(t, crd.Spec.Versions, 1)
	schema := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	def := schema.Properties["spec"].Properties["skipPatterns"].Default
	require.NotNil(t, def, "skipPatterns default missing from CRD")

	var got []string
	require.NoError(t, json.Unmarshal(def.Raw, &got))
	assert.Equal(t, DefaultSkipPatterns, got)
}
