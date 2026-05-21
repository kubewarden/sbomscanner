package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToSchemeRegistersKnownTypes(t *testing.T) {
	scheme := runtime.NewScheme()

	require.NoError(t, AddToScheme(scheme))

	obj, err := scheme.New(GroupVersion.WithKind("ScanJob"))
	require.NoError(t, err)
	require.IsType(t, &ScanJob{}, obj)
}
