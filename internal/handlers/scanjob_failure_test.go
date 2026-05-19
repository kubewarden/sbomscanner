package handlers

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sbombasticv1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestScanJobFailureHandler_HandleFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	err := sbombasticv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	scanJob := &sbombasticv1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
		},
		Spec: sbombasticv1alpha1.ScanJobSpec{
			Registry: "test-registry",
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(scanJob).
		WithStatusSubresource(scanJob).
		Build()

	handler := NewScanJobFailureHandler(k8sClient, slog.Default())

	message, err := json.Marshal(&GenerateSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
			},
		},
		Image: ObjectRef{
			Name:      "test-image",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	errorMessage := "SBOM generation failed"
	err = handler.HandleFailure(t.Context(), &testMessage{data: message}, errorMessage)
	require.NoError(t, err)

	updatedScanJob := &sbombasticv1alpha1.ScanJob{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{
		Name:      scanJob.Name,
		Namespace: scanJob.Namespace,
	}, updatedScanJob)
	require.NoError(t, err)

	assert.True(t, updatedScanJob.IsFailed())
	failedCondition := meta.FindStatusCondition(updatedScanJob.Status.Conditions, string(sbombasticv1alpha1.ConditionTypeFailed))
	require.NotNil(t, failedCondition)
	assert.Equal(t, sbombasticv1alpha1.ReasonInternalError, failedCondition.Reason)
	assert.Equal(t, errorMessage, failedCondition.Message)
}
