package handlers

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestNodeScanJobFailureHandler_HandleFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: "test-node",
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(nodeScanJob).
		WithStatusSubresource(nodeScanJob).
		Build()

	handler := NewNodeScanJobFailureHandler(k8sClient, slog.Default())

	message, err := json.Marshal(&GenerateNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
			},
		},
		Node: ObjectRef{
			Name: "test-node",
		},
	})
	require.NoError(t, err)

	errorMessage := "NodeSBOM generation failed"
	err = handler.HandleFailure(t.Context(), &testMessage{data: message}, errorMessage)
	require.NoError(t, err)

	updatedJob := &v1alpha1.NodeScanJob{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: nodeScanJob.Name}, updatedJob)
	require.NoError(t, err)

	assert.True(t, updatedJob.IsFailed())
	failedCondition := meta.FindStatusCondition(updatedJob.Status.Conditions, v1alpha1.ConditionNodeScanJobTypeFailed)
	require.NotNil(t, failedCondition)
	assert.Equal(t, v1alpha1.ReasonScanJobInternalError, failedCondition.Reason)
	assert.Equal(t, errorMessage, failedCondition.Message)
}

func TestNodeScanJobFailureHandler_HandleFailure_NodeScanJobNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewNodeScanJobFailureHandler(k8sClient, slog.Default())

	message, err := json.Marshal(&GenerateNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: "missing-nodescanjob",
			},
		},
		Node: ObjectRef{
			Name: "test-node",
		},
	})
	require.NoError(t, err)

	err = handler.HandleFailure(t.Context(), &testMessage{data: message}, "kaboom")
	require.NoError(t, err)

	job := &v1alpha1.NodeScanJob{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: "missing-nodescanjob"}, job)
	assert.True(t, apierrors.IsNotFound(err))
}
