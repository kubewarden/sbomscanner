package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	_ "modernc.org/sqlite"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestNodeScanSBOMHandler_Handle(t *testing.T) {
	cacheDir := t.TempDir()

	spdxData, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"))
	require.NoError(t, err)

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
			UID:  "test-nodescanjob-uid",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: "test-node",
		},
	}

	nodeSBOM := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			UID:  "test-nodesbom-uid",
		},
		NodeMetadata: storagev1alpha1.NodeMetadata{
			Name:     "test-node",
			Platform: "linux/amd64",
		},
		SPDX: runtime.RawExtension{Raw: spdxData},
	}

	vexHubs := &v1alpha1.VEXHubList{
		Items: []v1alpha1.VEXHub{},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(nodeScanJob, nodeSBOM, vexHubs).
		WithStatusSubresource(&v1alpha1.NodeScanJob{}).
		Build()

	handler := NewNodeScanSBOMHandler(k8sClient, scheme, cacheDir, testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

	message, err := json.Marshal(&ScanNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
				UID:  string(nodeScanJob.UID),
			},
		},
		NodeSBOM: ObjectRef{
			Name: nodeSBOM.Name,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	report := &storagev1alpha1.NodeVulnerabilityReport{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: nodeSBOM.Name}, report)
	require.NoError(t, err)

	assert.Equal(t, nodeSBOM.NodeMetadata, report.NodeMetadata)
	assert.Equal(t, string(nodeScanJob.UID), report.Labels[v1alpha1.LabelNodeScanJobUIDKey])
	assert.Equal(t, api.LabelManagedByValue, report.Labels[api.LabelManagedByKey])
	assert.Equal(t, api.LabelPartOfValue, report.Labels[api.LabelPartOfKey])
	assert.Equal(t, nodeSBOM.UID, report.GetOwnerReferences()[0].UID)
	assert.NotEmpty(t, report.Report.Results)

	updatedJob := &v1alpha1.NodeScanJob{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: nodeScanJob.Name}, updatedJob)
	require.NoError(t, err)
	assert.True(t, updatedJob.IsComplete())
}

func TestNodeScanSBOMHandler_Handle_StopProcessing(t *testing.T) {
	spdxData, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"))
	require.NoError(t, err)

	nodeSBOM := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		NodeMetadata: storagev1alpha1.NodeMetadata{
			Name:     "test-node",
			Platform: "linux/amd64",
		},
		SPDX: runtime.RawExtension{Raw: spdxData},
	}

	vexHubs := &v1alpha1.VEXHubList{
		Items: []v1alpha1.VEXHub{},
	}

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
			UID:  "test-nodescanjob-uid",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: "test-node",
		},
	}

	differentUIDNodeScanJob := nodeScanJob.DeepCopy()
	differentUIDNodeScanJob.UID = "test-nodescanjob-different-uid"

	failedNodeScanJob := nodeScanJob.DeepCopy()
	failedNodeScanJob.MarkFailed(v1alpha1.ReasonScanJobInternalError, "kaboom")

	tests := []struct {
		name            string
		nodeScanJob     *v1alpha1.NodeScanJob
		existingObjects []runtime.Object
	}{
		{
			name:            "nodescanjob not found",
			nodeScanJob:     nodeScanJob,
			existingObjects: []runtime.Object{nodeSBOM, vexHubs},
		},
		{
			name:            "nodescanjob was recreated with different UID",
			nodeScanJob:     nodeScanJob,
			existingObjects: []runtime.Object{differentUIDNodeScanJob, nodeSBOM, vexHubs},
		},
		{
			name:            "nodescanjob is failed",
			nodeScanJob:     failedNodeScanJob,
			existingObjects: []runtime.Object{failedNodeScanJob, nodeSBOM, vexHubs},
		},
		{
			name:            "nodesbom not found",
			nodeScanJob:     nodeScanJob,
			existingObjects: []runtime.Object{nodeScanJob, vexHubs},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, storagev1alpha1.AddToScheme(scheme))
			require.NoError(t, v1alpha1.AddToScheme(scheme))

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(test.existingObjects...).
				WithStatusSubresource(&v1alpha1.NodeScanJob{}).
				Build()

			cacheDir := t.TempDir()
			handler := NewNodeScanSBOMHandler(k8sClient, scheme, cacheDir, testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

			message, err := json.Marshal(&ScanNodeSBOMMessage{
				NodeBaseMessage: NodeBaseMessage{
					NodeScanJob: ObjectRef{
						Name: test.nodeScanJob.Name,
						UID:  string(test.nodeScanJob.UID),
					},
				},
				NodeSBOM: ObjectRef{
					Name: nodeSBOM.Name,
				},
			})
			require.NoError(t, err)

			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			report := &storagev1alpha1.NodeVulnerabilityReport{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: nodeSBOM.Name}, report)
			assert.True(t, apierrors.IsNotFound(err), "NodeVulnerabilityReport should not exist")
		})
	}
}
