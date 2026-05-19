package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	messagingMocks "github.com/kubewarden/sbomscanner/internal/messaging/mocks"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
)

func TestGenerateNodeSBOMHandler_Handle(t *testing.T) {
	targetDir := filepath.Join("..", "..", "test", "fixtures", "node")
	nodeName := "test-node"

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  "test-node-uid",
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OperatingSystem: "linux",
				Architecture:    "amd64",
			},
		},
	}

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
			UID:  "test-nodescanjob-uid",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: nodeName,
		},
	}

	config := &v1alpha1.NodeScanConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: v1alpha1.NodeScanConfigurationName,
		},
	}

	scheme := scheme.Scheme
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(node, nodeScanJob, config).
		WithIndex(&storagev1alpha1.NodeSBOM{}, storagev1alpha1.IndexNodeMetadataName, func(obj client.Object) []string {
			sbom, ok := obj.(*storagev1alpha1.NodeSBOM)
			if !ok {
				return nil
			}
			return []string{sbom.NodeMetadata.Name}
		}).
		Build()

	publisher := messagingMocks.NewMockPublisher(t)

	expectedScanMessage, err := json.Marshal(&ScanNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
				UID:  string(nodeScanJob.UID),
			},
		},
		NodeSBOM: ObjectRef{
			Name: nodeName,
		},
	})
	require.NoError(t, err)

	publisher.On("Publish",
		mock.Anything,
		ScanNodeSBOMSubject+"."+nodeName,
		fmt.Sprintf("nodeScanSBOM/%s/%s", nodeScanJob.UID, nodeName),
		expectedScanMessage,
	).Return(nil).Once()

	handler := NewGenerateNodeSBOMHandler(k8sClient, scheme, t.TempDir(), targetDir, testTrivyJavaDBRepository, publisher, "sbomscanner", slog.Default())

	message, err := json.Marshal(&GenerateNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
				UID:  string(nodeScanJob.UID),
			},
		},
		Node: ObjectRef{
			Name: nodeName,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	sbom := &storagev1alpha1.NodeSBOM{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: nodeName}, sbom)
	require.NoError(t, err)

	assert.Equal(t, nodeName, sbom.NodeMetadata.Name)
	assert.Equal(t, "linux/amd64", sbom.NodeMetadata.Platform)
	assert.Equal(t, api.LabelManagedByValue, sbom.Labels[api.LabelManagedByKey])
	assert.Equal(t, api.LabelPartOfValue, sbom.Labels[api.LabelPartOfKey])
	assert.Equal(t, node.UID, sbom.GetOwnerReferences()[0].UID)
	assert.NotEmpty(t, sbom.SPDX.Raw)
}

func TestGenerateNodeSBOMHandler_Handle_StopProcessing(t *testing.T) {
	nodeName := "test-node"

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  "test-node-uid",
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OperatingSystem: "linux",
				Architecture:    "amd64",
			},
		},
	}

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
			UID:  "test-nodescanjob-uid",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: nodeName,
		},
	}

	failedNodeScanJob := nodeScanJob.DeepCopy()
	failedNodeScanJob.MarkFailed(v1alpha1.ReasonInternalError, "kaboom")

	config := &v1alpha1.NodeScanConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: v1alpha1.NodeScanConfigurationName,
		},
	}

	tests := []struct {
		name            string
		nodeScanJob     *v1alpha1.NodeScanJob
		existingObjects []runtime.Object
	}{
		{
			name:            "nodescanjob not found",
			nodeScanJob:     nodeScanJob,
			existingObjects: []runtime.Object{node, config},
		},
		{
			name:            "nodescanjob is failed",
			nodeScanJob:     failedNodeScanJob,
			existingObjects: []runtime.Object{failedNodeScanJob, node, config},
		},
		{
			name:            "node not found",
			nodeScanJob:     nodeScanJob,
			existingObjects: []runtime.Object{nodeScanJob, config},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := scheme.Scheme
			require.NoError(t, storagev1alpha1.AddToScheme(scheme))
			require.NoError(t, v1alpha1.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(test.existingObjects...).
				WithIndex(&storagev1alpha1.NodeSBOM{}, storagev1alpha1.IndexNodeMetadataName, func(obj client.Object) []string {
					sbom, ok := obj.(*storagev1alpha1.NodeSBOM)
					if !ok {
						return nil
					}
					return []string{sbom.NodeMetadata.Name}
				}).
				Build()

			publisher := messagingMocks.NewMockPublisher(t)

			handler := NewGenerateNodeSBOMHandler(k8sClient, scheme, t.TempDir(), "/tmp", testTrivyJavaDBRepository, publisher, "sbomscanner", slog.Default())

			message, err := json.Marshal(&GenerateNodeSBOMMessage{
				NodeBaseMessage: NodeBaseMessage{
					NodeScanJob: ObjectRef{
						Name: test.nodeScanJob.Name,
						UID:  string(test.nodeScanJob.UID),
					},
				},
				Node: ObjectRef{
					Name: nodeName,
				},
			})
			require.NoError(t, err)

			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			sbom := &storagev1alpha1.NodeSBOM{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: nodeName}, sbom)
			assert.True(t, apierrors.IsNotFound(err), "NodeSBOM should not exist")
		})
	}
}

func TestGenerateNodeSBOMHandler_Handle_ReuseSBOMWithSameNodeName(t *testing.T) {
	targetDir := filepath.Join("..", "..", "test", "fixtures", "node")
	nodeName := "test-node"

	expectedSPDXContent := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0"}`)

	existingNodeSBOM := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-node-sbom",
			UID:  "existing-sbom-uid",
		},
		NodeMetadata: storagev1alpha1.NodeMetadata{
			Name:     nodeName,
			Platform: "linux/amd64",
		},
		SPDX: runtime.RawExtension{Raw: expectedSPDXContent},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  "test-node-uid",
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OperatingSystem: "linux",
				Architecture:    "amd64",
			},
		},
	}

	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nodescanjob",
			UID:  "test-nodescanjob-uid",
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: nodeName,
		},
	}

	config := &v1alpha1.NodeScanConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: v1alpha1.NodeScanConfigurationName,
		},
	}

	scheme := scheme.Scheme
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(existingNodeSBOM, node, nodeScanJob, config).
		WithIndex(&storagev1alpha1.NodeSBOM{}, storagev1alpha1.IndexNodeMetadataName, func(obj client.Object) []string {
			sbom, ok := obj.(*storagev1alpha1.NodeSBOM)
			if !ok {
				return nil
			}
			return []string{sbom.NodeMetadata.Name}
		}).
		Build()

	publisher := messagingMocks.NewMockPublisher(t)

	expectedScanMessage, err := json.Marshal(&ScanNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
				UID:  string(nodeScanJob.UID),
			},
		},
		NodeSBOM: ObjectRef{
			Name: nodeName,
		},
	})
	require.NoError(t, err)

	publisher.On("Publish",
		mock.Anything,
		ScanNodeSBOMSubject+"."+nodeScanJob.Spec.NodeName,
		fmt.Sprintf("nodeScanSBOM/%s/%s", nodeScanJob.UID, nodeName),
		expectedScanMessage,
	).Return(nil).Once()

	handler := NewGenerateNodeSBOMHandler(k8sClient, scheme, t.TempDir(), targetDir, testTrivyJavaDBRepository, publisher, "sbomscanner", slog.Default())

	message, err := json.Marshal(&GenerateNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: ObjectRef{
				Name: nodeScanJob.Name,
				UID:  string(nodeScanJob.UID),
			},
		},
		Node: ObjectRef{
			Name: nodeName,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	newSBOM := &storagev1alpha1.NodeSBOM{}
	err = k8sClient.Get(t.Context(), types.NamespacedName{Name: nodeName}, newSBOM)
	require.NoError(t, err)

	assert.Equal(t, expectedSPDXContent, newSBOM.SPDX.Raw, "SPDX content should be reused from existing NodeSBOM")
	assert.Equal(t, nodeName, newSBOM.NodeMetadata.Name)
	assert.Equal(t, "linux/amd64", newSBOM.NodeMetadata.Platform)
	assert.Equal(t, node.UID, newSBOM.GetOwnerReferences()[0].UID)
	assert.Equal(t, api.LabelManagedByValue, newSBOM.Labels[api.LabelManagedByKey])
	assert.Equal(t, api.LabelPartOfValue, newSBOM.Labels[api.LabelPartOfKey])
}
