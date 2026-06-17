package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTransformStripPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name:    "init-container",
					Image:   "busybox:latest",
					Command: []string{"echo", "init"},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{ //nolint:exhaustive // this is just a test
							corev1.ResourceMemory: resource.MustParse("64Mi"),
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:    "main-container",
					Image:   "nginx:1.25",
					Command: []string{"nginx"},
					Args:    []string{"-g", "daemon off;"},
					Ports: []corev1.ContainerPort{
						{ContainerPort: 80},
					},
					Env: []corev1.EnvVar{
						{Name: "FOO", Value: "bar"},
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{ //nolint:exhaustive // this is just a test
							corev1.ResourceMemory: resource.MustParse("128Mi"),
							corev1.ResourceCPU:    resource.MustParse("100m"),
						},
					},
				},
				{
					Name:  "sidecar",
					Image: "fluentd:latest",
				},
			},
			ServiceAccountName: "my-service-account",
			NodeName:           "node-1",
			Volumes: []corev1.Volume{
				{Name: "data"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.1",
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:  "main-container",
					Ready: true,
				},
			},
		},
	}

	result, err := TransformStripPod(pod)
	require.NoError(t, err)

	resultPod := result.(*corev1.Pod)

	// ObjectMeta should be preserved
	assert.Equal(t, "test-pod", resultPod.Name)
	assert.Equal(t, "default", resultPod.Namespace)

	// Init containers should only have Name and Image
	require.Len(t, resultPod.Spec.InitContainers, 1)
	assert.Equal(t, "init-container", resultPod.Spec.InitContainers[0].Name)
	assert.Equal(t, "busybox:latest", resultPod.Spec.InitContainers[0].Image)
	assert.Nil(t, resultPod.Spec.InitContainers[0].Command)
	assert.Empty(t, resultPod.Spec.InitContainers[0].Resources.Limits)

	// Containers should only have Name and Image
	require.Len(t, resultPod.Spec.Containers, 2)
	assert.Equal(t, "main-container", resultPod.Spec.Containers[0].Name)
	assert.Equal(t, "nginx:1.25", resultPod.Spec.Containers[0].Image)
	assert.Nil(t, resultPod.Spec.Containers[0].Command)
	assert.Nil(t, resultPod.Spec.Containers[0].Args)
	assert.Nil(t, resultPod.Spec.Containers[0].Ports)
	assert.Nil(t, resultPod.Spec.Containers[0].Env)
	assert.Empty(t, resultPod.Spec.Containers[0].Resources.Limits)

	assert.Equal(t, "sidecar", resultPod.Spec.Containers[1].Name)
	assert.Equal(t, "fluentd:latest", resultPod.Spec.Containers[1].Image)

	// Other spec fields should be stripped
	assert.Empty(t, resultPod.Spec.ServiceAccountName)
	assert.Empty(t, resultPod.Spec.NodeName)
	assert.Nil(t, resultPod.Spec.Volumes)

	// Status should be stripped
	assert.Empty(t, resultPod.Status.Phase)
	assert.Empty(t, resultPod.Status.PodIP)
	assert.Nil(t, resultPod.Status.ContainerStatuses)
}

func TestTransformStripNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			Labels: map[string]string{
				"kubernetes.io/os":   "linux",
				"kubernetes.io/arch": "amd64",
			},
			Annotations: map[string]string{
				"node.alpha.kubernetes.io/ttl": "0",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:       "10.244.0.0/24",
			ProviderID:    "aws:///us-east-1a/i-0abcdef",
			Unschedulable: true,
			Taints: []corev1.Taint{
				{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule},
			},
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OperatingSystem: "linux",
				Architecture:    "amd64",
				KernelVersion:   "5.15.0",
				OSImage:         "Ubuntu 22.04",
				KubeletVersion:  "v1.30.0",
			},
			Capacity: corev1.ResourceList{ //nolint:exhaustive // this is just a test
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{ //nolint:exhaustive // this is just a test
				corev1.ResourceCPU:    resource.MustParse("3500m"),
				corev1.ResourceMemory: resource.MustParse("7Gi"),
			},
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			},
			Images: []corev1.ContainerImage{
				{Names: []string{"nginx:1.25"}, SizeBytes: 12345},
				{Names: []string{"busybox:latest"}, SizeBytes: 6789},
			},
			VolumesInUse: []corev1.UniqueVolumeName{"v1", "v2"},
			VolumesAttached: []corev1.AttachedVolume{
				{Name: "v1", DevicePath: "/dev/sda"},
			},
		},
	}

	result, err := TransformStripNode(node)
	require.NoError(t, err)

	resultNode := result.(*corev1.Node)

	// Name and Labels should be preserved
	assert.Equal(t, "test-node", resultNode.Name)
	assert.Equal(t, "linux", resultNode.Labels["kubernetes.io/os"])
	assert.Equal(t, "amd64", resultNode.Labels["kubernetes.io/arch"])

	// Only OperatingSystem and Architecture from NodeInfo should be preserved
	assert.Equal(t, "linux", resultNode.Status.NodeInfo.OperatingSystem)
	assert.Equal(t, "amd64", resultNode.Status.NodeInfo.Architecture)
	assert.Empty(t, resultNode.Status.NodeInfo.KernelVersion)
	assert.Empty(t, resultNode.Status.NodeInfo.OSImage)
	assert.Empty(t, resultNode.Status.NodeInfo.KubeletVersion)

	// Annotations should be stripped
	assert.Nil(t, resultNode.Annotations)

	// Spec should be stripped entirely
	assert.Empty(t, resultNode.Spec.PodCIDR)
	assert.Empty(t, resultNode.Spec.ProviderID)
	assert.False(t, resultNode.Spec.Unschedulable)
	assert.Nil(t, resultNode.Spec.Taints)

	// All other Status fields should be stripped
	assert.Empty(t, resultNode.Status.Capacity)
	assert.Empty(t, resultNode.Status.Allocatable)
	assert.Nil(t, resultNode.Status.Conditions)
	assert.Nil(t, resultNode.Status.Addresses)
	assert.Nil(t, resultNode.Status.Images)
	assert.Nil(t, resultNode.Status.VolumesInUse)
	assert.Nil(t, resultNode.Status.VolumesAttached)
}
