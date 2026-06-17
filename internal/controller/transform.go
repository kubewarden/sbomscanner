package controller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// TransformStripPod strips the Pod object to only keep container names and images.
// This removes status and all other spec fields to reduce memory usage.
// The workloadscan controller only needs container names and images.
func TransformStripPod(object any) (any, error) {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return object, fmt.Errorf("expected Pod object, got %T", object)
	}

	// Keep only Name and Image for init containers
	strippedInitContainers := make([]corev1.Container, len(pod.Spec.InitContainers))
	for index, container := range pod.Spec.InitContainers {
		strippedInitContainers[index] = corev1.Container{
			Name:  container.Name,
			Image: container.Image,
		}
	}

	// Keep only Name and Image for containers
	strippedContainers := make([]corev1.Container, len(pod.Spec.Containers))
	for index, container := range pod.Spec.Containers {
		strippedContainers[index] = corev1.Container{
			Name:  container.Name,
			Image: container.Image,
		}
	}

	// Replace spec with stripped version, keeping only containers
	pod.Spec = corev1.PodSpec{
		InitContainers: strippedInitContainers,
		Containers:     strippedContainers,
	}

	// Strip status entirely
	pod.Status = corev1.PodStatus{}

	return cache.TransformStripManagedFields()(pod)
}

// TransformStripNode strips a Node object to reduce cache memory usage.
// It clears Spec entirely, clears Status except for NodeInfo.OperatingSystem/Architecture, and strips Annotations and managed fields.
func TransformStripNode(object any) (any, error) {
	node, ok := object.(*corev1.Node)
	if !ok {
		return object, fmt.Errorf("expected Node object, got %T", object)
	}

	node.Annotations = nil
	node.Spec = corev1.NodeSpec{}
	node.Status = corev1.NodeStatus{
		NodeInfo: corev1.NodeSystemInfo{
			OperatingSystem: node.Status.NodeInfo.OperatingSystem,
			Architecture:    node.Status.NodeInfo.Architecture,
		},
	}

	return cache.TransformStripManagedFields()(node)
}
