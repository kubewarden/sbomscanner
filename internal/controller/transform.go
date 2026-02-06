package controller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// TransformStripPod strips the Pod object to only keep container names and images.
// This removes status and all other spec fields to reduce memory usage.
// The workloadscan controller only needs container names and images.
func TransformStripPod(object interface{}) (interface{}, error) {
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
