package controller

import (
	"context"
	"slices"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// mapObjToNamespace maps any object to a reconciliation request for its namespace
func mapObjToNamespace(_ context.Context, obj client.Object) []ctrl.Request {
	// Trigger reconciliation for the entire namespace
	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: obj.GetNamespace(),
				Name:      "", // Empty name for namespace-level reconciliation
			},
		},
	}
}

// mapConfigToNamespaces returns a handler that enqueues all namespaces matching the selector when config changes
func mapConfigToNamespaces(c client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		logger := log.FromContext(ctx)

		config, ok := obj.(*v1alpha1.WorkloadScanConfiguration)
		if !ok {
			return nil
		}

		var namespaces metav1.PartialObjectMetadataList
		namespaces.SetGroupVersionKind(
			corev1.SchemeGroupVersion.WithKind("NamespaceList"),
		)

		var listOpts []client.ListOption
		if config.Spec.NamespaceSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(
				config.Spec.NamespaceSelector,
			)
			if err != nil {
				logger.Error(err, "invalid namespace selector")
				return nil
			}

			listOpts = append(
				listOpts,
				client.MatchingLabelsSelector{Selector: selector},
			)
		}

		if err := c.List(ctx, &namespaces, listOpts...); err != nil {
			logger.Error(err, "failed to list namespaces")
			return nil
		}

		requests := make([]ctrl.Request, 0, len(namespaces.Items))
		for _, ns := range namespaces.Items {
			requests = append(requests, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns.Name,
				},
			})
		}

		logger.Info("config changed, enqueuing namespaces", "count", len(requests))

		return requests
	}
}

// mapNamespace maps a namespace object to a reconciliation request for that namespace
func mapNamespace(_ context.Context, obj client.Object) []ctrl.Request {
	// Trigger reconciliation for the entire namespace
	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: obj.GetName(),
				Name:      "", // Empty name for namespace-level reconciliation
			},
		},
	}
}

// podImagesChangedPredicate filters events to only trigger when container images change
func podImagesChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(_ event.CreateEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, ok := e.ObjectOld.(*corev1.Pod)
			if !ok {
				return false
			}
			newPod, ok := e.ObjectNew.(*corev1.Pod)
			if !ok {
				return false
			}
			oldImages := slices.Sorted(slices.Values(extractImagesFromPodSpec(oldPod.Spec)))
			newImages := slices.Sorted(slices.Values(extractImagesFromPodSpec(newPod.Spec)))
			return !slices.Equal(oldImages, newImages)
		},
		DeleteFunc: func(_ event.DeleteEvent) bool {
			return true
		},
	}
}

// extractImagesFromPodSpec returns all container images in a PodSpec
func extractImagesFromPodSpec(podSpec corev1.PodSpec) []string {
	images := make([]string, 0, len(podSpec.InitContainers)+len(podSpec.Containers))

	for _, container := range podSpec.InitContainers {
		images = append(images, container.Image)
	}

	for _, container := range podSpec.Containers {
		images = append(images, container.Image)
	}

	return images
}
