package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// reconcileWorkloadScanReports creates or updates WorkloadScanReport resources for each workload.
// It also deletes stale reports that no longer have corresponding workloads.
func (r *WorkloadScanReconciler) reconcileWorkloadScanReports(ctx context.Context, namespace string, pods []corev1.Pod, config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	// Build set of expected report names from current pods
	podsByReport, err := r.buildPodsByReport(ctx, pods)
	if err != nil {
		return err
	}

	var existingReports storagev1alpha1.WorkloadScanReportList
	if err := r.List(ctx, &existingReports,
		client.InNamespace(namespace),
		client.MatchingLabels{api.LabelManagedByKey: api.LabelManagedByValue},
	); err != nil {
		return fmt.Errorf("failed to list WorkloadScanReports: %w", err)
	}

	// Delete stale WorkloadScanReports
	for _, report := range existingReports.Items {
		if _, exists := podsByReport[report.Name]; exists {
			continue
		}

		logger.Info("Deleting stale WorkloadScanReport", "report", report.Name)
		if err := r.Delete(ctx, &report); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete stale WorkloadScanReport %s: %w", report.Name, err)
		}
	}

	// Create or update reports for current workloads
	for reportName, pod := range podsByReport {
		if err := r.createOrPatchWorkloadScanReport(ctx, namespace, reportName, pod, config); err != nil {
			return err
		}
	}

	return nil
}

// buildPodsByReport builds a map of report names to pods.
// Each unique workload owner gets one report.
func (r *WorkloadScanReconciler) buildPodsByReport(ctx context.Context, pods []corev1.Pod) (map[string]*corev1.Pod, error) {
	podsByReport := make(map[string]*corev1.Pod)

	for i := range pods {
		pod := &pods[i]
		ownerReference, err := r.resolveWorkloadOwner(ctx, pod)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve workload owner for pod %s: %w", pod.Name, err)
		}

		reportName := computeWorkloadScanReportName(ownerReference.Kind, ownerReference.Name)
		if _, exists := podsByReport[reportName]; !exists {
			podsByReport[reportName] = pod
		}
	}

	return podsByReport, nil
}

// createOrPatchWorkloadScanReport creates or updates a single WorkloadScanReport.
func (r *WorkloadScanReconciler) createOrPatchWorkloadScanReport(ctx context.Context, namespace, reportName string, pod *corev1.Pod, config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	ownerReference, err := r.resolveWorkloadOwner(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to resolve workload owner for pod %s: %w", pod.Name, err)
	}

	report := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: namespace,
		},
	}

	operation, err := controllerutil.CreateOrPatch(ctx, r.Client, report, func() error {
		if report.Labels == nil {
			report.Labels = make(map[string]string)
		}
		report.Labels[api.LabelManagedByKey] = api.LabelManagedByValue
		report.OwnerReferences = []metav1.OwnerReference{*ownerReference}
		imageRefNamespace := namespace
		if config.Spec.ArtifactsNamespace != "" {
			imageRefNamespace = config.Spec.ArtifactsNamespace
		}
		report.Spec.Containers = r.buildContainerRefs(ctx, imageRefNamespace, pod.Spec)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update workload scan report %s: %w", reportName, err)
	}

	logger.V(1).Info("Reconciled workload scan report",
		"report", reportName,
		"workload", ownerReference.Name,
		"kind", ownerReference.Kind,
		"operation", operation)

	return nil
}

// resolveWorkloadOwner walks up the owner reference chain to find the top-level workload.
// If the pod has no owner, it returns an OwnerReference pointing to the pod itself.
func (r *WorkloadScanReconciler) resolveWorkloadOwner(ctx context.Context, pod *corev1.Pod) (*metav1.OwnerReference, error) {
	ownerReference := metav1.GetControllerOf(pod)

	if ownerReference == nil {
		return &metav1.OwnerReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       pod.Name,
			UID:        pod.UID,
		}, nil
	}

	if ownerReference.Kind == "ReplicaSet" {
		replicaSet := &metav1.PartialObjectMetadata{}
		replicaSet.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))

		if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: ownerReference.Name}, replicaSet); err != nil {
			if apierrors.IsNotFound(err) {
				return ownerReference, nil
			}
			return nil, fmt.Errorf("failed to get ReplicaSet %s/%s: %w", pod.Namespace, ownerReference.Name, err)
		}

		if deploymentReference := metav1.GetControllerOf(replicaSet); deploymentReference != nil && deploymentReference.Kind == "Deployment" {
			return deploymentReference, nil
		}
	}

	return ownerReference, nil
}

// computeWorkloadScanReportName generates a name for a WorkloadScanReport
func computeWorkloadScanReportName(kind, name string) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(kind), name)
}

// buildContainerRefs builds ContainerRef entries with ImageRef from a PodSpec
func (r *WorkloadScanReconciler) buildContainerRefs(ctx context.Context, namespace string, podSpec corev1.PodSpec) []storagev1alpha1.ContainerRef {
	result := make([]storagev1alpha1.ContainerRef, 0, len(podSpec.InitContainers)+len(podSpec.Containers))

	for _, container := range podSpec.InitContainers {
		reference, err := r.parseImageToImageRef(ctx, namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.ContainerRef{
			Name:     container.Name,
			ImageRef: reference,
		})
	}

	for _, container := range podSpec.Containers {
		reference, err := r.parseImageToImageRef(ctx, namespace, container.Image)
		if err != nil {
			continue
		}
		result = append(result, storagev1alpha1.ContainerRef{
			Name:     container.Name,
			ImageRef: reference,
		})
	}

	slices.SortFunc(result, func(a, b storagev1alpha1.ContainerRef) int {
		return strings.Compare(a.Name, b.Name)
	})

	return result
}

// parseImageToImageRef parses an image reference into an ImageRef
func (r *WorkloadScanReconciler) parseImageToImageRef(ctx context.Context, namespace, image string) (storagev1alpha1.ImageRef, error) {
	logger := log.FromContext(ctx)

	if image == "" {
		return storagev1alpha1.ImageRef{}, errors.New("empty image reference")
	}

	reference, err := name.ParseReference(image)
	if err != nil {
		logger.Error(err, "Failed to parse image reference", "image", image)
		return storagev1alpha1.ImageRef{}, fmt.Errorf("failed to parse image %q: %w", image, err)
	}

	return storagev1alpha1.ImageRef{
		Registry:   computeRegistryName(reference.Context().RegistryStr()),
		Namespace:  namespace,
		Repository: reference.Context().RepositoryStr(),
		Tag:        reference.Identifier(),
	}, nil
}
