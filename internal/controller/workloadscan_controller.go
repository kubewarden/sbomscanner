package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/messaging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	workloadScanRegistry = "workload-scan-registry"
)

// WorkloadScanReconciler reconciles a ScanJob object
type WorkloadScanReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Publisher messaging.Publisher
}

// Reconcile reconciles a ScanJob object.
func (r *WorkloadScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling WorkloadScan")

	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Pod not found, skipping reconciliation", "pod", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get ScanJob: %w", err)
	}

	// Pod is being deleted, so we remove its entry from Registry resource.
	if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
		for _, container := range pod.Spec.Containers {
			repositoryName := pod.Name
			imageTag := strings.Split(container.Image, ":")[1]
			registryURL := strings.Split(container.Image, "/")[0]
			log.Info("Deleting repository entry from Registry resoruce", "pod", pod.Name, "image", container.Image, "tag", imageTag)
			err := r.deleteRegistryEntry(ctx, req.Namespace, registryURL, repositoryName, pod.Name, imageTag)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	for _, container := range pod.Spec.Containers {
		repositoryName := pod.Name
		imageTag := strings.Split(container.Image, ":")[1]
		registryURL := strings.Split(container.Image, "/")[0]
		log.Info("Adding repository entry to Registry resoruce", "pod", pod.Name, "image", container.Image, "tag", imageTag)
		err := r.addRegistryEntry(ctx, req.Namespace, registryURL, repositoryName, pod.Name, imageTag)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *WorkloadScanReconciler) deleteRegistryEntry(ctx context.Context, namespace, registryURL, repositoryName, podName, imageTag string) error {
	registry := v1alpha1.Registry{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      workloadScanRegistry + "-" + registryURL,
	}, &registry); err != nil {
		if errors.IsNotFound(err) {
			// if registry did not exist, returns no error.
			return nil
		}
		return err
	}
	// Registry exists, so remove repository entry.
	repoFound := false
	var repoID int
	for id, repo := range registry.Spec.Repositories {
		if repo.Name == repositoryName {
			repoFound = true
			repoID = id
			break
		}
	}
	// repository exists, remove it.
	if repoFound {
		tagFound := false
		var tagID int
		for id, mc := range registry.Spec.Repositories[repoID].MatchConditions {
			if mc.Name == podName {
				tagFound = true
				tagID = id
				break
			}
		}
		// tag exists, remove it.
		if tagFound {
			original := registry.DeepCopy()
			registry.Spec.Repositories[repoID].MatchConditions = slices.Delete(registry.Spec.Repositories[repoID].MatchConditions, tagID, tagID+1)
			if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
				return fmt.Errorf("failed to remove tag from Registry: %w", err)
			}
			return nil
		}
		original := registry.DeepCopy()
		registry.Spec.Repositories = slices.Delete(registry.Spec.Repositories, repoID, repoID+1)
		if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
			return fmt.Errorf("failed to remove repository from Registry: %w", err)
		}
		return nil
	}
	return nil
}

func (r *WorkloadScanReconciler) addRegistryEntry(ctx context.Context, namespace, registryURL, repositoryName, podName, imageTag string) error {
	registry := v1alpha1.Registry{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      workloadScanRegistry + "-" + registryURL,
	}, &registry); err != nil {
		if errors.IsNotFound(err) {
			// create a new Registry resource.
			registry.Name = workloadScanRegistry
			registry.Namespace = namespace
			registry.Spec.URI = registryURL
			registry.Spec.Repositories = []v1alpha1.Repository{
				{
					Name: repositoryName,
					MatchConditions: []v1alpha1.MatchCondition{
						{
							Name:       podName,
							Expression: fmt.Sprintf("tag == '%s'", imageTag),
						},
					},
				},
			}
			if err := r.Create(ctx, &registry, &client.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create Registry for WorkloadScan: %w", err)
			}
			return nil
		}
		// Registry exists, so add new repository entry.
		found := false
		var repoID int
		for id, repo := range registry.Spec.Repositories {
			if repo.Name == repositoryName {
				found = true
				repoID = id
				break
			}
		}
		// repository does not exists, add new one.
		if !found {
			original := registry.DeepCopy()
			newRepositoryEntry := v1alpha1.Repository{
				Name: repositoryName,
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       podName,
						Expression: fmt.Sprintf("tag == '%s'", imageTag),
					},
				},
			}
			registry.Spec.Repositories = append(registry.Spec.Repositories, newRepositoryEntry)
			if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
				return fmt.Errorf("failed to add repository to Registry: %w", err)
			}
			return nil
		}
		// tag does not exists, add new one.
		original := registry.DeepCopy()
		newTagEntry := v1alpha1.MatchCondition{
			Name:       podName,
			Expression: fmt.Sprintf("tag == '%s'", imageTag),
		}
		conditions := registry.Spec.Repositories[repoID].MatchConditions
		conditions = append(conditions, newTagEntry)
		registry.Spec.Repositories[repoID].MatchConditions = conditions
		if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
			return fmt.Errorf("failed to add tag to Registry: %w", err)
		}
		return nil
	}
	return nil
}
