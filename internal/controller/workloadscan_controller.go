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
	workloadScanRegistry = "workloadscan-registry"
)

// WorkloadScanReconciler reconciles a ScanJob object
type WorkloadScanReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Publisher messaging.Publisher
}

// SetupWithManager sets up the controller with the Manager
func (r *WorkloadScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// Reconcile reconciles a ScanJob object.
func (r *WorkloadScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling WorkloadScan")

	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Registry not found", "pod", pod.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get ScanJob: %w", err)
	}

	// Pod is being deleted, so we remove its entry from Registry resource.
	if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
		for _, container := range pod.Spec.Containers {
			repositoryName := extractRepository(container.Image)
			imageTag := strings.Split(container.Image, ":")[1]
			registryURL := strings.Split(container.Image, "/")[0]
			log.Info("Deleting repository entry from Registry resoruce", "pod", pod.Name, "image", container.Image, "tag", imageTag)
			err := r.deleteRegistryEntry(ctx, req.Namespace, registryURL, repositoryName, pod.Name)
			if err != nil {
				log.Error(err, "error deleting entry from Registry")
				return ctrl.Result{}, err
			}
			log.Info("registry entry deleted")
		}
	}

	for _, container := range pod.Spec.Containers {
		repositoryName := extractRepository(container.Image)
		imageTag := strings.Split(container.Image, ":")[1]
		registryURL := strings.Split(container.Image, "/")[0]
		log.Info("Adding repository entry to Registry resoruce", "pod", pod.Name, "image", container.Image, "tag", imageTag)
		err := r.addRegistryEntry(ctx, req.Namespace, registryURL, repositoryName, pod.Name, imageTag)
		if err != nil {
			log.Error(err, "error adding entry to Registry")
			return ctrl.Result{}, err
		}
		log.Info("registry entry created")
	}

	return ctrl.Result{}, nil
}

func (r *WorkloadScanReconciler) deleteRegistryEntry(ctx context.Context, namespace, registryURL, repositoryName, podName string) error {
	log := logf.FromContext(ctx)

	registry := v1alpha1.Registry{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      workloadScanRegistry + "-" + registryURL,
	}, &registry); err != nil {
		if errors.IsNotFound(err) {
			// if registry did not exist, returns no error.
			log.Info("Registry not found", "name", registry.Name, "namespace", registry.Namespace)
			return nil
		}
		return err
	}
	// Registry exists, so remove repository entry.
	log.Info("Registry was found, deleting entry", "name", registry.Name, "namespace", registry.Namespace)
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
		log.Info("repository was found, deleting entry", "repository", repositoryName)
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
			log.Info("tag was found, deleting entry")
			original := registry.DeepCopy()
			registry.Spec.Repositories[repoID].MatchConditions = slices.Delete(registry.Spec.Repositories[repoID].MatchConditions, tagID, tagID+1)
			if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
				log.Error(err, "error removing tag", "name", repositoryName)
				return fmt.Errorf("failed to remove tag from Registry: %w", err)
			}
			return nil
		}
		original := registry.DeepCopy()
		registry.Spec.Repositories = slices.Delete(registry.Spec.Repositories, repoID, repoID+1)
		if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
			log.Error(err, "error removing repository", "name", repositoryName)
			return fmt.Errorf("failed to remove repository from Registry: %w", err)
		}
		return nil
	}
	return nil
}

func (r *WorkloadScanReconciler) addRegistryEntry(ctx context.Context, namespace, registryURL, repositoryName, podName, imageTag string) error {
	log := logf.FromContext(ctx)

	registry := v1alpha1.Registry{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      workloadScanRegistry + "-" + registryURL,
	}, &registry); err != nil {
		if errors.IsNotFound(err) {
			// create a new Registry resource.
			registry.Name = workloadScanRegistry + "-" + registryURL
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
			log.Info("Registry not found, creating it", "name", registry.Name, "namespace", registry.Namespace)
			if err := r.Create(ctx, &registry, &client.CreateOptions{}); err != nil {
				log.Error(err, "error creating Registry", "name", registry.Name, "namespace", registry.Namespace)
				return fmt.Errorf("failed to create Registry for WorkloadScan: %w", err)
			}
			return nil
		}
		return err
	}
	// Registry exists, so add new repository entry.
	log.Info("Registry was found, adding entry", "name", registry.Name, "namespace", registry.Namespace)
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
		log.Info("repository not found, adding entry", "repository", repositoryName)
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
			log.Error(err, "error adding repository", "name", repositoryName)
			return fmt.Errorf("failed to add repository to Registry: %w", err)
		}
		return nil
	}
	// tag does not exists, add new one.
	log.Info("tag not found, adding entry", "tag", imageTag)
	original := registry.DeepCopy()
	newTagEntry := v1alpha1.MatchCondition{
		Name:       podName,
		Expression: fmt.Sprintf("tag == '%s'", imageTag),
	}
	conditions := registry.Spec.Repositories[repoID].MatchConditions
	conditions = append(conditions, newTagEntry)
	registry.Spec.Repositories[repoID].MatchConditions = conditions
	if err := r.Patch(ctx, &registry, client.MergeFrom(original)); err != nil {
		log.Error(err, "error adding tag", "name", imageTag)
		return fmt.Errorf("failed to add tag to Registry: %w", err)
	}
	return nil
}

// extractRepository returns the repository part of an image reference
// without registry and tag.
func extractRepository(image string) string {
	// Remove tag (everything after the last ':', if present)
	if i := strings.LastIndex(image, ":"); i != -1 && !strings.Contains(image[i+1:], "/") {
		image = image[:i]
	}

	// Split by '/' to check for registry
	parts := strings.Split(image, "/")

	// If first part looks like a registry (contains '.' or ':'), skip it
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		return strings.Join(parts[1:], "/")
	}

	// Otherwise, the whole image is already the repository
	return image
}
