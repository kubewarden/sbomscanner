package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const namespacePrefix = "namespace/"

// repositoryTags maps repository names to their set of tags
type repositoryTags map[string]sets.Set[string]

// matchConditionKey identifies a match condition within a repository
type matchConditionKey struct {
	repository string
	name       string
	expression string
}

// reconcileRegistries creates, updates, or deletes Registry resources based on the discovered images.
func (r *WorkloadScanReconciler) reconcileRegistries(ctx context.Context, workloadNamespace string, pods []corev1.Pod, config *v1alpha1.WorkloadScanConfiguration) error {
	logger := log.FromContext(ctx)

	registryNamespace := workloadNamespace
	if config.Spec.ArtifactsNamespace != "" {
		logger.V(1).Info("Using artifacts namespace from configuration", "namespace", config.Spec.ArtifactsNamespace)
		registryNamespace = config.Spec.ArtifactsNamespace
	}

	images := sets.New[string]()
	for _, pod := range pods {
		images.Insert(extractImagesFromPodSpec(pod.Spec)...)
	}
	registriesByURI := r.groupImagesByRegistry(ctx, images)

	var existingRegistries v1alpha1.RegistryList
	if err := r.List(ctx, &existingRegistries,
		client.InNamespace(registryNamespace),
		client.MatchingLabels{
			api.LabelManagedByKey:    api.LabelManagedByValue,
			api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list registries: %w", err)
	}

	processedURIs := sets.New[string]()

	for i := range existingRegistries.Items {
		registry := &existingRegistries.Items[i]
		uri := registry.Spec.URI
		processedURIs.Insert(uri)

		repositories := registriesByURI[uri] // may be nil if this namespace no longer uses this registry

		shouldDelete, err := r.updateRegistry(ctx, registry, workloadNamespace, repositories, config)
		if err != nil {
			return err
		}

		if shouldDelete {
			logger.Info("Deleting registry with no repositories", "registry", registry.Name)
			if err := r.Delete(ctx, registry); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete registry %s: %w", registry.Name, err)
			}
		}
	}

	for uri, repositories := range registriesByURI {
		if processedURIs.Has(uri) {
			continue
		}

		if err := r.createRegistry(ctx, uri, workloadNamespace, registryNamespace, repositories, config); err != nil {
			return err
		}
	}

	logger.V(1).Info("Reconciled registries", "count", len(registriesByURI))

	return nil
}

// updateRegistry updates a registry with this namespace's contributions.
// Returns true if the registry should be deleted (no repositories remain).
func (r *WorkloadScanReconciler) updateRegistry(
	ctx context.Context,
	registry *v1alpha1.Registry,
	sourceNamespace string,
	repositories repositoryTags,
	config *v1alpha1.WorkloadScanConfiguration,
) (bool, error) {
	logger := log.FromContext(ctx)

	neededConditions := buildNeededConditions(repositories)
	oldConditions := extractConditionsFromRegistry(registry)

	processedRepositories, processedConditions := r.processExistingRepositories(registry, sourceNamespace, neededConditions)

	// Add conditions that are needed but weren't in existing repositories
	newConditions := neededConditions.Difference(processedConditions)
	updatedRepositories := addNewConditions(processedRepositories, newConditions, sourceNamespace)

	if len(updatedRepositories) == 0 {
		return true, nil
	}

	sortRepositories(updatedRepositories)

	registry.Spec.Repositories = updatedRepositories
	registry.Spec.AuthSecret = config.Spec.AuthSecret
	registry.Spec.CABundle = config.Spec.CABundle
	registry.Spec.Insecure = config.Spec.Insecure
	registry.Spec.ScanInterval = config.Spec.ScanInterval
	registry.Spec.Platforms = config.Spec.Platforms

	currentConditions := extractConditionsFromRegistry(registry)
	hasNewConditions := currentConditions.Difference(oldConditions).Len() > 0

	if config.Spec.ScanOnChange && hasNewConditions {
		if registry.Annotations == nil {
			registry.Annotations = make(map[string]string)
		}
		registry.Annotations[v1alpha1.AnnotationRescanRequestedKey] = time.Now().UTC().Format(time.RFC3339)
		logger.V(1).Info("Conditions changed, marking registry for rescan", "registry", registry.Name)
	}

	if err := r.Update(ctx, registry); err != nil {
		return false, fmt.Errorf("failed to update registry %s: %w", registry.Name, err)
	}

	logger.V(1).Info("Updated registry",
		"registry", registry.Name,
		"sourceNamespace", sourceNamespace,
		"repositories", len(updatedRepositories))

	return false, nil
}

// buildNeededConditions builds the set of conditions this namespace needs from the repositories.
func buildNeededConditions(repositories repositoryTags) sets.Set[matchConditionKey] {
	neededConditions := sets.New[matchConditionKey]()
	for repositoryName, tags := range repositories {
		for tag := range tags {
			neededConditions.Insert(matchConditionKey{
				repository: repositoryName,
				name:       fmt.Sprintf("tag-%s", tag),
				expression: fmt.Sprintf("tag == %q", tag),
			})
		}
	}
	return neededConditions
}

// extractConditionsFromRegistry extracts all conditions from a registry as a set.
func extractConditionsFromRegistry(registry *v1alpha1.Registry) sets.Set[matchConditionKey] {
	conditions := sets.New[matchConditionKey]()
	for _, repository := range registry.Spec.Repositories {
		for _, condition := range repository.MatchConditions {
			conditions.Insert(matchConditionKey{
				repository: repository.Name,
				name:       condition.Name,
				expression: condition.Expression,
			})
		}
	}
	return conditions
}

// processExistingRepositories processes existing repositories and updates condition labels.
// Returns the processed repositories and the set of conditions that were found in existing repositories.
func (r *WorkloadScanReconciler) processExistingRepositories(
	registry *v1alpha1.Registry,
	sourceNamespace string,
	neededConditions sets.Set[matchConditionKey],
) ([]v1alpha1.Repository, sets.Set[matchConditionKey]) {
	var processedRepositories []v1alpha1.Repository
	processedConditions := sets.New[matchConditionKey]()

	for _, repository := range registry.Spec.Repositories {
		conditions, processed := processRepositoryConditions(repository, sourceNamespace, neededConditions)
		processedConditions = processedConditions.Union(processed)

		if len(conditions) > 0 {
			processedRepositories = append(processedRepositories, v1alpha1.Repository{
				Name:            repository.Name,
				MatchConditions: conditions,
				MatchOperator:   v1alpha1.MatchOperatorOr,
			})
		}
	}

	return processedRepositories, processedConditions
}

// processRepositoryConditions processes conditions for a single repository.
// Returns the conditions to keep and the set of conditions that matched neededConditions.
func processRepositoryConditions(
	repository v1alpha1.Repository,
	sourceNamespace string,
	neededConditions sets.Set[matchConditionKey],
) ([]v1alpha1.MatchCondition, sets.Set[matchConditionKey]) {
	var conditionsToKeep []v1alpha1.MatchCondition
	matchedConditions := sets.New[matchConditionKey]()

	for _, condition := range repository.MatchConditions {
		key := matchConditionKey{
			repository: repository.Name,
			name:       condition.Name,
			expression: condition.Expression,
		}

		if condition.Labels == nil {
			condition.Labels = make(map[string]string)
		}

		nsLabel := namespacePrefix + sourceNamespace
		if neededConditions.Has(key) {
			condition.Labels[nsLabel] = "true"
			matchedConditions.Insert(key)
		} else {
			delete(condition.Labels, nsLabel)
		}

		if len(condition.Labels) > 0 {
			conditionsToKeep = append(conditionsToKeep, condition)
		}
	}

	return conditionsToKeep, matchedConditions
}

// addNewConditions adds new conditions to the repositories.
func addNewConditions(
	repositories []v1alpha1.Repository,
	conditions sets.Set[matchConditionKey],
	sourceNamespace string,
) []v1alpha1.Repository {
	for key := range conditions {
		repository := findOrAppendRepository(&repositories, key.repository)
		repository.MatchConditions = append(repository.MatchConditions, v1alpha1.MatchCondition{
			Name:       key.name,
			Expression: key.expression,
			Labels: map[string]string{
				namespacePrefix + sourceNamespace: "true",
			},
		})
	}
	return repositories
}

// createRegistry creates a new registry with this namespace's contributions.
func (r *WorkloadScanReconciler) createRegistry(
	ctx context.Context,
	uri, sourceNamespace, registryNamespace string,
	repositories repositoryTags,
	config *v1alpha1.WorkloadScanConfiguration,
) error {
	logger := log.FromContext(ctx)
	registryName := computeRegistryName(uri)

	// Build repositories with conditions
	var registryRepositories []v1alpha1.Repository
	for repositoryName, tags := range repositories {
		var conditions []v1alpha1.MatchCondition
		for tag := range tags {
			conditions = append(conditions, v1alpha1.MatchCondition{
				Name:       fmt.Sprintf("tag-%s", tag),
				Expression: fmt.Sprintf("tag == %q", tag),
				Labels: map[string]string{
					namespacePrefix + sourceNamespace: "true",
				},
			})
		}
		registryRepositories = append(registryRepositories, v1alpha1.Repository{
			Name:            repositoryName,
			MatchConditions: conditions,
			MatchOperator:   v1alpha1.MatchOperatorOr,
		})
	}

	sortRepositories(registryRepositories)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      registryName,
			Namespace: registryNamespace,
			Labels: map[string]string{
				api.LabelManagedByKey:    api.LabelManagedByValue,
				api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
			},
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          uri,
			Repositories: registryRepositories,
			AuthSecret:   config.Spec.AuthSecret,
			CABundle:     config.Spec.CABundle,
			Insecure:     config.Spec.Insecure,
			ScanInterval: config.Spec.ScanInterval,
			Platforms:    config.Spec.Platforms,
		},
	}

	// Set rescan annotation on creation if ScanOnChange is enabled
	if config.Spec.ScanOnChange {
		registry.Annotations = map[string]string{
			v1alpha1.AnnotationRescanRequestedKey: time.Now().UTC().Format(time.RFC3339),
		}
	}

	if err := r.Create(ctx, registry); err != nil {
		return fmt.Errorf("failed to create registry %s: %w", registryName, err)
	}

	logger.V(1).Info("Created registry",
		"registry", registryName,
		"sourceNamespace", sourceNamespace,
		"repositories", len(repositories))

	return nil
}

func findOrAppendRepository(repositories *[]v1alpha1.Repository, name string) *v1alpha1.Repository {
	for i := range *repositories {
		if (*repositories)[i].Name == name {
			return &(*repositories)[i]
		}
	}
	*repositories = append(*repositories, v1alpha1.Repository{
		Name:          name,
		MatchOperator: v1alpha1.MatchOperatorOr,
	})
	return &(*repositories)[len(*repositories)-1]
}

func sortRepositories(repositories []v1alpha1.Repository) {
	slices.SortFunc(repositories, func(a, b v1alpha1.Repository) int {
		return strings.Compare(a.Name, b.Name)
	})
	for i := range repositories {
		slices.SortFunc(repositories[i].MatchConditions, func(a, b v1alpha1.MatchCondition) int {
			return strings.Compare(a.Name, b.Name)
		})
	}
}

// computeRegistryName converts a registry URI to a valid Kubernetes resource name by hashing it with SHA-256.
func computeRegistryName(uri string) string {
	sha := sha256.New()
	fmt.Fprint(sha, uri)
	return "workloadscan-" + hex.EncodeToString(sha.Sum(nil))
}

// groupImagesByRegistry parses images and groups them by registry uri -> repository -> tags
func (r *WorkloadScanReconciler) groupImagesByRegistry(ctx context.Context, images sets.Set[string]) map[string]repositoryTags {
	logger := log.FromContext(ctx)
	result := make(map[string]repositoryTags)

	for image := range images {
		if image == "" {
			continue
		}

		reference, err := name.ParseReference(image)
		if err != nil {
			logger.V(1).Info("Failed to parse image reference, skipping", "image", image, "error", err)
			continue
		}

		uri := reference.Context().RegistryStr()
		repository := reference.Context().RepositoryStr()
		tag := reference.Identifier()

		if result[uri] == nil {
			result[uri] = make(repositoryTags)
		}
		if result[uri][repository] == nil {
			result[uri][repository] = sets.New[string]()
		}
		result[uri][repository].Insert(tag)
	}

	return result
}
