package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// RegistryReconciler reconciles a Registry object
type RegistryReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=registries,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=registries/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=registries/finalizers,verbs=update
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=images,verbs=get;list;watch;delete

// Reconcile reconciles a Registry.
// If the Registry has repositories specified, it deletes all images that are not in the current list of repositories.
func (r *RegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var registry v1alpha1.Registry
	if err := r.Get(ctx, req.NamespacedName, &registry); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("unable to fetch Registry: %w", err)
		}

		return ctrl.Result{}, nil
	}

	if !registry.DeletionTimestamp.IsZero() {
		log.V(1).Info("ScanJob is being deleted, skipping reconciliation", "scanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	return r.reconcileRegistry(ctx, &registry)
}

func (r *RegistryReconciler) reconcileRegistry(ctx context.Context, registry *v1alpha1.Registry) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if len(registry.Spec.Repositories) == 0 {
		return ctrl.Result{}, nil
	}

	log.V(1).
		Info("Deleting Images that are not in the current list of repositories", "name", registry.Name, "namespace", registry.Namespace, "repositories", registry.Spec.Repositories)

	images := &storagev1alpha1.ImageList{}
	listOpts := []client.ListOption{
		client.InNamespace(registry.Namespace),
		client.MatchingFields{
			storagev1alpha1.IndexImageMetadataRegistry: registry.Name,
		},
	}
	if err := r.List(ctx, images, listOpts...); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to list Images: %w", err)
	}

	var repositories []string
	for _, repo := range registry.Spec.Repositories {
		repositories = append(repositories, repo.Name)
	}
	allowedRepositories := sets.NewString(repositories...)

	for _, image := range images.Items {
		if allowedRepositories.Has(image.GetImageMetadata().Repository) {
			continue
		}

		if err := r.Delete(ctx, &image); err != nil {
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("unable to delete Image %s: %w", image.Name, err)
			}
		}

		log.V(1).Info("Deleted Image", "name", image.Name, "repository", image.GetImageMetadata().Repository)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RegistryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Registry{}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create Registry controller: %w", err)
	}

	return nil
}
