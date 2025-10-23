package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/containerd/platforms"
	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

const (
	defaultCatalogType = v1alpha1.CatalogTypeOCIDistribution
)

var availableCatalogTypes = []string{v1alpha1.CatalogTypeNoCatalog, v1alpha1.CatalogTypeOCIDistribution}

// SetupRegistryWebhookWithManager registers the webhook for Registry in the manager.
func SetupRegistryWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).For(&v1alpha1.Registry{}).
		WithValidator(&RegistryCustomValidator{
			logger: mgr.GetLogger().WithName("registry_validator"),
		}).
		WithDefaulter(&RegistryCustomDefaulter{
			logger: mgr.GetLogger().WithName("registry_defaulter"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup Registry webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/mutate-sbomscanner-kubewarden-io-v1alpha1-registry,mutating=true,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=registries,verbs=create;update,versions=v1alpha1,name=mregistry.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type RegistryCustomDefaulter struct {
	logger logr.Logger
}

var _ webhook.CustomDefaulter = &RegistryCustomDefaulter{}

// Default implements admission.CustomDefaulter.
func (d *RegistryCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	registry, ok := obj.(*v1alpha1.Registry)
	if !ok {
		return fmt.Errorf("expected a Registry object but got %T", obj)
	}

	d.logger.Info("Defaulting Registry", "name", registry.GetName())

	if registry.Spec.CatalogType == "" {
		registry.Spec.CatalogType = defaultCatalogType
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-registry,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=registries,verbs=create;update,versions=v1alpha1,name=vregistry.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type RegistryCustomValidator struct {
	logger logr.Logger
}

var _ webhook.CustomValidator = &RegistryCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	registry, ok := obj.(*v1alpha1.Registry)
	if !ok {
		return nil, fmt.Errorf("expected a Registry object but got %T", obj)
	}
	v.logger.Info("Validation for Registry upon creation", "name", registry.GetName())

	allErrs := validateRegistry(registry)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("Registry").GroupKind(),
			registry.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	registry, ok := newObj.(*v1alpha1.Registry)
	if !ok {
		return nil, fmt.Errorf("expected a Registry object for the newObj but got %T", newObj)
	}
	v.logger.Info("Validation for Registry upon update", "name", registry.GetName())

	allErrs := validateRegistry(registry)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("Registry").GroupKind(),
			registry.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	registry, ok := obj.(*v1alpha1.Registry)
	if !ok {
		return nil, fmt.Errorf("expected a Registry object but got %T", obj)
	}
	v.logger.Info("Validation for Registry upon deletion", "name", registry.GetName())

	return nil, nil
}

func validateScanInterval(registry *v1alpha1.Registry) error {
	if registry.Spec.ScanInterval == nil {
		return nil
	}
	if registry.Spec.ScanInterval.Duration < time.Minute {
		return errors.New("scanInterval must be at least 1 minute")
	}

	return nil
}

func validateCatalogType(registry *v1alpha1.Registry) error {
	// If the catalog type is empty, the Defaulter will set it to the default catalog type.
	if registry.Spec.CatalogType == "" {
		return nil
	}
	if !slices.Contains(availableCatalogTypes, registry.Spec.CatalogType) {
		return fmt.Errorf("%s is not a valid CatalogType", registry.Spec.CatalogType)
	}

	return nil
}

func validateRepositories(registry *v1alpha1.Registry) error {
	if registry.Spec.CatalogType == v1alpha1.CatalogTypeNoCatalog && len(registry.Spec.Repositories) == 0 {
		return errors.New("repositories must be explicitly provided when catalogType is NoCatalog")
	}
	return nil
}

func validatePlatforms(registry *v1alpha1.Registry) error {
	if registry.Spec.Platforms == nil {
		return nil
	}
	for _, platform := range registry.Spec.Platforms {
		parsedPlatform, err := platforms.Parse(platform.String())
		if err != nil {
			return fmt.Errorf("%s is not a valid platform format: %w", platform.String(), err)
		}
		matcher := platforms.Only(parsedPlatform)
		isAllowed := slices.ContainsFunc(allowedPlatforms, matcher.Match)

		if !isAllowed {
			return fmt.Errorf("%s is not an allowed platform", platform.String())
		}
	}
	return nil
}

func validateRegistry(registry *v1alpha1.Registry) field.ErrorList {
	var allErrs field.ErrorList

	if err := validateScanInterval(registry); err != nil {
		fieldPath := field.NewPath("spec").Child("scanInterval")
		allErrs = append(allErrs, field.Invalid(fieldPath, registry.Spec.ScanInterval, err.Error()))
	}

	if err := validateCatalogType(registry); err != nil {
		fieldPath := field.NewPath("spec").Child("catalogType")
		allErrs = append(allErrs, field.Invalid(fieldPath, registry.Spec.CatalogType, err.Error()))
	}

	if err := validateRepositories(registry); err != nil {
		fieldPath := field.NewPath("spec").Child("repositories")
		allErrs = append(allErrs, field.Invalid(fieldPath, registry.Spec.Repositories, err.Error()))
	}
	if err := validatePlatforms(registry); err != nil {
		filepath := field.NewPath("spec").Child("platforms")
		allErrs = append(allErrs, field.Invalid(filepath, registry.Spec.Platforms, err.Error()))
	}

	return allErrs
}
