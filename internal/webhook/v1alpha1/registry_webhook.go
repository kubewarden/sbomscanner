package v1alpha1

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

const (
	defaultCatalogType = v1alpha1.CatalogTypeOCIDistribution
)

var availableCatalogTypes = []string{v1alpha1.CatalogTypeNoCatalog, v1alpha1.CatalogTypeOCIDistribution}

// SetupRegistryWebhookWithManager registers the webhook for Registry in the manager.
func SetupRegistryWebhookWithManager(mgr ctrl.Manager, serviceAccountNamespace, serviceAccountName string) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.Registry{}).
		WithValidator(&RegistryCustomValidator{
			serviceAccountNamespace: serviceAccountNamespace,
			serviceAccountName:      serviceAccountName,
			logger:                  mgr.GetLogger().WithName("registry_validator"),
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

var _ admission.Defaulter[*v1alpha1.Registry] = &RegistryCustomDefaulter{}

// Default implements admission.Defaulter.
func (d *RegistryCustomDefaulter) Default(_ context.Context, registry *v1alpha1.Registry) error {
	d.logger.Info("Defaulting Registry", "name", registry.GetName())

	if registry.Spec.CatalogType == "" {
		registry.Spec.CatalogType = defaultCatalogType
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-registry,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=registries,verbs=create;update;delete,versions=v1alpha1,name=vregistry.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type RegistryCustomValidator struct {
	serviceAccountNamespace string
	serviceAccountName      string
	logger                  logr.Logger
}

var _ admission.Validator[*v1alpha1.Registry] = &RegistryCustomValidator{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateCreate(ctx context.Context, registry *v1alpha1.Registry) (admission.Warnings, error) {
	v.logger.Info("Validation for Registry upon creation", "name", registry.GetName())

	if err := v.validatedManagedRegistry(ctx, registry); err != nil {
		return nil, err
	}

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

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateUpdate(ctx context.Context, oldRegistry, registry *v1alpha1.Registry) (admission.Warnings, error) {
	v.logger.Info("Validation for Registry upon update", "name", registry.GetName())

	if err := v.validatedManagedRegistry(ctx, oldRegistry); err != nil {
		return nil, err
	}

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

// ValidateDelete implements admission.Validator so a webhook will be registered for the type Registry.
func (v *RegistryCustomValidator) ValidateDelete(ctx context.Context, registry *v1alpha1.Registry) (admission.Warnings, error) {
	v.logger.Info("Validation for Registry upon deletion", "name", registry.GetName())

	if err := v.validatedManagedRegistry(ctx, registry); err != nil {
		return nil, err
	}

	return nil, nil
}

// validatedManagedRegistry ensures that only the designated service account can modify managed Registry resources.
func (v *RegistryCustomValidator) validatedManagedRegistry(ctx context.Context, registry *v1alpha1.Registry) error {
	managedLabel := registry.GetLabels()[api.LabelManagedByKey]
	if managedLabel != api.LabelManagedByValue {
		return nil
	}

	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return apierrors.NewInternalError(errors.New("unable to retrieve admission request from context"))
	}

	allowedUsername := fmt.Sprintf("system:serviceaccount:%s:%s", v.serviceAccountNamespace, v.serviceAccountName)
	if request.UserInfo.Username != allowedUsername {
		return apierrors.NewForbidden(
			v1alpha1.GroupVersion.WithResource("registries").GroupResource(),
			registry.Name,
			errors.New("only the designated service account can modify managed Registry resources"),
		)
	}

	return nil
}

func validateRegistry(registry *v1alpha1.Registry) field.ErrorList {
	var allErrs field.ErrorList

	if err := validateScanInterval(registry.Spec.ScanInterval); err != nil {
		allErrs = append(allErrs, err)
	}
	if err := validateCatalogType(registry.Spec.CatalogType); err != nil {
		allErrs = append(allErrs, err)
	}
	allErrs = append(allErrs, validateRepositories(registry.Spec.Repositories, registry.Spec.CatalogType)...)
	allErrs = append(allErrs, validatePlatforms(registry.Spec.Platforms)...)

	return allErrs
}
