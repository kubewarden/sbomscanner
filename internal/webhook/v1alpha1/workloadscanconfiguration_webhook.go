package v1alpha1

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// SetupWorkloadScanConfigurationWebhookWithManager registers the webhook for WorkloadScanConfiguration in the manager.
func SetupWorkloadScanConfigurationWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.WorkloadScanConfiguration{}).
		WithValidator(&WorkloadScanConfigurationCustomValidator{
			logger: mgr.GetLogger().WithName("WorkloadScanConfiguration_validator"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup WorkloadScanConfiguration webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-workloadscanconfiguration,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=workloadscanconfigurations,verbs=create;update;delete,versions=v1alpha1,name=vworkloadscanconfiguration.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type WorkloadScanConfigurationCustomValidator struct {
	logger logr.Logger
}

var _ admission.Validator[*v1alpha1.WorkloadScanConfiguration] = &WorkloadScanConfigurationCustomValidator{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type Registry.
func (v *WorkloadScanConfigurationCustomValidator) ValidateCreate(_ context.Context, configuration *v1alpha1.WorkloadScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for WorkloadScanConfiguration upon creation", "name", configuration.GetName())

	allErrs := validateWorkloadScanConfiguration(configuration)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("WorkloadScanConfiguration").GroupKind(),
			configuration.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type Registry.
func (v *WorkloadScanConfigurationCustomValidator) ValidateUpdate(_ context.Context, _, configuration *v1alpha1.WorkloadScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for WorkloadScanConfiguration upon update", "name", configuration.GetName())

	allErrs := validateWorkloadScanConfiguration(configuration)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("WorkloadScanConfiguration").GroupKind(),
			configuration.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type Registry.
func (v *WorkloadScanConfigurationCustomValidator) ValidateDelete(_ context.Context, configuration *v1alpha1.WorkloadScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for WorkloadScanConfiguration upon deletion", "name", configuration.GetName())

	return admission.Warnings{
		"WorkloadScanConfiguration deleted. Workload scan feature is now disabled",
	}, nil
}

func validateWorkloadScanConfiguration(configuration *v1alpha1.WorkloadScanConfiguration) field.ErrorList {
	var allErrs field.ErrorList

	if err := validateScanInterval(configuration.Spec.ScanInterval); err != nil {
		allErrs = append(allErrs, err)
	}
	allErrs = append(allErrs, validatePlatforms(configuration.Spec.Platforms)...)
	allErrs = append(allErrs, validateNamespaceSelector(configuration.Spec.NamespaceSelector)...)

	return allErrs
}

func validateNamespaceSelector(selector *metav1.LabelSelector) field.ErrorList {
	if selector == nil {
		return nil
	}

	fieldPath := field.NewPath("spec").Child("namespaceSelector")
	opts := metav1validation.LabelSelectorValidationOptions{}

	return metav1validation.ValidateLabelSelector(selector, opts, fieldPath)
}
