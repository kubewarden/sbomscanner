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

// SetupNodeScanConfigurationWebhookWithManager registers the webhook for NodeScanConfiguration in the manager.
func SetupNodeScanConfigurationWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.NodeScanConfiguration{}).
		WithValidator(&NodeScanConfigurationCustomValidator{
			logger: mgr.GetLogger().WithName("NodeScanConfiguration_validator"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup NodeScanConfiguration webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-nodescanconfiguration,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations,verbs=create;update;delete,versions=v1alpha1,name=vnodescanconfiguration.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type NodeScanConfigurationCustomValidator struct {
	logger logr.Logger
}

var _ admission.Validator[*v1alpha1.NodeScanConfiguration] = &NodeScanConfigurationCustomValidator{}

func (v *NodeScanConfigurationCustomValidator) ValidateCreate(_ context.Context, config *v1alpha1.NodeScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanConfiguration upon creation", "name", config.GetName())

	allErrs := validateNodeScanConfiguration(config)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanConfiguration").GroupKind(),
			config.Name,
			allErrs,
		)
	}

	return nil, nil
}

func (v *NodeScanConfigurationCustomValidator) ValidateUpdate(_ context.Context, _, config *v1alpha1.NodeScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanConfiguration upon update", "name", config.GetName())

	allErrs := validateNodeScanConfiguration(config)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanConfiguration").GroupKind(),
			config.Name,
			allErrs,
		)
	}

	return nil, nil
}

func (v *NodeScanConfigurationCustomValidator) ValidateDelete(_ context.Context, config *v1alpha1.NodeScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanConfiguration upon deletion", "name", config.GetName())

	return admission.Warnings{
		"NodeScanConfiguration deleted. Node scan feature is now disabled",
	}, nil
}

func validateNodeScanConfiguration(config *v1alpha1.NodeScanConfiguration) field.ErrorList {
	var allErrs field.ErrorList

	if err := validateScanInterval(config.Spec.ScanInterval); err != nil {
		allErrs = append(allErrs, err)
	}
	allErrs = append(allErrs, validatePlatforms(config.Spec.Platforms)...)
	allErrs = append(allErrs, validateNodeSelector(config.Spec.NodeSelector)...)

	return allErrs
}

func validateNodeSelector(selector *metav1.LabelSelector) field.ErrorList {
	if selector == nil {
		return nil
	}

	fieldPath := field.NewPath("spec").Child("nodeSelector")
	opts := metav1validation.LabelSelectorValidationOptions{}

	return metav1validation.ValidateLabelSelector(selector, opts, fieldPath)
}
