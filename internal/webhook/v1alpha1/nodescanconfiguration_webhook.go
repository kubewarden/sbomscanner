package v1alpha1

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// missingDefaultSkipPatternsWarning builds the admission warning emitted when a
// user-supplied skipPatterns list drops one or more of the default patterns.
// The default list is rendered from v1alpha1.DefaultSkipPatterns so the message
// can never drift out of sync with the actual defaults.
func missingDefaultSkipPatternsWarning() string {
	return fmt.Sprintf(
		"spec.skipPatterns does not include all of the default skip patterns. "+
			"The defaults exclude container-runtime state directories; scanning those paths may cause the node scan to fail. "+
			"Default skip patterns: %s.",
		strings.Join(v1alpha1.DefaultSkipPatterns, ", "),
	)
}

func validateNodeScanConfiguration(config *v1alpha1.NodeScanConfiguration) (admission.Warnings, field.ErrorList) {
	var warnings admission.Warnings
	var allErrs field.ErrorList

	if config.Spec.SkipPatterns != nil {
		warnings = append(warnings, validateNodeScanSkipPatterns(*config.Spec.SkipPatterns)...)
	}

	if err := validateScanInterval(config.Spec.ScanInterval); err != nil {
		allErrs = append(allErrs, err)
	}
	allErrs = append(allErrs, validatePlatforms(config.Spec.Platforms)...)
	allErrs = append(allErrs, validateNodeSelector(config.Spec.NodeSelector)...)

	return warnings, allErrs
}

func validateNodeSelector(selector *metav1.LabelSelector) field.ErrorList {
	if selector == nil {
		return nil
	}

	fieldPath := field.NewPath("spec").Child("nodeSelector")
	opts := metav1validation.LabelSelectorValidationOptions{}

	return metav1validation.ValidateLabelSelector(selector, opts, fieldPath)
}

// validateNodeScanSkipPatterns returns a warning when the user-supplied skipPatterns
// list drops one or more of the default patterns, since removing the
// container-runtime paths can make the node scan fail while walking a running
// container's directory tree.
func validateNodeScanSkipPatterns(skipPatterns []string) admission.Warnings {
	if sets.New(skipPatterns...).HasAll(v1alpha1.DefaultSkipPatterns...) {
		return nil
	}
	return admission.Warnings{missingDefaultSkipPatternsWarning()}
}

// SetupNodeScanConfigurationWebhookWithManager registers the webhook for NodeScanConfiguration in the manager.
func SetupNodeScanConfigurationWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.NodeScanConfiguration{}).
		WithValidator(&NodeScanConfigurationCustomValidator{
			logger: mgr.GetLogger().WithName("NodeScanConfiguration_validator"),
		}).
		WithDefaulter(&NodeScanConfigurationCustomDefaulter{
			logger: mgr.GetLogger().WithName("NodeScanConfiguration_defaulter"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup NodeScanConfiguration webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/mutate-sbomscanner-kubewarden-io-v1alpha1-nodescanconfiguration,mutating=true,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations,verbs=create;update,versions=v1alpha1,name=mnodescanconfiguration.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type NodeScanConfigurationCustomDefaulter struct {
	logger logr.Logger
}

var _ admission.Defaulter[*v1alpha1.NodeScanConfiguration] = &NodeScanConfigurationCustomDefaulter{}

// Default implements admission.Defaulter. When skipPatterns is unset (nil) it is
// filled with v1alpha1.DefaultSkipPatterns. An explicitly empty list ([]) is
// left untouched, so users can opt into scanning every path.
func (d *NodeScanConfigurationCustomDefaulter) Default(_ context.Context, config *v1alpha1.NodeScanConfiguration) error {
	d.logger.Info("Defaulting NodeScanConfiguration", "name", config.GetName())

	if config.Spec.SkipPatterns == nil {
		patterns := slices.Clone(v1alpha1.DefaultSkipPatterns)
		config.Spec.SkipPatterns = &patterns
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

	warnings, allErrs := validateNodeScanConfiguration(config)

	if len(allErrs) > 0 {
		return warnings, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanConfiguration").GroupKind(),
			config.Name,
			allErrs,
		)
	}

	return warnings, nil
}

func (v *NodeScanConfigurationCustomValidator) ValidateUpdate(_ context.Context, _, config *v1alpha1.NodeScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanConfiguration upon update", "name", config.GetName())

	warnings, allErrs := validateNodeScanConfiguration(config)

	if len(allErrs) > 0 {
		return warnings, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanConfiguration").GroupKind(),
			config.Name,
			allErrs,
		)
	}

	return warnings, nil
}

func (v *NodeScanConfigurationCustomValidator) ValidateDelete(_ context.Context, config *v1alpha1.NodeScanConfiguration) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanConfiguration upon deletion", "name", config.GetName())

	return admission.Warnings{
		"NodeScanConfiguration deleted. Node scan feature is now disabled",
	}, nil
}
