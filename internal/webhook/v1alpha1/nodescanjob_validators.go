package v1alpha1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/filters"
)

// ValidateNodeScanJobAgainstConfig checks that the node targeted by a
// NodeScanJob exists and matches the singleton NodeScanConfiguration.
// It returns field-level errors suitable for both webhook rejection and
// controller failure reporting.
func ValidateNodeScanJobAgainstConfig(ctx context.Context, c client.Reader, nodeName string) field.ErrorList {
	var allErrs field.ErrorList
	nodeNameField := field.NewPath("spec").Child("nodeName")

	var config v1alpha1.NodeScanConfiguration
	if err := c.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			allErrs = append(allErrs, field.Forbidden(nodeNameField,
				"NodeScanConfiguration not found: node scanning is not configured"))
			return allErrs
		}
		allErrs = append(allErrs, field.InternalError(nodeNameField,
			fmt.Errorf("fetching NodeScanConfiguration: %w", err)))
		return allErrs
	}

	var node corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			allErrs = append(allErrs, field.NotFound(nodeNameField, nodeName))
			return allErrs
		}
		allErrs = append(allErrs, field.InternalError(nodeNameField,
			fmt.Errorf("fetching Node %q: %w", nodeName, err)))
		return allErrs
	}

	if config.Spec.NodeSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			allErrs = append(allErrs, field.InternalError(nodeNameField,
				fmt.Errorf("parsing NodeSelector: %w", err)))
			return allErrs
		}
		if !selector.Matches(labels.Set(node.Labels)) {
			allErrs = append(allErrs, field.Forbidden(nodeNameField,
				fmt.Sprintf("node %q does not match the NodeScanConfiguration nodeSelector", nodeName)))
		}
	}

	if !filters.IsPlatformAllowed(
		node.Status.NodeInfo.OperatingSystem,
		node.Status.NodeInfo.Architecture,
		"",
		config.Spec.Platforms,
	) {
		allErrs = append(allErrs, field.Forbidden(nodeNameField,
			fmt.Sprintf("node %q platform %s/%s is not allowed by the NodeScanConfiguration",
				nodeName, node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture)))
	}

	return allErrs
}
