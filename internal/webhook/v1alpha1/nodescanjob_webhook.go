package v1alpha1

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/webhook"
)

// SetupNodeScanJobWebhookWithManager registers the webhook for NodeScanJob in the manager.
func SetupNodeScanJobWebhookWithManager(mgr ctrl.Manager, instrumentation *webhook.Instrumentation) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.NodeScanJob{}).
		WithValidator(webhook.InstrumentValidator(instrumentation, "NodeScanJob", &NodeScanJobCustomValidator{
			client: mgr.GetClient(),
			logger: mgr.GetLogger().WithName("NodeScanJob_validator"),
		})).
		WithDefaulter(webhook.InstrumentDefaulterWithTraceparent(instrumentation, "NodeScanJob", &NodeScanJobCustomDefaulter{
			logger: mgr.GetLogger().WithName("NodeScanJob_defaulter"),
		})).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup NodeScanJob webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/mutate-sbomscanner-kubewarden-io-v1alpha1-nodescanjob,mutating=true,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=nodescanjobs,verbs=create,versions=v1alpha1,name=mnodescanjob.sbomscanner.kubewarden.io,admissionReviewVersions=v1

// NodeScanJobCustomDefaulter has no defaults to apply:
// it exists to register the mutating webhook that the tracing wrapper uses
// to persist the job traceparent at creation (see webhook.InstrumentDefaulterWithTraceparent).
type NodeScanJobCustomDefaulter struct {
	logger logr.Logger
}

var _ admission.Defaulter[*v1alpha1.NodeScanJob] = &NodeScanJobCustomDefaulter{}

// Default implements admission.Defaulter.
func (d *NodeScanJobCustomDefaulter) Default(_ context.Context, job *v1alpha1.NodeScanJob) error {
	d.logger.Info("Defaulting NodeScanJob", "name", job.GetName())

	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-nodescanjob,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=nodescanjobs,verbs=create;update,versions=v1alpha1,name=vnodescanjob.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type NodeScanJobCustomValidator struct {
	client client.Client
	logger logr.Logger
}

var _ admission.Validator[*v1alpha1.NodeScanJob] = &NodeScanJobCustomValidator{}

func (v *NodeScanJobCustomValidator) ValidateCreate(ctx context.Context, job *v1alpha1.NodeScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanJob upon creation", "name", job.GetName())

	allErrs := ValidateNodeScanJobAgainstConfig(ctx, v.client, job.Spec.NodeName)

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanJob").GroupKind(),
			job.Name,
			allErrs,
		)
	}

	return nil, nil
}

func (v *NodeScanJobCustomValidator) ValidateUpdate(_ context.Context, oldJob, newJob *v1alpha1.NodeScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanJob upon update", "name", newJob.GetName())

	var allErrs field.ErrorList
	if oldJob.Spec.NodeName != newJob.Spec.NodeName {
		fieldPath := field.NewPath("spec").Child("nodeName")
		allErrs = append(allErrs, field.Invalid(fieldPath, newJob.Spec.NodeName, "field is immutable"))
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("NodeScanJob").GroupKind(),
			newJob.Name,
			allErrs,
		)
	}

	return nil, nil
}

func (v *NodeScanJobCustomValidator) ValidateDelete(_ context.Context, job *v1alpha1.NodeScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for NodeScanJob upon deletion", "name", job.GetName())
	return nil, nil
}
