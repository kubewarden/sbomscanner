package v1alpha1

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func SetupScanJobWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &v1alpha1.ScanJob{}).
		WithValidator(&ScanJobCustomValidator{
			client: mgr.GetClient(),
			logger: mgr.GetLogger().WithName("scanjob_validator"),
		}).
		WithDefaulter(&ScanJobCustomDefaulter{
			logger: mgr.GetLogger().WithName("scanjob_defaulter"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup ScanJob webhook: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/mutate-sbomscanner-kubewarden-io-v1alpha1-scanjob,mutating=true,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=scanjobs,verbs=create;update,versions=v1alpha1,name=mscanjob.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type ScanJobCustomDefaulter struct {
	logger logr.Logger
}

var _ admission.Defaulter[*v1alpha1.ScanJob] = &ScanJobCustomDefaulter{}

// Default mutates the object to set default values.
func (d *ScanJobCustomDefaulter) Default(_ context.Context, scanJob *v1alpha1.ScanJob) error {
	d.logger.Info("Defaulting ScanJob", "name", scanJob.GetName())

	if scanJob.Annotations == nil {
		scanJob.Annotations = make(map[string]string)
	}

	// Add creation timestamp annotation with nanosecond precision
	scanJob.Annotations[v1alpha1.AnnotationScanJobCreationTimestampKey] = time.Now().Format(time.RFC3339Nano)

	return nil
}

// +kubebuilder:webhook:path=/validate-sbomscanner-kubewarden-io-v1alpha1-scanjob,mutating=false,failurePolicy=fail,sideEffects=None,groups=sbomscanner.kubewarden.io,resources=scanjobs,verbs=create;update,versions=v1alpha1,name=vscanjob.sbomscanner.kubewarden.io,admissionReviewVersions=v1

type ScanJobCustomValidator struct {
	client client.Client
	logger logr.Logger
}

var _ admission.Validator[*v1alpha1.ScanJob] = &ScanJobCustomValidator{}

// ValidateCreate validates the object on creation.
func (v *ScanJobCustomValidator) ValidateCreate(ctx context.Context, scanJob *v1alpha1.ScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for ScanJob upon creation", "name", scanJob.GetName())

	var allErrs field.ErrorList

	scanJobList := &v1alpha1.ScanJobList{}

	if err := v.client.List(ctx, scanJobList,
		client.InNamespace(scanJob.GetNamespace()),
		client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: scanJob.Spec.Registry}); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("listing ScanJobs: %w", err))
	}

	for _, existingScanJob := range scanJobList.Items {
		// Check if the a ScanJob with the same registry is already running
		if !existingScanJob.IsComplete() && !existingScanJob.IsFailed() {
			fieldPath := field.NewPath("spec").Child("registry")
			allErrs = append(allErrs, field.Forbidden(fieldPath, fmt.Sprintf("a ScanJob for the registry %q is already running", scanJob.Spec.Registry)))
			break
		}
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("ScanJob").GroupKind(),
			scanJob.Name,
			allErrs,
		)
	}
	return nil, nil
}

// ValidateUpdate validates the object on update.
func (v *ScanJobCustomValidator) ValidateUpdate(_ context.Context, oldJob, newJob *v1alpha1.ScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for ScanJob upon update", "name", newJob.GetName())

	var allErrs field.ErrorList
	if oldJob.Spec.Registry != newJob.Spec.Registry {
		fieldPath := field.NewPath("spec").Child("registry")
		allErrs = append(allErrs, field.Invalid(fieldPath, newJob.Spec.Registry, "field is immutable"))
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			v1alpha1.GroupVersion.WithKind("ScanJob").GroupKind(),
			newJob.Name,
			allErrs,
		)
	}
	return nil, nil
}

// ValidateDelete validates the object on deletion.
func (v *ScanJobCustomValidator) ValidateDelete(_ context.Context, scanJob *v1alpha1.ScanJob) (admission.Warnings, error) {
	v.logger.Info("Validation for ScanJob upon deletion", "name", scanJob.GetName())
	return nil, nil
}
