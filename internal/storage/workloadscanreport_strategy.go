package storage

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// newWorkloadScanReportStrategy creates and returns a workloadScanReportStrategy instance
func newWorkloadScanReportStrategy(typer runtime.ObjectTyper) workloadScanReportStrategy {
	return workloadScanReportStrategy{typer, names.SimpleNameGenerator}
}

type workloadScanReportStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (workloadScanReportStrategy) NamespaceScoped() bool {
	return true
}

func (workloadScanReportStrategy) PrepareForCreate(_ context.Context, _ runtime.Object) {
}

func (workloadScanReportStrategy) PrepareForUpdate(_ context.Context, _, _ runtime.Object) {
}

func (workloadScanReportStrategy) Validate(_ context.Context, obj runtime.Object) field.ErrorList {
	report, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return field.ErrorList{
			field.InternalError(field.NewPath(""), fmt.Errorf("expected WorkloadScanReport, got %T", obj)),
		}
	}

	return validateReadOnlyFieldsEmpty(report)
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (workloadScanReportStrategy) WarningsOnCreate(_ context.Context, _ runtime.Object) []string {
	return nil
}

func (workloadScanReportStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (workloadScanReportStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (workloadScanReportStrategy) Canonicalize(_ runtime.Object) {
}

func (workloadScanReportStrategy) ValidateUpdate(_ context.Context, obj, old runtime.Object) field.ErrorList {
	newReport, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return field.ErrorList{
			field.InternalError(field.NewPath(""), fmt.Errorf("expected WorkloadScanReport, got %T", obj)),
		}
	}

	oldReport, ok := old.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return field.ErrorList{
			field.InternalError(field.NewPath(""), fmt.Errorf("expected WorkloadScanReport, got %T", old)),
		}
	}

	return validateReadOnlyFieldsUnchanged(newReport, oldReport)
}

// WarningsOnUpdate returns warnings for the given update.
func (workloadScanReportStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}

// validateReadOnlyFieldsEmpty validates that status, summary and containers are empty on create.
func validateReadOnlyFieldsEmpty(report *storagev1alpha1.WorkloadScanReport) field.ErrorList {
	var errs field.ErrorList

	if !reflect.DeepEqual(report.Status, storagev1alpha1.WorkloadScanReportStatus{}) {
		errs = append(errs, field.Forbidden(field.NewPath("status"), "field is read-only"))
	}

	if !reflect.DeepEqual(report.Summary, storagev1alpha1.Summary{}) {
		errs = append(errs, field.Forbidden(field.NewPath("summary"), "field is read-only"))
	}

	if len(report.Containers) > 0 {
		errs = append(errs, field.Forbidden(field.NewPath("containers"), "field is read-only"))
	}

	return errs
}

// validateReadOnlyFieldsUnchanged validates that status, summary and containers are not modified on update.
func validateReadOnlyFieldsUnchanged(newReport, oldReport *storagev1alpha1.WorkloadScanReport) field.ErrorList {
	var errs field.ErrorList

	if !reflect.DeepEqual(newReport.Status, oldReport.Status) {
		errs = append(errs, field.Forbidden(field.NewPath("status"), "field is read-only"))
	}

	if !reflect.DeepEqual(newReport.Summary, oldReport.Summary) {
		errs = append(errs, field.Forbidden(field.NewPath("summary"), "field is read-only"))
	}

	if !reflect.DeepEqual(newReport.Containers, oldReport.Containers) {
		errs = append(errs, field.Forbidden(field.NewPath("containers"), "field is read-only"))
	}

	return errs
}
