package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"
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

func (workloadScanReportStrategy) Validate(_ context.Context, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
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

func (workloadScanReportStrategy) ValidateUpdate(_ context.Context, _, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (workloadScanReportStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}
