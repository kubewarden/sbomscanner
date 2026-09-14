package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"
)

// newSBOMStrategy creates and returns a sbomStrategy instance
func newSBOMStrategy(typer runtime.ObjectTyper) sbomStrategy {
	return sbomStrategy{typer, names.SimpleNameGenerator}
}

type sbomStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (sbomStrategy) NamespaceScoped() bool {
	return true
}

func (sbomStrategy) PrepareForCreate(_ context.Context, _ runtime.Object) {
}

func (sbomStrategy) PrepareForUpdate(_ context.Context, _, _ runtime.Object) {
}

func (sbomStrategy) Validate(_ context.Context, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (sbomStrategy) WarningsOnCreate(_ context.Context, _ runtime.Object) []string {
	return nil
}

func (sbomStrategy) AllowCreateOnUpdate(_ context.Context) bool {
	return false
}

func (sbomStrategy) AllowUnconditionalUpdate(_ context.Context) bool {
	return false
}

func (sbomStrategy) Canonicalize(_ runtime.Object) {
}

func (sbomStrategy) ValidateUpdate(_ context.Context, _, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (sbomStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}
