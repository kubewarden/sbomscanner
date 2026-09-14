package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"
)

func newImageStrategy(typer runtime.ObjectTyper) imageStrategy {
	return imageStrategy{typer, names.SimpleNameGenerator}
}

type imageStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (imageStrategy) NamespaceScoped() bool {
	return true
}

func (imageStrategy) PrepareForCreate(_ context.Context, _ runtime.Object) {
}

func (imageStrategy) PrepareForUpdate(_ context.Context, _, _ runtime.Object) {
}

func (imageStrategy) Validate(_ context.Context, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (imageStrategy) WarningsOnCreate(_ context.Context, _ runtime.Object) []string {
	return nil
}

func (imageStrategy) AllowCreateOnUpdate(_ context.Context) bool {
	return false
}

func (imageStrategy) AllowUnconditionalUpdate(_ context.Context) bool {
	return false
}

func (imageStrategy) Canonicalize(_ runtime.Object) {
}

func (imageStrategy) ValidateUpdate(_ context.Context, _, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (imageStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}
