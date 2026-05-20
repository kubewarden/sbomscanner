package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"
)

// newNodeSBOMStrategy creates and returns a nodeSBOMStrategy instance
func newNodeSBOMStrategy(typer runtime.ObjectTyper) nodeSBOMStrategy {
	return nodeSBOMStrategy{typer, names.SimpleNameGenerator}
}

type nodeSBOMStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (nodeSBOMStrategy) NamespaceScoped() bool {
	return false
}

func (nodeSBOMStrategy) PrepareForCreate(_ context.Context, _ runtime.Object) {
}

func (nodeSBOMStrategy) PrepareForUpdate(_ context.Context, _, _ runtime.Object) {
}

func (nodeSBOMStrategy) Validate(_ context.Context, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (nodeSBOMStrategy) WarningsOnCreate(_ context.Context, _ runtime.Object) []string {
	return nil
}

func (nodeSBOMStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (nodeSBOMStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (nodeSBOMStrategy) Canonicalize(_ runtime.Object) {
}

func (nodeSBOMStrategy) ValidateUpdate(_ context.Context, _, _ runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (nodeSBOMStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}
