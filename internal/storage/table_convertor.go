package storage

import (
	"fmt"

	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// imageMetadataTableColumns returns the common table columns for resources that
// implement the ImageMetadataAccessor interface.
func imageMetadataTableColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Description: "Name"}, //nolint:goconst // table column literals
		{Name: "Reference", Type: "string", Description: "Image reference"},
		{Name: "Platform", Type: "string", Description: "Image platform"},
	}
}

// imageMetadataTableRowCells returns the common table row cells for resources that
// implement the ImageMetadataAccessor interface.
func imageMetadataTableRowCells(name string, obj v1alpha1.ImageMetadataAccessor) []any {
	meta := obj.GetImageMetadata()

	reference := fmt.Sprintf("%s/%s:%s", meta.RegistryURI, meta.Repository, meta.Tag)

	return []any{
		name,
		reference,
		meta.Platform,
	}
}
