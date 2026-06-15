package storage

import (
	"errors"
	"fmt"

	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
)

// matcher returns a storage.SelectionPredicate that matches the given label and field selectors
func matcher(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: getAttrs,
	}
}

// getAttrs return labels and fields that can be used in a selection
func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get metadata: %w", err)
	}

	imageMetadataAccessor, ok := obj.(v1alpha1.ImageMetadataAccessor)
	if !ok {
		return nil, nil, errors.New("object does not implement ImageMetadataAccessor")
	}

	selectableMetadata := fields.Set{
		//nolint:goconst // These are user-friendly field names, not constant values used elsewhere
		"metadata.name":      objMeta.GetName(),
		"metadata.namespace": objMeta.GetNamespace(),
	}

	selectableFields := fields.Set{
		"imageMetadata.registry":    imageMetadataAccessor.GetImageMetadata().Registry,
		"imageMetadata.registryURI": imageMetadataAccessor.GetImageMetadata().RegistryURI,
		"imageMetadata.repository":  imageMetadataAccessor.GetImageMetadata().Repository,
		"imageMetadata.tag":         imageMetadataAccessor.GetImageMetadata().Tag,
		"imageMetadata.platform":    imageMetadataAccessor.GetImageMetadata().Platform,
		"imageMetadata.digest":      imageMetadataAccessor.GetImageMetadata().Digest,
	}

	return labels.Set(objMeta.GetLabels()), generic.MergeFieldsSets(selectableMetadata, selectableFields), nil
}
