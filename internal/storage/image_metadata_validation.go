package storage

import (
	"github.com/google/go-containerregistry/pkg/name"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

const (
	// The image parser accepts 255 repository characters,
	// and RepositoryStr can add the implicit Docker Hub namespace after parsing.
	repositoryMaxLength = 255 + len("library/")

	// Tag also stores digest references. A SHA-512 identifier is 135 bytes,
	// so preserve valid digest identifiers beyond the normal 128-byte tag limit.
	tagMaxLength    = 128
	digestMaxLength = len("sha512:") + 128
)

// validateImageMetadata bounds the fields used by the image-reference indexes.
// It leaves format validation and requirements for empty fields unchanged.
func validateImageMetadata(metadata storagev1alpha1.ImageMetadata) field.ErrorList {
	path := field.NewPath("imageMetadata")
	errs := validateImageRegistry(metadata.Registry, path.Child("registry"))
	errs = append(errs, validateImageRepository(metadata.Repository, path.Child("repository"))...)
	errs = append(errs, validateImageTag(metadata.Tag, path.Child("tag"))...)
	return errs
}

func validateImageRegistry(registry string, path *field.Path) field.ErrorList {
	if len(registry) > validation.DNS1123SubdomainMaxLength {
		return field.ErrorList{field.TooLong(path, registry, validation.DNS1123SubdomainMaxLength)}
	}
	return nil
}

func validateImageRepository(repository string, path *field.Path) field.ErrorList {
	if len(repository) > repositoryMaxLength {
		return field.ErrorList{field.TooLong(path, repository, repositoryMaxLength)}
	}
	return nil
}

func validateImageTag(tag string, path *field.Path) field.ErrorList {
	if len(tag) > tagMaxLength {
		if len(tag) <= digestMaxLength {
			if ref, err := name.NewDigest("example.invalid/image@" + tag); err == nil && ref.DigestStr() == tag {
				return nil
			}
		}
		return field.ErrorList{field.TooLong(path, tag, tagMaxLength)}
	}
	return nil
}
