package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/validation/field"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

func TestValidateImageMetadataFields(t *testing.T) {
	validators := []struct {
		name     string
		validate func(string, *field.Path) field.ErrorList
		maxBytes int
	}{
		{"registry", validateImageRegistry, 253},
		{"repository", validateImageRepository, 263},
		{"tag", validateImageTag, 128},
	}
	for _, v := range validators {
		t.Run(v.name, func(t *testing.T) {
			path := field.NewPath("imageMetadata", v.name)
			tests := []struct {
				name    string
				value   string
				tooLong bool
			}{
				{"empty", "", false},
				{"maximum length", strings.Repeat("a", v.maxBytes), false},
				{"one byte over", strings.Repeat("a", v.maxBytes+1), true},
				{"Unicode within byte limit", strings.Repeat("é", v.maxBytes/2), false},
				{"Unicode over byte limit", strings.Repeat("é", v.maxBytes/2+1), true},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					errs := v.validate(test.value, path)
					if !test.tooLong {
						require.Empty(t, errs)
						return
					}
					require.Len(t, errs, 1)
					assert.Equal(t, field.ErrorTypeTooLong, errs[0].Type)
					assert.Equal(t, path.String(), errs[0].Field)
				})
			}
		})
	}
}

func TestValidateImageTagDigests(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		tooLong bool
	}{
		{"sha256 identifier", "sha256:" + strings.Repeat("a", 64), false},
		{"sha384 identifier", "sha384:" + strings.Repeat("a", 96), false},
		{"sha512 identifier", "sha512:" + strings.Repeat("a", 128), false},
		{"invalid long digest", "sha512:" + strings.Repeat("z", 128), true},
		{"digest too long", "sha512:" + strings.Repeat("a", 129), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errs := validateImageTag(test.tag, field.NewPath("imageMetadata", "tag"))
			if !test.tooLong {
				require.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Equal(t, field.ErrorTypeTooLong, errs[0].Type)
			assert.Equal(t, "imageMetadata.tag", errs[0].Field)
		})
	}
}

func TestValidateImageMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata storagev1alpha1.ImageMetadata
		fields   []string
	}{
		{name: "empty fields remain allowed"},
		{
			name: "maximum lengths with normalized repository",
			metadata: storagev1alpha1.ImageMetadata{
				Registry: strings.Repeat("a", 253), Repository: "library/" + strings.Repeat("a", 255), Tag: strings.Repeat("a", 128),
			},
		},
		{
			name: "all field errors",
			metadata: storagev1alpha1.ImageMetadata{
				Registry: strings.Repeat("a", 254), Repository: strings.Repeat("a", 264), Tag: strings.Repeat("a", 129),
			},
			fields: []string{"imageMetadata.registry", "imageMetadata.repository", "imageMetadata.tag"},
		},
		{
			name: "digest does not hide other errors",
			metadata: storagev1alpha1.ImageMetadata{
				Registry: strings.Repeat("a", 254), Repository: strings.Repeat("a", 264), Tag: "sha512:" + strings.Repeat("a", 128),
			},
			fields: []string{"imageMetadata.registry", "imageMetadata.repository"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := test.metadata
			errs := validateImageMetadata(test.metadata)
			var fields []string
			for _, err := range errs {
				assert.Equal(t, field.ErrorTypeTooLong, err.Type)
				fields = append(fields, err.Field)
			}
			assert.Equal(t, test.fields, fields)
			assert.Equal(t, before, test.metadata, "validation must not change the metadata")
		})
	}
}
