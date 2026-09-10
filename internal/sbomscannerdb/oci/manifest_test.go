package oci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDataLayerMediaType(t *testing.T) {
	assert.Equal(t, "application/vnd.sbomscanner.db.kev.v1.sqlite+tar+gzip", DataLayerMediaType("kev"))
	assert.Equal(t, "application/vnd.sbomscanner.db.epss.v1.sqlite+tar+gzip", DataLayerMediaType("epss"))
}

func TestIsDataLayerMediaType(t *testing.T) {
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("gtfobins")))
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("kev")))
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("epss")))

	assert.False(t, isDataLayerMediaType(ArtifactType))
	assert.False(t, isDataLayerMediaType("application/vnd.oci.image.layer.v1.tar+gzip"))
	assert.False(t, isDataLayerMediaType(""))
}
