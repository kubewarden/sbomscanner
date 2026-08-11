package oci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDataLayerMediaType(t *testing.T) {
	assert.Equal(t, "application/vnd.sbomscanner.db.kev.v1.json+gzip", DataLayerMediaType("kev", "json"))
	assert.Equal(t, "application/vnd.sbomscanner.db.epss.v1.csv+gzip", DataLayerMediaType("epss", "csv"))
}

func TestIsDataLayerMediaType(t *testing.T) {
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("gtfobins", "json")))
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("kev", "json")))
	assert.True(t, isDataLayerMediaType(DataLayerMediaType("epss", "csv")))

	assert.False(t, isDataLayerMediaType(ArtifactType))
	assert.False(t, isDataLayerMediaType("application/vnd.oci.image.layer.v1.tar+gzip"))
	assert.False(t, isDataLayerMediaType(""))
}
