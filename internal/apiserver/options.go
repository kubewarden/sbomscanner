package apiserver

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/generic"
)

type RestOptionsGetter struct{}

// GetRESTOptions implements the generic.RESTOptionsGetter interface to ensure the GarbageCollection is enabled.
// ResourcePrefix is set to "/<group>/<resource>", compatible with the storage Key format: /storage.sbomscanner.kubewarden.io/<resource>/<namespace>/<name>.
func (o *RestOptionsGetter) GetRESTOptions(
	resource schema.GroupResource,
	_ runtime.Object,
) (generic.RESTOptions, error) {
	return generic.RESTOptions{
		EnableGarbageCollection: true,
		DeleteCollectionWorkers: 1,
		ResourcePrefix:          fmt.Sprintf("/%s/%s", resource.Group, resource.Resource),
	}, nil
}
