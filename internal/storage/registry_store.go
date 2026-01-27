package storage

import (
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// RegistryStoreWithWatcher is a wrapper around registry.Store that includes a watcher.
// This is needed to setup the genericserver and start the watchers in the same errgroup.
type RegistryStoreWithWatchers struct {
	Store    *registry.Store
	Watchers []manager.Runnable
}
