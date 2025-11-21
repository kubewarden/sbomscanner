package storage

import (
	"context"

	"k8s.io/apiserver/pkg/registry/generic/registry"
)

// RegistryStoreWithWatcher is a wrapper around registry.Store that includes a watcher.
// This is needed to setup the genericserver and start the watchers in the same errgroup.
type RegistryStoreWithWatcher struct {
	store   *registry.Store
	watcher *natsWatcher
}

// GetStore returns the underlying registry.Store.
func (r *RegistryStoreWithWatcher) GetStore() *registry.Store {
	return r.store
}

// StartWatcher starts the watcher associated with this store.
func (r *RegistryStoreWithWatcher) StartWatcher(ctx context.Context) error {
	return r.watcher.Start(ctx)
}
