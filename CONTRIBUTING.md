# Contributing

## Run tests

```shell
make test
```

## Lint code

```shell
make lint
```

## Run the development environment with Tilt

We use [Tilt](https://tilt.dev/) to run a local development environment.
Customize `tilt-settings.yaml` to your needs.

Run tilt:

```shell
tilt up
```

Run tilt with unified logs:

```shell
tilt up --stream
```

Follow controller logs:

```shell
tilt logs -f controller
```

Follow storage logs:

```shell
tilt logs -f storage
```

Follow worker logs:

```shell
tilt logs -f worker
```

Teardown the environment:

```shell
tilt down
```

### Development registry

Tilt automatically runs a local Docker registry alongside your development components. The registry deployment configuration is defined in [`hack/registry.yaml`](hack/registry.yaml).

**Private Registry Setup**
If you need authentication, set `use_private_registry: true` in your [`tilt-settings.yaml`](tilt-settings.yaml) file. The default credentials are `user:password`, and the deployment manifest is located at [`hack/private-registry.yaml`](hack/private-registry.yaml).

**Using the Registry**

- Registry endpoint: `localhost:5000`
- Tag images with the `localhost:5000/` prefix to push them to this registry
- Check out [`examples/registry.yaml`](examples/registry.yaml) for a sample `Registry` resource configured for this development setup

## Generate code

When you make changes to the CRDs in `/api` or rbac rules annotations, you need to regenerate the code.

```shell
make generate
```

## Writing Tests

**Controller Tests**
Controller tests live in the `controllers` package and use [envtest](https://book.kubebuilder.io/reference/envtest.html) to run against a real API server and etcd instance.
We use [Ginkgo](https://onsi.github.io/ginkgo/) and [Gomega](https://onsi.github.io/gomega/) for BDD-style testing.

**Unit Tests**
Unit tests for other packages are in their respective directories.

**E2E Tests**
End-to-end tests are in the `test/e2e` package using the [e2e-framework](https://github.com/kubernetes-sigs/e2e-framework) to test against real Kubernetes clusters.
You'll need [Kind](https://kind.sigs.k8s.io/) installed to create local test clusters.

## Update fixtures

From time to time, you may need to update the test fixtures.

Update SBOM fixtures

```shell
make generate-fixtures
```
