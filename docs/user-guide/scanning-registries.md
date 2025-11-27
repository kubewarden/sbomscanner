# Scanning Registries

This guide explains how to configure and run scans on container registries using SBOMscanner.

It covers:

- Defining a `Registry` custom resource
- Running on-demand scans with a `ScanJob`
- Configuring scheduled scans
- Configuring registry without catalog
- Filtering by tags
- Filtering by platforms
- Monitoring scan progress and results
- Stopping scans and cleaning up resources
- Remove a Registry

## 1. Define a Registry

Before scanning a registry, create a `Registry` custom resource that specifies the registry endpoint and repositories to scan.

Example manifest:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-registry
  namespace: default
spec:
  uri: ghcr.io
  scanInterval: 1h
  repositories:
    - kubewarden/sbomscanner/test-assets/golang
```

This configuration:

- Targets the `ghcr.io` registry
- Scans the `kubewarden/sbomscanner/test-assets/golang` repository
- Runs a new scan every hour

Apply the resource:

```bash
kubectl apply -f registry.yaml
```

For private registries, see the [Private Registries guide](./private-registries.md).

## 2. Run a Scan on Demand

To run a one-time scan, omit the `scanInterval` in the `Registry` resource and create a `ScanJob` that references it.

Example `Registry` without scheduling:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-registry
  namespace: default
spec:
  uri: ghcr.io
  repositories:
    - kubewarden/sbomscanner/test-assets/golang
```

Example `ScanJob` manifest:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: ScanJob
metadata:
  name: my-scanjob
  namespace: default
spec:
  registry: my-registry
```

Apply the job:

```bash
kubectl apply -f scanjob.yaml
```

> **Note**: The `ScanJob` must be created in the same namespace as its referenced `Registry`.

## 3. Configuring registry without catalog

In some cases, you may work with registries that do not implement/exposes the `_catalog` endpoint (such as **Docker Hub**, **Amazon ECR**, or **ghcr.io**).

To make SBOMscanner work with these registries, you can manually specify the repositories you want to scan, instead of pulling the catalog.

> **Note**: When using `catalogType` as `NoCatalog`, you must explicitly provide the list of `repositories` to scan.

Example `Registry` without catalog:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-registry
  namespace: default
spec:
  uri: ghcr.io
  catalogType: NoCatalog
  repositories:
    - name: kubewarden/sbomscanner/test-assets/golang
```

Here's a list of registries that do NOT support `_catalog` (or intentionally disable it):

* Amazon ECR

* Google Container Registry (GCR)

* GitHub Container Registry (GHCR)

## 4. Filtering By Platforms

In most cases you don't want to scan all the platforms of the same image version. For this reason we created a filter mechanism to avoid unuseful scans and waste of time.

To lighten the workload of SBOMscanner, you can specify which platforms you want to scan, instead of discovering them and consequently scan.

Here's an example of how to configure the registry to look only at the `linux/amd64` platform.

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-first-registry
  namespace: default
spec:
  uri: dev-registry.default.svc.cluster.local:5000
  platforms:
    - arch: "amd64"
      os: "linux"
```

To configure multiple platforms, you can list them this way:

```yaml
...
spec:
  uri: dev-registry.default.svc.cluster.local:5000
  platforms:
    - arch: "amd64"
      os: "linux"
    - arch: "386"
      os: "linux"
    - arch: "arm64"
      os: "linux"
      variant: "v7"
```

## 5. Filtering By Tags

You can filter image tags using [CEL](https://kubernetes.io/docs/reference/using-api/cel/) expressions in the `matchConditions` field under `repositories`. This lets you use regex patterns, semantic versioning comparisons, or string operations (like substring matching or contains checks) to select which tags to scan. This filtering capability helps reduce the number of scanned images and lowers the load on the system.

Let's see an example:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-first-registry
  namespace: default
spec:
  uri: dev-registry.default.svc.cluster.local:5000
  repositories:
    - name: kubewarden/sbomscanner/test-assets/test-image
      matchConditions:
        - name: "production tags"
          expression: "tag.endsWith('-prod')"
```

This example shows how to filter for images with a tag ending with `-prod`, helpful to scan only for images being deployed in a production environment.

Another helpful example is to avoid scanning for release candidate images, which are typically tagged as `<version>-rc<rc_version_number>`, by using the following expression: `!tag.matches('-rc*')`.

It's important to mention that multiple expressions can be defined under the `matchConditions` field. This will help the user to define complex filters, splitting them into shorter expressions:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-first-registry
  namespace: default
spec:
  uri: dev-registry.default.svc.cluster.local:5000
  repositories:
    - name: kubewarden/sbomscanner/test-assets/test-image
      matchConditions:
        - name: "semver is less than v1.0.0"
          expression: "semver(tag, true).isLessThan(semver('v1.0.0', true))"
        - name: "semver is greater than v1.1.0"
          expression: "semver(tag, true).isGreaterThan(semver('v1.1.0', true))"
```

This way the user can scan only for a defined range of image versions (from `v1.0.0` to `v1.1.0`).

### Common Expression Language

The Common Expression Language ([CEL](https://github.com/google/cel-go)) is used in the Kubernetes API to declare validation rules, policy rules, and other constraints or conditions.

It is widely used in [Kubernetes](https://kubernetes.io/docs/reference/using-api/cel/), making CEL a convenient alternative to out-of-process mechanisms, such as webhooks, for many extensibility use cases.

For further information about the CEL specification, please take a look to this repository: https://github.com/google/cel-spec

Here's the most common CEL expressions that can be used for tag filtering:

#### String and Regex

| function | example | description |
| --- | --- | ---|
| `startsWith` | `tag.startsWith('v1')` | Tags that starts with `v1` prefix. |
| `endsWith` | `tag.endsWith('-prod')` | Tags that ends with `-prod` suffix. |
| `matches` | `tag.matches('^v[01]\.*')` | Tags that matches the regex `^v[01]\.*`. |

Reference: https://github.com/google/cel-spec/blob/master/doc/langdef.md#string-functions

#### Semver

| function | example | description |
| --- | --- | ---|
| `isGreaterThan` | `semver(tag, true).isGreaterThan(semver('v1.1.0', true))` | Tags that are greater than a given version. |
| `isLessThan` | `semver(tag, true).isLessThan(semver('v1.1.0', true))` | Tags that are less than a given version. |

Reference: https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-semver-library

## 6. Monitor Scan Progress

Check the status of a scan:

```bash
kubectl get scanjob my-scanjob -n default -o yaml
```

Example status:

```yaml
status:
  imagesCount: 10
  conditions:
    - type: Complete
      status: "True"
      reason: "AllImagesScanned"
      message: "Scan completed successfully"
```

## 7. View Results

Reports generated by scans include images, SBOMs, and vulnerability findings.
See the [Querying Reports guide](./querying-reports.md) for details.

## 8. Stop an Ongoing Scan

To cancel a running scan, delete its `ScanJob`:

```bash
kubectl delete scanjob my-scanjob -n default
```

## 9. Remove a Registry

To delete a registry and its associated data:

```bash
kubectl delete registry my-registry -n default
```

This action removes:

- The registry definition
- All related images, SBOMs, and vulnerability reports
- Any `ScanJob` resources referencing the registry

If a scan is in progress, it will be terminated.
