| Field        | Value                                                      |
| :----------- | :--------------------------------------------------------- |
| Feature Name | Workload Scan                                              |
| Start Date   | 2025-02-01                                                 |
| Category     | Architecture                                               |
| RFC PR       | [#XXX](https://github.com/kubewarden/sbomscanner/pull/XXX) |
| State        | **DRAFT**                                                  |

# Summary

[summary]: #summary

This RFC introduces the WorkloadScan feature, which automatically discovers container images from running workloads and creates the necessary scanning infrastructure. Instead of requiring users to manually configure registries and image filters for runtime scanning, the system watches running pods and generates `Registry` resources on the fly. It also produces `WorkloadScanReport` resources that aggregate vulnerability findings per workload.

# Motivation

[motivation]: #motivation

The existing `Registry` configuration approach works well for users who want to scan entire registries or specific repositories. However, some users want a different perspective: they want to know which vulnerabilities affect their actual running pods, not everything that exists in a registry.

The WorkloadScan feature addresses this use case by:

- Automatically discovering container images from running workloads
- Creating and managing `Registry` resources scoped to what's actually deployed
- Producing per-workload vulnerability reports that answer "what needs to be fixed in this deployment?"

This gives users runtime context for their vulnerability data. A registry might contain thousands of images, but only a subset are running in production at any given time. WorkloadScan focuses scanning efforts on that subset and links findings directly to the workloads that need attention.

## Examples / User Stories

[examples]: #examples

- As a user, I want to activate and configure the workload scan functionality.
  - Given a cluster with SBOMScanner installed, when a cluster-scoped `WorkloadScanConfiguration` custom resource (CR) is created, then the workload scan functionality is enabled for all namespaces.
  - Given a cluster with SBOMScanner installed, when a user creates a `WorkloadScanConfiguration` CR that specifies a `namespaceSelector`, then only the matching namespaces are included in the workload scan.
  - Given a cluster with SBOMScanner installed, when a user creates a `WorkloadScanConfiguration` CR that includes global registry options (`authSecret`, `caBundle`, `scanInterval`), then those global settings are propagated to the `Registry` resources created by the operator.

- As a user, I want SBOMScanner to automatically scan the images used by my running workloads.
  - Given a namespace where WorkloadScan is enabled, when a workload is created or updated, then a corresponding managed `Registry` configuration is created or updated by the operator for the matching registry URI, including filters that reflect the platforms, repositories, and image tags of the container images used by the pods scheduled by the workload.
  - Given a `Registry` created by the WorkloadScan reconciler, when the defined `scanInterval` has passed, then the images are rescanned accordingly.

- As a user, I want SBOMScanner to produce vulnerability reports for my workloads.
  - Given a namespace where WorkloadScan is enabled, when all image scans for a workload are complete, then SBOMScanner generates a `WorkloadScanReport` in the same namespace. The report includes references to the workload's containers, scan status per container, and a summary counting vulnerabilities by severity.

# Detailed design

[design]: #detailed-design

## Feature enablement

The WorkloadScan feature can be controlled at two levels:

1. **Helm chart flag**: A flag in the Helm chart allows disabling the feature completely. When disabled, the WorkloadScan reconcilers do not run and no resources are watched. This is useful for clusters where workload scanning is not needed and operators want to avoid any overhead from the reconcilers.

2. **WorkloadScanConfiguration resource**: When the reconcilers are enabled, the feature is only active if a `WorkloadScanConfiguration` resource exists. If no configuration is present, the reconcilers will not process any workloads.

The Helm chart will provide a default `WorkloadScanConfiguration` with a namespace selector set to an arbitrary label (e.g., `sbomscanner.kubewarden.io/workloadscan: "true"`). This allows users to phase in the feature gradually by labeling the namespaces they want to include in workload scanning, rather than enabling it cluster-wide immediately.

## WorkloadScanConfiguration CRD

The `WorkloadScanConfiguration` is a cluster-scoped singleton resource that enables and configures the workload scanning feature. Only one instance named `default` is allowed.

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: WorkloadScanConfiguration
metadata:
  name: default
spec:
  # Filter which namespaces are scanned. If not specified, workloads in all namespaces are scanned.
  namespaceSelector:
    matchLabels:
      environment: production

  # Namespace where Registry, ScanJob, SBOM, and VulnerabilityReport resources are created.
  # WorkloadScanReport resources are always created in their respective workload namespaces.
  # If not specified, resources are created in the workload's namespace.
  targetNamespace: sbomscanner-system

  # Interval at which discovered registries are scanned.
  scanInterval: 24h

  # Trigger a scan when a managed Registry resource is created or updated.
  # Defaults to true.
  scanOnChange: true

  # Name of the secret in the SBOMScanner installation namespace that contains the
  # credentials to access the registry in dockerconfigjson format.
  # See: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
  authSecret: registry-credentials
  caBundle: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  insecure: false
  # Platforms to scan. If not specified, all platforms available in the image manifest are scanned.
  platforms:
    - os: linux
      architecture: amd64
    - os: linux
      architecture: arm64
```

The `namespaceSelector` field uses standard Kubernetes label selectors. When specified, only workloads in namespaces matching the selector are considered for scanning. If not specified, workloads in all namespaces are scanned.

The `targetNamespace` field allows centralizing scan artifacts in a single namespace. If not specified, resources are created in the workload's namespace, which is the preferred approach for multi-tenant clusters where scan data should be isolated per namespace.

The `authSecret` field references a secret containing registry credentials. This secret must exist in the SBOMScanner installation namespace and use the `kubernetes.io/dockerconfigjson` format. See [Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) for details on creating this secret.

The `platforms` field specifies which platforms to scan for container images. This is useful for multi-arch clusters where nodes run different architectures. When multiple platforms are specified, SBOMScanner will scan each platform variant of the image and produce separate `VulnerabilityReport` resources for each. If not specified, all platforms available in the image manifest are scanned.

## WorkloadScanReport CRD

The `WorkloadScanReport` resource aggregates vulnerability information for a single workload. It is created in the same namespace as the workload it references.

```yaml
apiVersion: storage.sbomscanner.kubewarden.io/v1alpha1
kind: WorkloadScanReport
metadata:
  name: deployment-nginx
  namespace: production
  labels:
    sbomscanner.kubewarden.io/managed-by: sbomscanner
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: nginx
      uid: abc-123
spec:
  containers:
    - name: nginx
      imageRef:
        registry: workload-scan-docker-io
        namespace: sbomscanner-system
        repository: library/nginx
        tag: "1.25"
    - name: sidecar
      imageRef:
        registry: workload-scan-ghcr-io
        namespace: sbomscanner-system
        repository: example/sidecar
        tag: "v1.0.0"
status:
  containerStatuses:
    - name: nginx
      scanStatus: ScanComplete
    - name: sidecar
      scanStatus: ScanInProgress
summary:
  high: 5
  medium: 12
  low: 23
  unknown: 0
  suppressed: 2
containers:
  - name: nginx
    vulnerabilityReports:
      - imageMetadata:
          registry: workload-scan-docker-io
          repository: library/nginx
          tag: "1.25"
          digest: sha256:abc...
          platform:
            os: linux
            architecture: amd64
        report:
          vulnerabilities: [...]
```

The `spec.containers` field is written by the reconciler and contains references to the images used by each container in the workload.

The `status`, `summary`, and `containers` fields are computed at read time by joining with `Image` and `VulnerabilityReport` data. They are not stored in the database.

### Scan status semantics

Each container has a `scanStatus` field with one of three values:

- `WaitingForScan`: No `Image` record exists for this container's image reference
- `ScanInProgress`: The `Image` exists but not all platforms have corresponding `VulnerabilityReport` records
- `ScanComplete`: All platforms have vulnerability reports

### Summary computation

The summary counts vulnerabilities across all containers in the workload. In multi-arch environments, the same vulnerability may appear in vulnerability reports for different platforms of the same image. To avoid inflating the vulnerability count, the summary applies deduplication at the container level.

Two vulnerabilities are considered duplicates if they share the same package name, CVE identifier, package version, and VEX suppression status. When duplicates are found across multiple platform variants of the same container image, they are counted only once for that container. The deduplicated counts are then summed across all containers in the workload.

For example, consider a workload with two containers: `init-container` and `myapp-container`. If CVE-2024-1234 affects `libssl` version `3.0.2` in both the `linux/amd64` and `linux/arm64` variants of `init-container`'s image, it contributes 1 to the summary count, not 2. If the same CVE also affects `myapp-container`'s image, it contributes an additional 1, for a total of 2.

## Pre-requisite: Repository pattern

Implementing `WorkloadScanReport` with computed fields requires abstracting database operations from the Kubernetes `storage.Interface` implementation.

The current `store` struct contains all SQL logic directly, which prevents custom storage strategies per resource type.
A `Repository` interface will be introduced to define standard operations: Create, Delete, Get, List, Update, and Count.

The repository abstraction must preserve full support for Kubernetes list semantics, including label selectors and field selectors.
Each repository implementation will be responsible for constructing queries that support these filtering capabilities.

The `store` will delegate to a `Repository` implementation, allowing different storage strategies:

- `GenericObjectRepository`: Single-table storage for resources that do not require computed fields
- `WorkloadScanReportRepository`: Custom storage that computes `status`, `summary`, and `containers` at read time by joining with `VulnerabilityReport` data

This pattern allows for additional repository implementations in the future, should other resources require specialized storage behavior.

### WorkloadScanReport storage

The `WorkloadScanReportRepository` stores only the `spec` portion of the resource. When reading, it executes a query that:

1. Retrieves the stored `spec` with container references
2. Joins with `Image` records to compute `status.containerStatuses`
3. Joins with `VulnerabilityReport` records to compute `summary` and `containers`

Computing fields at read time allows `WorkloadScanReport` to always reflect the current state of vulnerability data without any propagation delay or additional write operations.

## Resource labeling

All resources created by the WorkloadScan feature are labeled to indicate they are managed and to enable selective caching and filtering.

Managed `Registry` resources have two labels:

- `app.kubernetes.io/managed-by: sbomscanner` (standard Kubernetes label)
- `sbomscanner.kubewarden.io/workloadscan: "true"`

The `app.kubernetes.io/managed-by` label signals that the resource is managed by SBOMScanner and will be reconciled back to its expected state if modified externally.

Associated resources (`Image`, `SBOM`, `VulnerabilityReport`) created from workload-scan-managed registries inherit the `sbomscanner.kubewarden.io/workloadscan: "true"` label. This label can be used by clients to filter and retrieve only workload-scan-related resources, and internally for selective cache watches to reduce memory usage.

## Registry match condition extensions

The WorkloadScan feature introduces two extensions to the `MatchCondition` type used in `Registry` resources for filtering image tags.

### Match condition labels

Each `MatchCondition` can include a `labels` field containing key-value pairs. The `WorkloadScanReconciler` uses these labels to track which namespaces are using each condition.

When the reconciler creates or updates match conditions for discovered images, it adds a label in the format `<namespace>: "true"` for each namespace that requires that condition. If multiple namespaces use the same image tag, the condition will have labels for all of them.

### Match operator

The `Repository` type includes a `matchOperator` field that controls how multiple match conditions are combined:

- `And` (default): All conditions must pass for a tag to be included
- `Or`: At least one condition must pass for a tag to be included

For workload scanning, the reconciler uses the `Or` operator when multiple tags from the same repository are discovered across workloads. This allows a single repository configuration to match any of the discovered tags.

## Reconcilers

### Registry scan runner extension

The existing `RegistryScanRunner` has been extended to support on-demand scans via the `sbomscanner.kubewarden.io/rescan-requested` annotation.
When this annotation is present on a `Registry` resource, the runner schedules a scan regardless of whether the configured `scanInterval` has elapsed. After scheduling the scan, the runner removes the annotation.

The `WorkloadScanReconciler` uses this mechanism to trigger scans when new images are discovered, without creating `ScanJob` resources directly.

### WorkloadScanReconciler

The `WorkloadScanReconciler` watches pods and manages `Registry` and `WorkloadScanReport` resources.

The reconciler operates at the namespace level and is triggered when:

- A pod is created, updated, or deleted (filtered to only trigger when container images change)
- A managed `Registry` resource changes (to reconcile it back to the expected state)
- A managed `WorkloadScanReport` resource changes (to reconcile it back to the expected state)
- The `WorkloadScanConfiguration` resource changes
- A namespace's labels change (which may affect selector matching)

The reconciliation logic proceeds as follows:

1. Check if the `WorkloadScanConfiguration` exists. If not, scanning is disabled and all managed resources in the namespace are deleted.
2. If a `namespaceSelector` is configured, verify the namespace matches. If it doesn't match, remove this namespace's labels from all match conditions in managed registries and delete managed `WorkloadScanReport` resources in this namespace, then skip the rest of the reconciliation.
3. List all pods in the namespace and extract container images.
4. Group images by registry host, then by repository and tag.
5. For each registry host, create or update a managed `Registry` resource with:
   - The `app.kubernetes.io/managed-by: sbomscanner` and `sbomscanner.kubewarden.io/workloadscan: "true"` labels
   - Repository filters matching the discovered images
   - CEL match conditions for each tag (e.g., `tag == "1.25"`), using an `Or` operator if multiple tags exist for the same repository
   - Labels on each match condition indicating which namespaces require it
   - Settings from the `WorkloadScanConfiguration` (auth, CA, platforms, scan interval)
6. If `scanOnChange` is enabled and the `Registry` was created or has new match conditions added, set the `sbomscanner.kubewarden.io/rescan-requested` annotation to request a scan from the `RegistryScanRunner`.
7. For match conditions no longer needed by this namespace, remove the namespace's label from the condition:
   - If the condition still has labels from other namespaces, preserve the condition
   - If the condition has no namespace labels remaining, delete it
   - If all conditions are removed from a repository, remove the repository from the registry
   - If all repositories are removed from a registry, delete the registry
8. For each workload (resolved from pod owner references), create or update a `WorkloadScanReport` with container references.
9. Delete `WorkloadScanReport` resources for workloads that no longer exist.

If a managed `Registry` or `WorkloadScanReport` is modified externally, the reconciler will revert it to the expected state on the next reconciliation.

Registry resources are named using the pattern `workload-scan-<sanitized-host>`. For example, `ghcr.io` becomes `workload-scan-ghcr-io`.

The reconciler walks up the owner reference chain to find the top-level workload. For example, a pod owned by a ReplicaSet owned by a Deployment results in a `WorkloadScanReport` for the Deployment.

### ImageAnnotationReconciler

The `ImageAnnotationReconciler` maintains bidirectional references between `Image` resources and the workloads that use them. This enables efficient querying of "which workloads use this image?" without scanning all `WorkloadScanReport` resources.

The reconciler watches both `Image` and `WorkloadScanReport` resources that have the `sbomscanner.kubewarden.io/workloadscan: "true"` label. When an `Image` changes, it finds all `WorkloadScanReport` resources that reference it and updates annotations on the `Image` with workload metadata.

Annotations use the format:

```yaml
annotations:
  sbomscanner.kubewarden.io/workloadscan-<uid>: '{"name":"nginx","namespace":"production","containers":2,"summary":{...}}'
```

This allows the UI or API clients to quickly identify which workloads are affected by vulnerabilities in a given image.

The reconciler uses field indexes to find related resources without listing all objects. These indexes enable lookups like "find all WorkloadScanReports referencing this image" in O(1) time. Custom predicates reduce unnecessary reconciliations by only triggering on relevant changes, such as when container images actually change or when resources have the managed-by label.

## Watch mechanism

`WorkloadScanReport` resources have computed fields that depend on `VulnerabilityReport` data. When a vulnerability report changes, any `WorkloadScanReport` that references the same image needs to emit a watch event so clients see updated data.

### WorkloadScanReportWatcher

A dedicated watcher subscribes to `VulnerabilityReport` events via NATS and generates synthetic `MODIFIED` events for affected `WorkloadScanReport` resources.

The event flow is as follows:

1. A `VulnerabilityReport` is created or updated
2. The storage layer broadcasts the event to NATS
3. `WorkloadScanReportWatcher` receives the event
4. It queries the database for all `WorkloadScanReport` resources where any container's `imageRef` matches the vulnerability report's image metadata
5. For each matching report, it broadcasts a `MODIFIED` event to the `WorkloadScanReport` NATS subject
6. Clients watching `WorkloadScanReport` resources receive the event with recomputed `status`, `summary`, and `containers` fields

The lookup uses a JSONB containment query to find matching `WorkloadScanReport` resources by their container image refs. A GIN index on the `spec.containers` JSONB path enables efficient containment queries without full table scans.

## Controller cache optimization

The WorkloadScan controllers need to watch multiple resource types, but many don't require the full object in memory.

### Metadata-only watches

For resources where only metadata is needed for reconciliation decisions, the controller uses `builder.OnlyMetadata`:

- `Registry` resources: Only need to check if they exist and their labels
- `Namespace` resources: Only need labels for selector matching

This reduces cache memory usage since only `PartialObjectMetadata` is stored instead of full objects.

### Label-based cache filtering

The `sbomscanner.kubewarden.io/workloadscan: "true"` label enables selective caching. The `ImageAnnotationReconciler` uses this label to filter the `Image` resources it watches, reducing memory usage in clusters with many non-workload-scan images.

## Future optimization: Targeted ScanJobs

When `scanOnChange` is enabled, the current implementation creates a `ScanJob` that scans the entire `Registry` whenever it is created or updated. This can be inefficient when a single new image tag is deployed to a workload, as it triggers a full registry scan even though only one new image needs to be scanned.

A future optimization could introduce a targeted `ScanJob` variant that scans only a specific repository and match condition within a registry. This targeted scan would have the following characteristics:

- Scopes the scan to a specific repository and tag (or set of tags) rather than the entire registry
- Does not delete obsolete `Image`, `SBOM`, or `VulnerabilityReport` resources, since it only processes a subset of the registry
- Does not participate in the recurring scan interval, as it is a one-time on-demand scan triggered by workload changes

This would allow the `WorkloadScanReconciler` to create a lightweight `ScanJob` that processes only the newly discovered images, while the regular interval-based scans continue to handle the full registry and cleanup of obsolete resources.

# Drawbacks

[drawbacks]: #drawbacks

- Adds complexity with multiple reconcilers watching different resource types
- The computed fields approach means `WorkloadScanReport` reads are more expensive than simple table lookups

# Alternatives

[alternatives]: #alternatives

An alternative to the `WorkloadScanReportRepository` with read-time aggregation was storing the `status`, `summary`, and `containers` fields in the database and updating them via a background job whenever `VulnerabilityReport` data changes. This approach would introduce additional write load on the database for every vulnerability report change, eventual consistency delays between vulnerability data and workload reports, complexity in coordinating job scheduling and failure handling, and race conditions when multiple vulnerability reports change simultaneously.
