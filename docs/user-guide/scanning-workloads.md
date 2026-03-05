# Scaning Workloads

## Overview

SBOMscanner can scan container registries based on explicit [Registry configurations](./scanning-registries.md), but often what you really want to know is: which vulnerabilities affect the workloads actually running in my cluster right now?

A registry might contain thousands of images, but only a fraction of those are deployed at any given time. The WorkloadScan feature closes this gap. It watches running workloads, discovers the container images they use, sets up the scanning infrastructure automatically, and produces per-workload vulnerability reports that answer the question "what needs to be fixed in this Deployment?".

Under the hood, SBOMscanner creates managed `Registry` resources for each discovered registry host, scoped to only the image tags that are actually in use. It then produces a `WorkloadScanReport` for each workload. The report aggregates vulnerability findings across all containers in the workload, giving you a single place to check the security posture of a Deployment, StatefulSet, or any other workload type.

### Supported workload types

SBOMscanner resolves pods to their owning workload by walking the owner reference chain. For example, a pod owned by a ReplicaSet owned by a Deployment results in a report for the Deployment. The following workload types are supported:

- Deployments
- StatefulSets
- DaemonSets
- ReplicaSets (not owned by a Deployment)
- Pods (not owned by any controller)
- Jobs
- CronJobs

### Default behavior

The WorkloadScan reconcilers are enabled by default when installing SBOMscanner via the Helm chart. Workload scanning becomes active once you create a `WorkloadScanConfiguration` resource. A sample configuration is available in the [examples folder](../../examples/workloadscanconfiguration.yaml).

## Configuration

The `WorkloadScanConfiguration` is a cluster-scoped singleton resource named `default`. It is the single entry point for controlling the workload scanning behavior. Only one instance is allowed.

To activate workload scanning after installation, create the configuration:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubewarden/sbomscanner/main/examples/workloadscanconfiguration.yaml
```

Or create your own configuration:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: WorkloadScanConfiguration
metadata:
  name: default
spec:
  namespaceSelector:
    matchLabels:
      sbomscanner.kubewarden.io/workloadscan: "true"
  artifactsNamespace: sbomscanner
  scanOnChange: true
  scanInterval: 1h
  platforms:
    - arch: amd64
      os: linux
    - arch: arm64
      os: linux
```

### Fields

| Field                | Description                                                                                                                                                                                                                                                                                                                                                             | Default                                   |
| :------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------- |
| `enabled`            | Enable or disable workload scanning. See [Disabling workload scanning](#disabling-workload-scanning) for details.                                                                                                                                                                                                                                                       | `true`                                    |
| `artifactsNamespace` | Namespace where managed `Registry`, `ScanJob`, `Image`, `SBOM`, and `VulnerabilityReport` resources are created. `WorkloadScanReport` resources are always created in the workload's namespace regardless of this setting. If omitted or empty, managed artifacts are created in the workload's namespace. See [Multi-tenancy setup](#multi-tenancy-setup) for details. | Workload's namespace (when omitted/empty) |
| `scanOnChange`       | Trigger a scan when a managed Registry resource is created or updated.                                                                                                                                                                                                                                                                                                  | `true`                                    |
| `scanInterval`       | How often discovered registries are rescanned. The vulnerability database is continuously updated, so periodic rescans ensure reports reflect the latest findings even if the workload hasn't changed.                                                                                                                                                                  | -                                         |
| `platforms`          | Which platforms to scan for each discovered image. See [Scanning multiple platforms](#scanning-multiple-platforms).                                                                                                                                                                                                                                                     | All platforms                             |
| `namespaceSelector`  | A standard [Kubernetes label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors). Only workloads in namespaces matching the selector are scanned. If omitted, workloads in all namespaces are scanned.                                                                                                                 | -                                         |
| `authSecret`         | Name of a secret in the SBOMscanner installation namespace containing registry credentials in `kubernetes.io/dockerconfigjson` format. These credentials are propagated to all managed `Registry` resources. See [Private Registries](./private-registries.md).                                                                                                         | -                                         |
| `caBundle`           | PEM-encoded CA certificate bundle for registries using a custom certificate authority.                                                                                                                                                                                                                                                                                  | -                                         |
| `insecure`           | Allow connections to registries without TLS verification.                                                                                                                                                                                                                                                                                                               | `false`                                   |

> **Note**: The `artifactsNamespace` field can only be changed when `enabled` is `false`. This prevents moving artifacts while scans are actively running.

### Scanning multiple platforms

Many container images are published as multi-arch manifests that contain variants for different CPU architectures (e.g., `linux/amd64`, `linux/arm64`). By default, SBOMscanner scans all platforms available in the image manifest.

In clusters that only run nodes of a specific architecture, scanning all platforms produces reports for architectures that are not actually deployed, which adds unnecessary scanning time and storage. The `platforms` field lets you restrict scanning to only the architectures your cluster runs:

```yaml
spec:
  platforms:
    - arch: amd64
      os: linux
```

For clusters with mixed architectures (e.g., both `amd64` and `arm64` node pools), list all platforms you want covered:

```yaml
spec:
  platforms:
    - arch: amd64
      os: linux
    - arch: arm64
      os: linux
```

When multiple platforms are specified, SBOMscanner produces separate `VulnerabilityReport` resources for each platform variant. The `WorkloadScanReport` summary deduplicates findings across platforms so the same CVE affecting the same package is not counted twice.

### Disabling workload scanning

There are two levels of disabling the feature:

**Disabling at the configuration level** either sets `enabled: false` in the `WorkloadScanConfiguration` resource or deletes the resource entirely. When `enabled` is `false`, the reconcilers remain running but stop processing workloads. This is useful when you want to temporarily pause scanning without removing the entire configuration, or when you need to change the `artifactsNamespace` field (which requires `enabled` to be `false`). Deleting the `WorkloadScanConfiguration` resource also disables scanning and causes all managed resources to be cleaned up.

**Disabling at the Helm chart level** prevents the reconcilers from starting entirely. No workload-scan-related resources are watched and no CPU or memory overhead is incurred. Use this when you don't need workload scanning at all:

```yaml
controller:
  workloadScan:
    enabled: false
```

This is particularly useful for clusters where scanning is handled through explicit `Registry` configurations and the workload-oriented perspective is not needed, or in resource-constrained environments where the additional controllers would consume resources without providing value.

## Enabling scanning for a namespace

The example configuration above uses a namespace selector that matches the label `sbomscanner.kubewarden.io/workloadscan: "true"`. Scanning is not active in any namespace until you apply this label.

Label the namespace you want to scan:

```bash
kubectl label namespace prod sbomscanner.kubewarden.io/workloadscan=true
```

Create a workload in that namespace:

```bash
kubectl create deployment nginx --image=nginx:1.25 -n prod
```

SBOMscanner will automatically:

1. Detect the container images used by the Deployment's pods
2. Create a managed `Registry` resource targeting `docker.io` with filters for the `library/nginx:1.25` image
3. Trigger a scan of that image (because `scanOnChange` is `true` by default)
4. Create a `WorkloadScanReport` in the `prod` namespace for the Deployment

If you later remove the label from the namespace, SBOMscanner cleans up all managed resources for that namespace: the namespace's entries are removed from managed `Registry` resources, and `WorkloadScanReport` resources are deleted. Similarly, when a workload is deleted or scaled to zero, its report is removed.

## Understanding WorkloadScanReport

The `WorkloadScanReport` is a namespaced resource that lives in the same namespace as the workload it describes. It is the primary output of the WorkloadScan feature and provides a unified view of the vulnerability posture of a workload.

A report is composed of four sections:

- **`spec`**: Written by the reconciler. Contains the list of containers and their image references. This is the stored portion of the resource.
- **`status`**: Computed at read time. Shows the scan progress for each container.
- **`summary`**: Computed at read time. Aggregated vulnerability counts (critical, high, medium, low, unknown, suppressed) across all containers, with deduplication applied so the same CVE affecting the same package across different platform variants of the same container image is counted only once.
- **`containers`**: Computed at read time. The full vulnerability report data for each container, obtained by joining with `VulnerabilityReport` resources. This is where you find the actual CVEs, affected packages, and severity details.

The `status`, `summary`, and `containers` fields are not stored in the database. They are computed on every read by joining with the latest `Image` and `VulnerabilityReport` data, so they always reflect the current state of vulnerability findings without any propagation delay.

List reports in a namespace:

```bash
kubectl get workloadscanreports -n prod
```

```
NAME               AGE
deployment-nginx   2m
```

Retrieve a report:

```bash
kubectl get workloadscanreport deployment-nginx -n prod -o yaml
```

```yaml
apiVersion: storage.sbomscanner.kubewarden.io/v1alpha1
kind: WorkloadScanReport
metadata:
  name: deployment-nginx
  namespace: prod
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: nginx
      uid: ...
spec:
  containers:
    - name: nginx
      imageRef:
        registry: workload-scan-docker-io
        namespace: sbomscanner
        repository: library/nginx
        tag: "1.25"
status:
  containerStatuses:
    - name: nginx
      scanStatus: ScanComplete
summary:
  critical: 0
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
          registryURI: docker.io
          repository: library/nginx
          tag: "1.25"
          digest: sha256:abc...
          platform: linux/amd64
        report:
          summary:
            critical: 0
            high: 5
            medium: 12
            low: 23
            unknown: 0
            suppressed: 2
          results:
            - class: os-pkgs
              target: ...
              type: debian
              vulnerabilities:
                - cve: CVE-2024-1234
                  packageName: libssl3
                  installedVersion: 3.0.2
                  severity: HIGH
                  suppressed: false
                  ...
```

### Scan status

Each container in the report has a `scanStatus` that tracks the progress of its image scan:

| Status           | Meaning                                                                                                                          |
| :--------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| `WaitingForScan` | No `Image` record exists yet for this container's image. The scan has not started.                                               |
| `ScanInProgress` | The `Image` exists but not all configured platforms have corresponding `VulnerabilityReport` records. The scan is still running. |
| `ScanComplete`   | All configured platforms have vulnerability reports. The scan is done.                                                           |

### Managed resources

SBOMscanner creates and manages `Registry` resources behind the scenes to drive scanning. These resources are labeled with `sbomscanner.kubewarden.io/workloadscan: "true"` and `app.kubernetes.io/managed-by: sbomscanner`.

Managed resources are protected: external modifications are rejected before they reach the cluster. Validating webhooks block unauthorized changes to managed `Registry` resources, and an admission plugin on the storage API extension server blocks unauthorized changes to managed `WorkloadScanReport` resources. Only the SBOMscanner controller service account is authorized to modify them.

You generally don't need to interact with managed `Registry` resources directly. They are an implementation detail of the WorkloadScan feature.

## Multi-tenancy setup

When `artifactsNamespace` is set, all scan artifacts (`Registry`, `Image`, `SBOM`, `VulnerabilityReport`) are centralized in that namespace, while `WorkloadScanReport` resources are always created in the workload's namespace. This is the simplest setup: if the same image runs in multiple namespaces, it is scanned only once, and all reports reference the shared results.

For multi-tenant clusters where teams should not have cross-namespace visibility into scan data, omit the `artifactsNamespace` field:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: WorkloadScanConfiguration
metadata:
  name: default
spec:
  namespaceSelector:
    matchLabels:
      sbomscanner.kubewarden.io/workloadscan: "true"
```

Without `artifactsNamespace`, SBOMscanner creates all resources in the workload's own namespace. Each namespace gets its own `Registry`, `Image`, `SBOM`, `VulnerabilityReport`, and `WorkloadScanReport` resources. This provides full namespace-level isolation: teams only see scan data related to their own workloads and standard Kubernetes RBAC controls access to all resources.

The trade-off is duplication. If the same image (e.g., `nginx:1.25`) runs in multiple namespaces, it is scanned independently in each one, producing separate `Image`, `SBOM`, and `VulnerabilityReport` resources per namespace. This means more scanning work and more storage, but guarantees that no data leaks across namespace boundaries.

| Setup                               | Artifacts location | Isolation                                            | Duplication                                                          |
| :---------------------------------- | :----------------- | :--------------------------------------------------- | :------------------------------------------------------------------- |
| With `artifactsNamespace` (default) | Central namespace  | Shared scan data, `WorkloadScanReport` per namespace | No duplication                                                       |
| Without `artifactsNamespace`        | Workload namespace | Full namespace isolation                             | Images shared across namespaces are scanned and stored independently |

Choose the setup that best fits your cluster's tenancy model. For single-tenant clusters or clusters with a dedicated security team reviewing all findings, the default centralized setup is simpler and avoids redundant work. For multi-tenant clusters where teams should not have cross-namespace visibility into scan data, omit `artifactsNamespace`.
