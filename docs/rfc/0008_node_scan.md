|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Node Scanning                   |
| Start Date   | March 5th, 2026                 |
| Category     | Architecture                    |
| RFC PR       | [#]() |
| State        | **ACCEPTED**                    |

# 

[summary]: #summary

Define how the scan of cluster nodes works.

# Motivation

[motivation]: #motivation

We want to build a full-stack, SBOM-based security scanner for Kubernetes.

Nodes are a fundamental building block of the cluster, and we must ensure the 
safety of the infrastructure where our workloads run. 

To achieve this, we need the Node Scanning feature to provide a complete 
overview of the security posture of our nodes.

## Examples / User Stories

[examples]: #examples

- As a user, I want to periodically scan the nodes of my cluster to check for vulnerabilities.
- As a user, I want to define how often the nodes needs to be scanned.
- As a user, I want to have the ability to skip files and/or directories from the scan.

# Detailed design

[design]: #detailed-design

The Node Scan feature will scan nodes in the cluster. This is achieved by 
deploying a `DaemonSet` that runs the worker component.
The worker will use a flag to determine its working mode (image or node scanning).
This allows us to reuse existing code to change the worker's behavior depending 
on the target object we want to scan.

## CRDs

For this feature we are going to add the following CRDs:

* `NodeScanConfiguration`
* `NodeScanJob`
* `NodeSBOM`
* `NodeVulnerabilityReport`

`NodeScanConfiguration` will allow the user to configure the scan on the nodes. This will have the following inputs:
* `scanInterval`: to define how often the scan will run on the cluster.
* `skip`: to define the directories or files that needs to be skipped.

### NodeMetadata Struct

`NodeSBOM` and `NodeVulnerabilityReport` are equal to the [`SBOM`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/sbom_types.go) and 
[`VulnerabilityReport`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/vulnerabilityreport_types.go) resource, execept for except for [`ImageMetadata`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/image_metadata.go).
In this case, we are going to use the `NodeMetadata` structure to store 
information about the node.

`NodeMetadata` will have the following attributes:

* `Name` specifies the unique name of the node in the cluster.
* `Platform` specifies the CPU architecture of the node. Example: amd64, arm64.
* `OS` specifies the operating system of the node. Example: linux, windows.

## Status Conditions

As we define a new CRDs, we also have to define its own status conditions.

The `NodeScanJob` has a very similar status conditions as [`ScanJob`](https://github.com/kubewarden/sbomscanner/blob/main/api/v1alpha1/scanjob_types.go#L36):

Status: `Scheduled` (The job is created but hasn't started doing actual work)
* `Scheduled`: The system has accepted the request and scheduled it.
* `Pending`: The job is in the queue waiting for resources or an executor to pick it up.

Status: `InProgress` (The job is actively executing)
* `InProgress`: Generic indicator that execution has started.
* `FilesystemScan`: Currently iterating through the filesystem.
* `SBOMGenerationInProgress`: Currently parsing dependencies and building the SBOM document.

Status: `Complete` (The job finished successfully)
* `Complete`: Generic success indicator.
* `EntireFilesystemScanned`: Successfully scanned the target system.
* `NoFilesystemToScan`: Finished quickly because the target directory/image was empty or missing.

Status: `Failed` (The job encountered a terminal error)
* `Failed`: Generic failure indicator (e.g., bad user input, invalid target).
* `InternalError`: Failed due to an unexpected system crash, out-of-memory error, or infrastructure issue.

# Drawbacks

[drawbacks]: #drawbacks

Accessing the underlying node's filesystem from Kubernetes is inherently dangerous because it bridges the isolation boundary between the container and the host.
If an attacker compromises a pod with write access to the node's root filesystem, they effectively gain full root access to the entire node.

To avoid security risks, the `DaemonSet` MUST have `volumeMounts` with `readOnly: true`.

