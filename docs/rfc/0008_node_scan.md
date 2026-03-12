|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Node Scan                       |
| Start Date   | March 5th, 2026                 |
| Category     | Architecture                    |
| RFC PR       | [#]() |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

Define the architectural and functional requirements for scanning Kubernetes cluster nodes.

# Motivation

[motivation]: #motivation

We aim to develop a full-stack, SBOM-based security scanner for Kubernetes.
Because nodes are the foundation of the cluster, maintaining visibility into their 
security posture is critical.

This feature provides a comprehensive overview of node-level vulnerabilities, 
ensuring the safety of the infrastructure where workloads reside.

## Examples / User Stories

[examples]: #examples

- As user, I want to have a comprehensive overview of node-level vulnerabilities, ensuring the safety of the infrastructure where workloads reside.
- As a user, I want to automatically scan cluster nodes for vulnerabilities on a recurring basis.
- As a user, I want to define the scan interval for my nodes.
- As a user, I want the ability to exclude specific files or directories from the scan to reduce noise or avoid sensitive paths.

# Detailed design

[design]: #detailed-design

Node scanning is implemented by deploying a `DaemonSet` that executes a worker 
component on every node. 
The worker will be provided with a flag to operate between image scanning and node scanning 
modes, allowing for significant code reuse across different scan targets.

## CRDs

For this feature we are going to add the following CRDs:

* `NodeScanConfiguration`: Defines the global scan settings.
  * `scanInterval`: Duration between automated scans.
  * `skip`: A list of file/directory paths to be ignored.
* `NodeScanJob`: Represents a single execution of a node scan.
* `NodeSBOM`: Stores the Software Bill of Materials for a specific node.
* `NodeVulnerabilityReport`: Contains the results of the vulnerability analysis.

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

Since we're defining new CRDs, we also need to define their status conditions.

The `NodeScanJob` has status conditions very similar to [`ScanJob`](https://github.com/kubewarden/sbomscanner/blob/main/api/v1alpha1/scanjob_types.go#L36):

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

Mounting the host filesystem into a container bridges the isolation boundary and 
introduces significant risk. To mitigate potential host compromise, the `DaemonSet` 
must mount the host root filesystem as `readOnly: true`.
