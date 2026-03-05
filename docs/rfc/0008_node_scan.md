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

* `NodeScanJob`

* `NodeScanSBOM`

* `NodeScanVulnerabilityReport`

`NodeScanJob` will allow the user to configure the scan on the nodes. This will
have the following inputs:
* `scanInterval`: to define how often the scan will run on the cluster.
* `skip`: to define the directories or files that needs to be skipped.

### NodeMetadata Struct

`NodeScanSBOM` and `NodeScanVulnerabilityReport` are equal to the [`SBOM`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/sbom_types.go) and 
[`VulnerabilityReport`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/vulnerabilityreport_types.go) resource, execept for except for [`ImageMetadata`](https://github.com/kubewarden/sbomscanner/blob/main/api/storage/v1alpha1/image_metadata.go).
In this case, we are going to use the `NodeMetadata` structure to store 
information about the node.

`NodeMetadata` will have the following attributes:

* `Name` specifies the unique name of the node in the cluster.

* `Platform` specifies the CPU architecture of the node. Example: amd64, arm64.

* `OS` specifies the operating system of the node. Example: linux, windows.

* `OSImage` specifies the OS image reported by the node. Example: Ubuntu 22.04.1 LTS.

* `KernelVersion` specifies the kernel version reported by the node.

* `InternalIP` specifies the primary internal IP address of the node used for cluster communication.

## 

# Drawbacks

[drawbacks]: #drawbacks

<!---
Why should we **not** do this?

  * obscure corner cases
  * will it impact performance?
  * what other parts of the product will be affected?
  * will the solution be hard to maintain in the future?
--->

# Alternatives

[alternatives]: #alternatives

<!---
- What other designs/options have been considered?
- What is the impact of not doing this?
--->

# Unresolved questions

[unresolved]: #unresolved-questions

<!---
- What are the unknowns?
- What can happen if Murphy's law holds true?
--->
