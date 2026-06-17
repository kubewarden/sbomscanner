# API Reference

## Packages
- [sbomscanner.kubewarden.io/v1alpha1](#sbomscannerkubewardeniov1alpha1)
- [storage.sbomscanner.kubewarden.io/v1alpha1](#storagesbomscannerkubewardeniov1alpha1)


## sbomscanner.kubewarden.io/v1alpha1

Package v1alpha1 contains API Schema definitions for the SBOMscanner v1alpha1 API group.

### Resource Types
- [NodeScanConfiguration](#nodescanconfiguration)
- [NodeScanConfigurationList](#nodescanconfigurationlist)
- [NodeScanJob](#nodescanjob)
- [NodeScanJobList](#nodescanjoblist)
- [Registry](#registry)
- [RegistryList](#registrylist)
- [ScanJob](#scanjob)
- [ScanJobList](#scanjoblist)
- [VEXHub](#vexhub)
- [VEXHubList](#vexhublist)
- [WorkloadScanConfiguration](#workloadscanconfiguration)
- [WorkloadScanConfigurationList](#workloadscanconfigurationlist)



#### MatchCondition



MatchCondition defines a CEL expression to filter image tags.



_Appears in:_
- [Repository](#repository)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is an identifier for this match condition, used for strategic merging of MatchConditions,<br />as well as providing an identifier for logging purposes.<br />A good name should be descriptive of the associated expression. |  |  |
| `expression` _string_ | Expression represents the expression which will be evaluated by CEL. Must evaluate to bool.<br />Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/ |  |  |
| `labels` _object (keys:string, values:string)_ | Labels are key-value pairs that can be used to organize and categorize match conditions. |  |  |


#### MatchOperator

_Underlying type:_ _string_

MatchOperator defines how multiple match conditions are combined.

_Validation:_
- Enum: [And Or]

_Appears in:_
- [Repository](#repository)

| Field | Description |
| --- | --- |
| `And` | MatchOperatorAnd requires all conditions to pass.<br /> |
| `Or` | MatchOperatorOr requires at least one condition to pass.<br /> |


#### NodeScanConfiguration



NodeScanConfiguration is the Schema for the nodescanconfigurations API.
This is a singleton resource - only one instance named "default" is allowed.



_Appears in:_
- [NodeScanConfigurationList](#nodescanconfigurationlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `NodeScanConfiguration` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NodeScanConfigurationSpec](#nodescanconfigurationspec)_ |  |  |  |


#### NodeScanConfigurationList



NodeScanConfigurationList contains a list of NodeScanConfiguration.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `NodeScanConfigurationList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[NodeScanConfiguration](#nodescanconfiguration) array_ |  |  |  |


#### NodeScanConfigurationSpec



NodeScanConfigurationSpec defines the desired configuration for node scanning.



_Appears in:_
- [NodeScanConfiguration](#nodescanconfiguration)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | Enabled controls whether node scanning is active. | true |  |
| `nodeSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | NodeSelector filters which nodes are scanned.<br />If not specified, all the nodes are scanned. |  | Optional: \{\} <br /> |
| `scanInterval` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#duration-v1-meta)_ | ScanInterval is the interval at which nodes are scanned. |  | Optional: \{\} <br /> |
| `skipPatterns` _string array_ | SkipPatterns specifies gitignore-style patterns for directories and files to skip during node scanning.<br />Patterns ending with "/" are treated as directories.<br />All other patterns are treated as files.<br />Glob patterns like "**/vendor/" or "*.min.js" are supported. |  | Optional: \{\} <br /> |
| `platforms` _[Platform](#platform) array_ | Platforms allows to specify the list of platforms to scan.<br />If not set, all nodes are scanned regardless of their platform. |  | Optional: \{\} <br /> |


#### NodeScanJob



NodeScanJob is the Schema for the nodescanjobs API.



_Appears in:_
- [NodeScanJobList](#nodescanjoblist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `NodeScanJob` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NodeScanJobSpec](#nodescanjobspec)_ |  |  |  |
| `status` _[NodeScanJobStatus](#nodescanjobstatus)_ |  |  |  |


#### NodeScanJobList



NodeScanJobList contains a list of NodeScanJob.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `NodeScanJobList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[NodeScanJob](#nodescanjob) array_ |  |  |  |


#### NodeScanJobSpec



NodeScanJobSpec defines the desired state of NodeScanJob.



_Appears in:_
- [NodeScanJob](#nodescanjob)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nodeName` _string_ | NodeName specifies the name of the node to be scanned. |  |  |


#### NodeScanJobStatus



NodeScanJobStatus defines the observed state of NodeScanJob.



_Appears in:_
- [NodeScanJob](#nodescanjob)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#condition-v1-meta) array_ | Conditions represent the latest available observations of ScanJob state |  | Optional: \{\} <br /> |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#time-v1-meta)_ | StartTime is when the job started processing. |  | Optional: \{\} <br /> |
| `completionTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#time-v1-meta)_ | CompletionTime is when the job completed or failed. |  | Optional: \{\} <br /> |


#### Platform



Platform describes the platform which the image in the manifest runs on.



_Appears in:_
- [NodeScanConfigurationSpec](#nodescanconfigurationspec)
- [RegistrySpec](#registryspec)
- [WorkloadScanConfigurationSpec](#workloadscanconfigurationspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `arch` _string_ | Architecture field specifies the CPU architecture, for example<br />`amd64` or `ppc64le`. |  |  |
| `os` _string_ | OS specifies the operating system, for example `linux` or `windows`. |  |  |
| `variant` _string_ | Variant is an optional field specifying a variant of the CPU, for<br />example `v7` to specify ARMv7 when architecture is `arm`. |  |  |


#### Registry



Registry is the Schema for the registries API



_Appears in:_
- [RegistryList](#registrylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `Registry` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RegistrySpec](#registryspec)_ |  |  |  |
| `status` _[RegistryStatus](#registrystatus)_ |  |  |  |


#### RegistryList



RegistryList contains a list of Registry





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `RegistryList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[Registry](#registry) array_ |  |  |  |


#### RegistrySpec



RegistrySpec defines the desired state of Registry



_Appears in:_
- [Registry](#registry)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `uri` _string_ | URI is the URI of the container registry |  |  |
| `catalogType` _string_ | CatalogType is the type of catalog used to list the images within the registry. |  |  |
| `repositories` _[Repository](#repository) array_ | Repositories is the list of the repositories to be scanned<br />An empty list means all the repositories found in the registry are going to be scanned. |  |  |
| `authSecret` _string_ | AuthSecret is the name of the secret in the same namespace that contains the credentials to access the registry.<br />The secret must be in dockerconfigjson format. See: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/ |  |  |
| `scanInterval` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#duration-v1-meta)_ | ScanInterval is the interval at which the registry is scanned.<br />If not set, automatic scanning is disabled. |  |  |
| `caBundle` _string_ | CABundle is the CA bundle to use when connecting to the registry. |  |  |
| `insecure` _boolean_ | Insecure allows insecure connections to the registry when set to true. |  |  |
| `platforms` _[Platform](#platform) array_ | Platforms allows to specify the list of platform to scan.<br />If not set, all the available platforms of a container image will be scanned. |  |  |


#### RegistryStatus



RegistryStatus defines the observed state of Registry



_Appears in:_
- [Registry](#registry)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#condition-v1-meta) array_ |  |  |  |


#### Repository



Repository specifies an OCI repository and which image tags to scan.



_Appears in:_
- [RegistrySpec](#registryspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the repository name. |  |  |
| `matchConditions` _[MatchCondition](#matchcondition) array_ | MatchConditions filters image tags using CEL expressions. |  |  |
| `matchOperator` _[MatchOperator](#matchoperator)_ | MatchOperator specifies how this condition is combined with other conditions.<br />When set to "And" (default), all conditions must pass for the filter to match.<br />When set to "Or", at least one condition must pass for the filter to match. | And | Enum: [And Or] <br />Optional: \{\} <br /> |




#### ScanJob



ScanJob is the Schema for the scanjobs API.



_Appears in:_
- [ScanJobList](#scanjoblist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `ScanJob` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ScanJobSpec](#scanjobspec)_ |  |  |  |
| `status` _[ScanJobStatus](#scanjobstatus)_ |  |  |  |


#### ScanJobList



ScanJobList contains a list of ScanJob.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `ScanJobList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ScanJob](#scanjob) array_ |  |  |  |


#### ScanJobRepository



ScanJobRepository selects a Registry repository (and optionally a subset of its match conditions) for a targeted ScanJob.



_Appears in:_
- [RescanRequest](#rescanrequest)
- [ScanJobSpec](#scanjobspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of a repository declared on the Registry. |  | Required: \{\} <br /> |
| `matchConditions` _string array_ | MatchConditions optionally narrows the scan to a subset of the MatchConditions declared on the targeted repository.<br />Each entry must reference an existing MatchCondition by name.<br />When empty, all MatchConditions of the repository apply. |  | Optional: \{\} <br /> |


#### ScanJobSpec



ScanJobSpec defines the desired state of ScanJob.



_Appears in:_
- [ScanJob](#scanjob)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `registry` _string_ | Registry is the registry in the same namespace to scan. |  | Required: \{\} <br /> |
| `repositories` _[ScanJobRepository](#scanjobrepository) array_ | Repositories optionally narrows the scan to a subset of the repositories configured on the targeted Registry.<br />When empty, all repositories of the Registry are scanned. |  | Optional: \{\} <br /> |


#### ScanJobStatus



ScanJobStatus defines the observed state of ScanJob.



_Appears in:_
- [ScanJob](#scanjob)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#condition-v1-meta) array_ | Conditions represent the latest available observations of ScanJob state |  | Optional: \{\} <br /> |
| `imagesCount` _integer_ | ImagesCount is the number of images in the registry. |  |  |
| `scannedImagesCount` _integer_ | ScannedImagesCount is the number of images that have been scanned. |  |  |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#time-v1-meta)_ | StartTime is when the job started processing. |  | Optional: \{\} <br /> |
| `completionTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#time-v1-meta)_ | CompletionTime is when the job completed or failed. |  | Optional: \{\} <br /> |


#### VEXHub



VEXHub is the Schema for the vexhubs API



_Appears in:_
- [VEXHubList](#vexhublist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `VEXHub` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[VEXHubSpec](#vexhubspec)_ | spec defines the desired state of VEXHub |  | Required: \{\} <br /> |
| `status` _[VEXHubStatus](#vexhubstatus)_ | status defines the observed state of VEXHub |  | Optional: \{\} <br /> |


#### VEXHubList



VEXHubList contains a list of VEXHub





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `VEXHubList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[VEXHub](#vexhub) array_ |  |  |  |


#### VEXHubSpec



VEXHubSpec defines the desired state of VEXHub



_Appears in:_
- [VEXHub](#vexhub)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `url` _string_ | URL is the URL of the VEXHub repository |  |  |
| `enabled` _boolean_ | Enabled tells if the VEX Hub is enabled for processing |  |  |


#### VEXHubStatus



VEXHubStatus defines the observed state of VEXHub.



_Appears in:_
- [VEXHub](#vexhub)



#### WorkloadScanConfiguration



WorkloadScanConfiguration is the Schema for the workloadscanconfigurations API.
This is a singleton resource - only one instance named "default" is allowed.



_Appears in:_
- [WorkloadScanConfigurationList](#workloadscanconfigurationlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WorkloadScanConfiguration` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[WorkloadScanConfigurationSpec](#workloadscanconfigurationspec)_ |  |  |  |


#### WorkloadScanConfigurationList



WorkloadScanConfigurationList contains a list of WorkloadScanConfiguration.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sbomscanner.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WorkloadScanConfigurationList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[WorkloadScanConfiguration](#workloadscanconfiguration) array_ |  |  |  |


#### WorkloadScanConfigurationSpec



WorkloadScanConfigurationSpec defines the desired configuration for workload scanning.



_Appears in:_
- [WorkloadScanConfiguration](#workloadscanconfiguration)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | Enabled controls whether workload scanning is active. | true |  |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | NamespaceSelector filters which namespaces are scanned for workloads.<br />If not specified, workloads in all namespaces are scanned. |  | Optional: \{\} <br /> |
| `artifactsNamespace` _string_ | ArtifactsNamespace is the namespace where scan artifacts (Registry, ScanJob, SBOM, VulnerabilityReport) are created.<br />When empty, artifacts are created in the workload's own namespace.<br />Can only be changed when Enabled is false.<br />Note: WorkloadScanReport resources are always created in the workload's namespace, regardless of this setting. |  | Optional: \{\} <br /> |
| `scanInterval` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#duration-v1-meta)_ | ScanInterval is the interval at which discovered registries are scanned. |  | Optional: \{\} <br /> |
| `scanOnChange` _boolean_ | ScanOnChange triggers a scan when a managed Registry resource is created or updated.<br />Defaults to true. | true | Optional: \{\} <br /> |
| `authSecret` _string_ | AuthSecret is the name of a secret in the installation namespace containing credentials to access registries.<br />The secret must be in dockerconfigjson format. See: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/ |  | Optional: \{\} <br /> |
| `caBundle` _string_ | CABundle is the CA bundle to use when connecting to registries. |  | Optional: \{\} <br /> |
| `insecure` _boolean_ | Insecure allows insecure connections to registries when set to true. |  | Optional: \{\} <br /> |
| `platforms` _[Platform](#platform) array_ | Platforms specifies which platforms to scan for container images.<br />If not specified, all platforms available in the image manifest will be scanned. |  | Optional: \{\} <br /> |



## storage.sbomscanner.kubewarden.io/v1alpha1

Package v1alpha1 contains the storage v1alpha1 types for SBOMscanner.



#### CVSS



CVSS holds Common Vulnerability Scoring System data for a vulnerability.



_Appears in:_
- [Vulnerability](#vulnerability)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `v3vector` _string_ | V3Vector string (e.g., "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") |  |  |
| `v3score` _string_ | V3Score numerical score |  |  |


#### Class

_Underlying type:_ _string_





_Appears in:_
- [Result](#result)



#### ContainerRef



ContainerRef identifies a container and its image reference for vulnerability lookup.



_Appears in:_
- [WorkloadScanReportSpec](#workloadscanreportspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the container. |  |  |
| `imageRef` _[ImageRef](#imageref)_ | ImageRef identifies which VulnerabilityReports to associate with this container. |  |  |


#### ContainerResult



ContainerResult contains the vulnerability scan results for a single container.



_Appears in:_
- [WorkloadScanReport](#workloadscanreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the container (matches ContainerRef.Name). |  |  |
| `vulnerabilityReports` _[WorkloadScanVulnerabilityReport](#workloadscanvulnerabilityreport) array_ | VulnerabilityReports contains the vulnerability reports for this container's image.<br />Multiple reports may exist for multi-arch images (one per platform). |  | Optional: \{\} <br /> |


#### ContainerStatus



ContainerStatus contains the scan status for a single container.



_Appears in:_
- [WorkloadScanReportStatus](#workloadscanreportstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the container (matches ContainerRef.Name). |  |  |
| `scanStatus` _[ScanStatus](#scanstatus)_ | ScanStatus indicates the scan status for this container. |  |  |


#### Image



Image is the Schema for the images API



_Appears in:_
- [ImageList](#imagelist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `imageMetadata` _[ImageMetadata](#imagemetadata)_ | Metadata of the image |  |  |
| `layers` _[ImageLayer](#imagelayer) array_ | List of the layers that make the image |  |  |
| `status` _[ImageStatus](#imagestatus)_ | Status of the image |  |  |


#### ImageLayer



ImageLayer define a layer part of an OCI Image



_Appears in:_
- [Image](#image)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `command` _string_ | command is the command that led to the creation<br />of the layer. The contents are base64 encoded |  |  |
| `digest` _string_ | digest is the Hash of the compressed layer |  |  |
| `diffID` _string_ | diffID is the Hash of the uncompressed layer |  |  |




#### ImageMetadata



ImageMetadata contains the metadata details of an image.



_Appears in:_
- [Image](#image)
- [SBOM](#sbom)
- [VulnerabilityReport](#vulnerabilityreport)
- [WorkloadScanVulnerabilityReport](#workloadscanvulnerabilityreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `registry` _string_ | Registry specifies the name of the Registry object in the same namespace where the image is stored. |  |  |
| `registryURI` _string_ | RegistryURI specifies the URI of the registry where the image is stored. Example: "registry-1.docker.io:5000".` |  |  |
| `repository` _string_ | Repository specifies the repository path of the image. Example: "kubewarden/sbomscanner". |  |  |
| `tag` _string_ | Tag specifies the tag of the image. Example: "latest". |  |  |
| `platform` _string_ | Platform specifies the platform of the image. Example "linux/amd64". |  |  |
| `digest` _string_ | Digest specifies the image manifest digest. |  |  |
| `indexDigest` _string_ | IndexDigest specifies the image index digest that referenced this manifest. Set only for multi-arch images. |  |  |




#### ImageRef



ImageRef identifies a set of VulnerabilityReports by image reference.



_Appears in:_
- [ContainerRef](#containerref)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `registry` _string_ | Registry is the name of the Registry custom resource. |  |  |
| `namespace` _string_ | Namespace is the namespace where the VulnerabilityReports are stored. |  |  |
| `repository` _string_ | Repository is the repository path of the image. |  |  |
| `tag` _string_ | Tag is the tag of the image. |  |  |


#### ImageStatus



ImageStatus contains the observed state of the Image



_Appears in:_
- [Image](#image)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `workloadScanReports` _[ImageWorkloadScanReports](#imageworkloadscanreports) array_ | WorkloadScanReports is the list of workloads referencing this image |  |  |


#### ImageWorkloadScanReports



ImageWorkloadScanReports identifies a workload that references this image



_Appears in:_
- [ImageStatus](#imagestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the WorkloadScanReport |  |  |
| `namespace` _string_ | Namespace of the WorkloadScanReport |  |  |


#### NodeMetadata



NodeMetadata contains the metadata details of a node.



_Appears in:_
- [NodeSBOM](#nodesbom)
- [NodeVulnerabilityReport](#nodevulnerabilityreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name specifies the name of the node. |  |  |
| `platform` _string_ | Platform specifies the platform of the image. Example "linux/amd64". |  |  |




#### NodeSBOM



NodeSBOM represents a Software Bill of Materials of a node



_Appears in:_
- [NodeSBOMList](#nodesbomlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `nodeMetadata` _[NodeMetadata](#nodemetadata)_ |  |  |  |
| `spdx` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_ | SPDX contains the SPDX document of the SBOM in JSON format |  |  |




#### NodeVulnerabilityReport



NodeVulnerabilityReport is the Schema for the scanresults API



_Appears in:_
- [NodeVulnerabilityReportList](#nodevulnerabilityreportlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `nodeMetadata` _[NodeMetadata](#nodemetadata)_ | NodeMetadata contains info about the scanned node |  |  |
| `report` _[Report](#report)_ | Report is the actual vulnerability scan report |  |  |




#### Report



Report contains metadata about the scanned image and a list of vulnerability results.



_Appears in:_
- [NodeVulnerabilityReport](#nodevulnerabilityreport)
- [VulnerabilityReport](#vulnerabilityreport)
- [WorkloadScanVulnerabilityReport](#workloadscanvulnerabilityreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `summary` _[Summary](#summary)_ | Summary of vulnerabilities found |  |  |
| `results` _[Result](#result) array_ | Results per target (e.g., layer, package type) |  |  |


#### Result



Result represents scan findings for a specific target and class of packages



_Appears in:_
- [Report](#report)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `target` _string_ | Target is the specific target scanned |  |  |
| `class` _[Class](#class)_ | Class is the classification of the target |  |  |
| `type` _string_ | Type is the language type |  |  |
| `vulnerabilities` _[Vulnerability](#vulnerability) array_ | Vulnerabilities found in this target |  |  |


#### SBOM



SBOM represents a Software Bill of Materials of an OCI artifact



_Appears in:_
- [SBOMList](#sbomlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `imageMetadata` _[ImageMetadata](#imagemetadata)_ |  |  |  |
| `spdx` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_ | SPDX contains the SPDX document of the SBOM in JSON format |  |  |




#### ScanStatus

_Underlying type:_ _string_

ScanStatus represents the status of a container's vulnerability scan.



_Appears in:_
- [ContainerStatus](#containerstatus)

| Field | Description |
| --- | --- |
| `WaitingForScan` | ScanStatusWaitingForScan indicates no Image record exists for this container's image.<br /> |
| `ScanInProgress` | ScanStatusScanInProgress indicates the Image exists but not all platforms have been scanned.<br /> |
| `ScanComplete` | ScanStatusScanComplete indicates all platforms have vulnerability reports.<br /> |


#### Summary



Summary provides a high-level overview of the vulnerabilities found.



_Appears in:_
- [Report](#report)
- [WorkloadScanReport](#workloadscanreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `critical` _integer_ | Critical vulnerabilities count |  |  |
| `high` _integer_ | High vulnerabilities count |  |  |
| `medium` _integer_ | Medium vulnerabilities count |  |  |
| `low` _integer_ | Low vulnerabilities count |  |  |
| `unknown` _integer_ | Unknown vulnerabilities count |  |  |
| `suppressed` _integer_ | Suppressed vulnerabilities count |  |  |


#### VEXStatus



VEXStatus represents the status of a vulnerability as declared
in a VEX document



_Appears in:_
- [Vulnerability](#vulnerability)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `repository` _string_ | Repository providing the VEX document |  |  |
| `status` _string_ | VEX status (e.g., "not_affected", "fixed", "under_investigation") |  |  |
| `statement` _string_ | Statement optionally explain statement from the VEX document |  |  |


#### Vulnerability



Vulnerability contains detailed information about a single vulnerability
found in a package



_Appears in:_
- [Result](#result)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `cve` _string_ | CVE identifier |  |  |
| `title` _string_ | Title is the title of the vulnerability |  |  |
| `packageName` _string_ | PackageName is the name of the vulnerable package<br />(empty when Class is "binary") |  |  |
| `packagePath` _string_ | PackagePath is the path where the package was found<br />(equal to Target when Class is "binary").<br />trivy removes the "/" at the beginning of the path<br />so we have to restore it. |  |  |
| `purl` _string_ | PURL (Package URL) identify the package uniquely |  |  |
| `installedVersion` _string_ | InstalledVersion of the package that was found |  |  |
| `fixedVersions` _string array_ | FixedVersions is the list of versions where the vulnerability is fixed |  |  |
| `diffID` _string_ | DiffID of the image layer where the vulnerability was introduced |  |  |
| `description` _string_ | Description of the vulnerability |  |  |
| `severity` _string_ | Severity rating (e.g., "HIGH", "MEDIUM") |  |  |
| `severitySource` _string_ | SeveritySource identifies the vendor that produced the Severity<br />(e.g. "nvd", "ghsa", "redhat", "alpine").<br />Consumers can use this key to look up the matching entry in the CVSS map to display alongside Severity.<br />May be empty when the source vendor is not known. |  |  |
| `references` _string array_ | References contains URLs for more information |  |  |
| `cvss` _object (keys:string, values:[CVSS](#cvss))_ | CVSS scoring details |  |  |
| `cwes` _string array_ | CWEs with which the CVE is classified |  |  |
| `suppressed` _boolean_ | Suppressed identify when vulnerability has<br />been suppressed by VEX documents |  |  |
| `vexStatus` _[VEXStatus](#vexstatus)_ | VEXStatus information |  |  |


#### VulnerabilityReport



VulnerabilityReport is the Schema for the scanresults API



_Appears in:_
- [VulnerabilityReportList](#vulnerabilityreportlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `imageMetadata` _[ImageMetadata](#imagemetadata)_ | ImageMetadata contains info about the scanned image |  |  |
| `report` _[Report](#report)_ | Report is the actual vulnerability scan report |  |  |




#### WorkloadScanReport



WorkloadScanReport represents the vulnerability scan results for a workload's containers.



_Appears in:_
- [WorkloadScanReportList](#workloadscanreportlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[WorkloadScanReportSpec](#workloadscanreportspec)_ | Spec contains the workload container references, written by the reconciler. |  |  |
| `status` _[WorkloadScanReportStatus](#workloadscanreportstatus)_ | Status contains the scan status for each container.<br />Populated at read time. |  | Optional: \{\} <br /> |
| `summary` _[Summary](#summary)_ | Summary provides aggregated vulnerability counts across all containers.<br />Vulnerabilities are deduplicated per container (same CVE across platforms counts as 1),<br />then summed across all containers.<br />Populated at read time. |  | Optional: \{\} <br /> |
| `containers` _[ContainerResult](#containerresult) array_ | Containers contains the vulnerability reports for each container.<br />Populated at read time by joining with VulnerabilityReport data. |  | Optional: \{\} <br /> |




#### WorkloadScanReportSpec



WorkloadScanReportSpec defines the containers to scan.



_Appears in:_
- [WorkloadScanReport](#workloadscanreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `containers` _[ContainerRef](#containerref) array_ | Containers contains the list of containers in the workload with their image references. |  |  |


#### WorkloadScanReportStatus



WorkloadScanReportStatus contains the observed scan state for the workload.



_Appears in:_
- [WorkloadScanReport](#workloadscanreport)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `containerStatuses` _[ContainerStatus](#containerstatus) array_ | ContainerStatuses contains the scan status for each container. |  | Optional: \{\} <br /> |


#### WorkloadScanVulnerabilityReport



WorkloadScanVulnerabilityReport contains vulnerability report data for a specific platform.



_Appears in:_
- [ContainerResult](#containerresult)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the VulnerabilityReport. |  |  |
| `namespace` _string_ | Namespace is the namespace where the VulnerabilityReport is stored. |  |  |
| `imageMetadata` _[ImageMetadata](#imagemetadata)_ | ImageMetadata contains the VulnerabilityReport's image metadata. |  |  |
| `report` _[Report](#report)_ | Report is the actual vulnerability scan report. |  |  |


