# Air Gap Support

SBOMscanner can be used in air-gapped environments.

To run the scans, SBOMscanner currently needs the following external sources:

* Vulnerability Database

* Java Vulnerability Database

* VEX Hub (optional)

These external sources can be self-hosted in your private infrastucture to make the whole environment air-gapped.

## Self-Hosting Vulnerability Databases

The following Vulnerability Databases are packaged as OCI images, allowing you to host them in your own registry:

* [`trivy-db`](https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db)

* [`trivy-java-db`](https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db)

Once mirrored in your own OCI registry, you can install SBOMscanner to point to them:

```shell
helm install sbomscanner ./chart \
    --set worker.trivyDBRepository="yourlocalregistry.example/sbomscanner/trivy-db" \
    --set worker.trivyJavaDBRepository="yourlocalregistry.example/sbomscanner/trivy-java-db"
```

## Self-Hosting VEX Hub

To setup your own VEX Hub repository, please refer to this [guide](https://github.com/aquasecurity/trivy/blob/main/docs/docs/advanced/self-hosting.md#make-a-local-copy-1).

Change the `repository_url` (if any) within the VEX files, to point to the internal registries.

All you need to do is to setup an HTTP server to provide the needed files for VEX.

By default, SBOMscanner seeds two `VEXHub` resources pointing to the public
`github.com/rancher/vexhub` and `github.com/aquasecurity/vexhub` repositories,
which are unreachable in an air-gapped environment. Disable this seeding at
install time by setting `controller.defaultVEXHubResources` to `false`:

```shell
helm install sbomscanner ./chart \
    --set controller.defaultVEXHubResources=false
```

To configure a VEX Hub in SBOMscanner, create a `VEXHub` resource with your local repository URL and apply it:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: VEXHub
metadata:
  name: local_vexhub
spec:
  url: "https://yourlocalrepo.example/"
  enabled: true
```
