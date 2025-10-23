# Collecting logs for debugging

## Install dependencies

Please follow the instructions in the [quickstart guide](../installation/quickstart.md#requirements) to ensure you have the necessary dependencies installed.

## Install or upgrade an existing installation with debug logging activated

```bash
helm repo add kubewarden https://charts.kubewarden.io
helm repo update
helm upgrade --install sbomscanner kubewarden/sbomscanner \
  --set=controller.logLevel=debug \
  --set=storage.logLevel=debug \
  --set=worker.logLevel=debug \
  --namespace sbomscanner \
  --create-namespace \
  --wait
```

## Verify installation

Check the version. It should match the latest `sbomscanner-chart-*` version found in the [releases](https://github.com/kubewarden/sbomscanner/releases) page.

```bash
helm list
```

Wait for pods to be running:

```bash
kubectl get pods
```

## Collect the logs

> **Warning:** ⚠️ Troubleshooting logs do not contain sensitive data such as Secrets,
> but they may include container registry names and URIs. Review the tarball contents
> before sharing to ensure no sensitive information is disclosed.

Using [the script found in the sbomscanner repository](https://github.com/kubewarden/sbomscanner/blob/main/hack/sbombscanner-debug.sh):

```bash
./hack/sbomscanner-debug.sh collect --compress-results
```

The script collects the following information:

- Logs from the pods of all SBOMscanner components (controller, workers, storage, NATS).
- Manifest of all SBOMscanner related resources (Registry, VEXHub, ScanJob, Image, VulnerabilityReport).

The script prints the names of the manifests being collected at runtime.

Upload the generated tar.gz file.
