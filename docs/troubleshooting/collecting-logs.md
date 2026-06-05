# Collecting logs for debugging

## Install dependencies

Please follow the instructions in the [quickstart guide](../installation/quickstart.md#requirements) to ensure you have the necessary dependencies installed.

The `sbomscanner-debug.sh` script additionally requires:

- `kubectl` configured against the target cluster
- `helm` v3
- `jq`
- `tar` (only if you use `--compress-results`)

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

The verify subcommand auto-discovers the SBOMscanner Helm release in any namespace and reports the chart, version and pod status.
You do not need to specify the namespace or the release name.

```bash
./hack/sbomscanner-debug.sh verify
```

Example output:

```
== Helm release ==
  ✅ Found SBOMscanner Helm release
  Release name       sbomscanner
  Namespace          sbomscanner
  Chart              sbomscanner-0.2.0
  App version        v0.2.0

== Deployments ==
  ✅ deployment 'sbomscanner-controller' running, all pods ready.
  ✅ deployment 'sbomscanner-worker' running, all pods ready.
  ✅ deployment 'sbomscanner-storage' running, all pods ready.

== StatefulSets ==
  ✅ statefulset 'sbomscanner-nats' running, all pods ready.
────────────────────────────────────────────────────────────────────
✅ Verification passed.
```

If your release lives in a non-standard namespace and discovery fails, you can still pin it explicitly:

```bash
./hack/sbomscanner-debug.sh verify --namespace <ns>
```

## Collect the logs

> **Warning:** ⚠️ The bundle may contain sensitive data.
> Pod logs include container registry names and URIs, and by default the
> bundle also includes the rendered Helm values and manifest, which can
> contain credentials depending on how the chart was configured (for
> example image pull secrets, registry auth, or any value passed via
> `--set`). Review the bundle contents before sharing.

Using [the script found in the sbomscanner repository](https://github.com/kubewarden/sbomscanner/blob/main/hack/sbomscanner-debug.sh):

```bash
./hack/sbomscanner-debug.sh collect --compress-results
```

By default the script collects:

- Logs from the pods of all SBOMscanner components (controller, workers, storage, NATS), including init containers and previous-container logs for crash-looped pods.
- Logs from the CloudNativePG cluster pods running in the SBOMscanner namespace.
- Helm release metadata (`values`, rendered `manifest`, history).

### Optional flags

| Flag                    | Purpose                                                                                                                                                                                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--namespace <ns>`      | Force a specific install namespace (otherwise auto-discovered)                                                                                                                                                                                                                                                                             |
| `--cnpg-namespace <ns>` | Also collect logs from the CNPG operator in that namespace (e.g. `cnpg-system`)                                                                                                                                                                                                                                                            |
| `--manifests`           | Also dump every SBOMscanner CR (cluster-scoped `VEXHub` and `WorkloadScanConfiguration`; namespaced `Registry`, `ScanJob`, `Image`, `VulnerabilityReport`, `WorkloadScanReport` collected cluster-wide), plus CNPG `Cluster`/`Pooler`/`Backup`/`ScheduledBackup` CRs, events and `kubectl describe` for every pod in the install namespace |
| `--output-dir <dir>`    | Write the bundle to `<dir>` instead of the current directory                                                                                                                                                                                                                                                                               |
| `--compress-results`    | Tar+gzip the bundle into a single `.tar.gz`                                                                                                                                                                                                                                                                                                |

### Examples

Minimal bundle (pod logs + helm metadata) in the current directory:

```bash
./hack/sbomscanner-debug.sh collect --compress-results
```

Full bundle (everything above plus CRs/events/describe) into `/tmp`:

```bash
./hack/sbomscanner-debug.sh collect \
  --cnpg-namespace cnpg-system \
  --manifests \
  --output-dir /tmp \
  --compress-results
```

The script prints the names of the manifests being collected at runtime and the final path of the bundle (or compressed tarball).

Upload the generated tar.gz file.
