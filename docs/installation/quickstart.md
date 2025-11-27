# SBOMscanner Quick Start

Welcome to the SBOMscanner Quick Start!

This guide will walk you through the following steps:

- Deploying the SBOMscanner stack in a Kubernetes cluster
- Running an automated image scan using a `Registry` custom resource

---

## Requirements

Before deployment, you need to prepare the following:

- A Kubernetes cluster (you can simply run a [kind](https://kind.sigs.k8s.io/) cluster)
- A [default Storage Class](https://kubernetes.io/docs/concepts/storage/storage-classes/#default-storageclass) defined inside of the cluster
- `helm` installed locally
- `kubectl` installed locally
- `cert-manager` installed in the cluster
- `CloudNativePG` installed in the cluster

### Install cert-manager

To install cert-manager, you can run the following commands:

```bash
helm repo add jetstack https://charts.jetstack.io

helm repo update

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --wait
```

> For more information on configuring cert-manager, please visit the [cert-manager documentation](https://cert-manager.io/docs/installation/helm)

---

### Install CloudNativePG

To install CloudNativePG, you can run the following commands:

```bash
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm repo update
helm install cnpg \
  --namespace cnpg-system \
  --create-namespace \
  --wait \
  cnpg/cloudnative-pg
```

To customize the CloudNativePG installation, refer to [Using CloudNativePG (Recommended)](helm-values.md#using-cloudnativepg-recommended) in the Helm values documentation.
You can also bring your own PostgreSQL instance instead of using CloudNativePG. See [Using an External PostgreSQL Instance](helm-values.md#using-an-external-postgresql-instance) for configuration details.

## Deploy SBOMscanner

Follow these simple steps from your local machine to get SBOMscanner up and running:

### Install the Helm chart

```bash
helm repo add kubewarden https://charts.kubewarden.io
helm repo update
helm install sbomscanner kubewarden/sbomscanner \
  --namespace sbomscanner \
  --create-namespace \
  --wait
```

> **TIP:**
>
> By default, the installation of SBOMscanner is configured to be highly available.
> If you want to save on resources, you can reduce the number of replicas to the minimum:
>
> ```bash
> helm install sbomscanner kubewarden/sbomscanner \
>   --namespace sbomscanner \
>   --create-namespace \
>   --set controller.replicas=1 \
>   --set storage.replicas=1 \
>   --set storage.postgres.cnpg.instances=1 \
>   --set worker.replicas=1 \
>   --wait
> ```
>
> This configuration is suitable for development environments where high availability is not required.

### Verify the Deployment

After installation, ensure all pods are running:

```bash
kubectl get pods -n sbomscanner
```

Example output:

```bash
sbomscanner           sbomscanner-controller-7f568c88dc-bmjgs       1/1     Running
sbomscanner           sbomscanner-controller-7f568c88dc-gcgbn       1/1     Running
sbomscanner           sbomscanner-controller-7f568c88dc-q7hbh       1/1     Running
sbomscanner           sbomscanner-nats-0                            2/2     Running
sbomscanner           sbomscanner-nats-1                            2/2     Running
sbomscanner           sbomscanner-nats-2                            2/2     Running
sbomscanner           sbomscanner-storage-5f596cd8f8-4t7z8          1/1     Running
sbomscanner           sbomscanner-worker-d9d68c5c-5dtck             1/1     Running
sbomscanner           sbomscanner-worker-d9d68c5c-qcp7n             1/1     Running
sbomscanner           sbomscanner-worker-d9d68c5c-tlpgm             1/1     Running
```

### Summary

At this point, your SBOMBastic deployment is up and running successfully. You're now ready to begin scanning images and generating reports!

---

## Run a Scan

In this section, you'll learn how to create a registry source and trigger an automated scan.

### Prepare a `registry.yaml` file

Before running a scan, you need to define a `Registry` custom resource for SBOMscanner to fetch images.

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: test-registry
  namespace: default
spec:
  uri: ghcr.io
  repositories:
    - name: kubewarden/sbomscanner/test-assets/golang
```

### Create the Registry CR

```bash
kubectl apply -f registry.yaml
```

### Prepare a `scan-job.yaml`

The `ScanJob` CR tells SBOMscanner which registry to scan.

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: ScanJob
metadata:
  name: test-scanjob
  namespace: default
spec:
  registry: test-registry
```

### Create a ScanJob CR

```bash
kubectl apply -f scanjob.yaml
```

### Wait for Results

Once the scan completes, check the generated SBOMs and vulnerability reports:

```bash
kubectl get sbom -n default
kubectl get vulnerabilityreport -n default
```

You should see output like:

```bash
NAME                                                               CREATED AT
2ca3e0b033d523509544cb6f31c626af2a710d7dbcc15cb9dffced2e4634d69b   2025-06-10T10:26:38Z
...
```

### Summary

You've successfully created a real-world Registry resource and triggered an automated scan.

You can jump to the [Querying reports](../user-guide/querying-reports.md) guide to learn how to query and inspect the generated images, SBOMs, and vulnerability reports.
