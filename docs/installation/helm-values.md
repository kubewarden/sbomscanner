# Helm Values Configuration

This document describes the available configuration options for the SBOMscanner Helm chart.

You can customize these values in two ways:

1. Create a custom values file (e.g., `my-values.yaml`) with your overrides and pass it to Helm:
```bash
helm install sbomscanner ./chart -f my-values.yaml
```

2. Use `--set` flags to override specific values directly:
```bash
helm install sbomscanner ./chart --set controller.replicas=5 --set storage.postgres.cnpg.instances=5
```

For more details on customizing Helm charts, see the [Helm documentation](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing).

## Log Levels
You can configure the log level for each SBOMscanner component to control the verbosity of the logs.

```yaml
controller:
  logLevel: "info"

storage:
  logLevel: "info"

worker:
  logLevel: "info"
```

Available log levels are: `debug`, `info`, `warn`, `error`.

## Resource Limits and Requests
Each component has default resource limits and requests that you can customize based on your cluster's capacity and workload requirements.

### Controller
```yaml
controller:
  resources:
    limits:
      cpu: 500m
      memory: 2Gi
    requests:
      cpu: 250m
      memory: 300Mi
```

### Storage
```yaml
storage:
  resources:
    limits:
      cpu: 500m
      memory: 3Gi
    requests:
      cpu: 250m
      memory: 300Mi
```

### Worker
```yaml
worker:
  resources:
    limits:
      cpu: 500m
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 300Mi
```

Adjust these values based on your workload. The storage component typically needs more memory due to SBOM processing.

For more information on resource management, see the [Kubernetes documentation on resource requests and limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

## PostgreSQL Configuration
SBOMscanner requires a PostgreSQL database to store SBOM data. You have two options: use the built-in [CloudNativePG (CNPG) operator](https://cloudnative-pg.io/) or connect to an external PostgreSQL instance.

### Using CloudNativePG (Default)
By default, SBOMscanner deploys a PostgreSQL cluster using the CloudNativePG operator. This is the easiest way to get started.

```yaml
storage:
  postgres:
    cnpg:
      enabled: true
      instances: 3
      imageName: ""
      storage:
        size: 1Gi
        resizeInUseVolumes: true
        storageClass: ""
        pvcTemplate: {}
```

**Configuration options:**
- `instances`: Number of PostgreSQL replicas (default: 3)
- `imageName`: Full image reference for the PostgreSQL container (e.g. `my-registry.example.com/postgresql:18.1`). Useful for air-gapped environments where the default CNPG operand image is not reachable. If empty, CNPG uses its default operand image.
- `storage.size`: Size of the persistent volume. You can increase this value later, and changes will be automatically applied to existing PVCs. Size cannot be decreased. See the [CNPG documentation](https://cloudnative-pg.io/documentation/current/storage/#volume-expansion) for more details.
- `storage.resizeInUseVolumes`: Automatically resize PVCs (default: true)
- `storage.storageClass`: Specify a storage class. If empty, uses the cluster's default storage class.
- `storage.pvcTemplate`: Custom PVC template if you need advanced configuration

For more configuration options, refer to the [CloudNativePG Cluster configuration documentation](https://cloudnative-pg.io/documentation/current/cloudnative-pg.v1/#postgresql-cnpg-io-v1-ClusterSpec).

### Using an External PostgreSQL Instance
If you already have a PostgreSQL instance or prefer to manage it separately, disable CNPG and provide connection details.

```yaml
storage:
  postgres:
    cnpg:
      enabled: false
    authSecretName: "my-postgres-credentials"
    caSecretName: "my-postgres-ca"
```

**Steps to configure external PostgreSQL:**

1. Create a `Secret` with the PostgreSQL connection URI:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-postgres-credentials
  namespace: default
stringData:
  uri: "postgresql://user:password@postgres.example.com:5432/sbomscanner?sslmode=require"
```

The URI format follows the [PostgreSQL connection URI specification](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS). 

> **Note:** Any `sslmode` or other `ssl*` parameters in the URI are ignored.  
> SBOMBastic always enforces CA verification when connecting to the database,  
> using the CA certificate specified in the `caSecretName` secret.

2. Create a `Secret` with the CA certificate used to verify the PostgreSQL server certificate:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-postgres-ca
  namespace: default
stringData:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

3. Reference the secrets in your Helm values:
```yaml
storage:
  postgres:
    authSecretName: "my-postgres-credentials"
    caSecretName: "my-postgres-ca"
```

**Please note:** When using an external PostgreSQL instance, make sure the database is already created and accessible from your Kubernetes cluster.
