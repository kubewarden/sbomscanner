# SBOMscanner Uninstall

You can remove the resources created by uninstalling the `helm` chart as follows:

```bash
helm uninstall --namespace sbomscanner sbomscanner
```

Then remove the following Custom Resource Definitions, this will also delete
all the resources of these types declared inside of the cluster:

```bash
kubectl delete crd vexhubs.sbomscanner.kubewarden.io
kubectl delete crd scanjobs.sbomscanner.kubewarden.io
kubectl delete crd registries.sbomscanner.kubewarden.io
kubectl delete crd workloadscanconfigurations.sbomscanner.kubewarden.io
```

Finally, delete the namespace where SBOMscanner was deployed:

```bash
kubectl delete ns sbomscanner
```

This will remove the Persistent Volume Claims and their associated
Persistent Volumes.
