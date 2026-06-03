# Common problems

This page documents common errors users may encounter while running SBOMscanner,
and how to address them.

## Docker Hub pull rate limit reached

### Problem

Scans end up in an error state with a message similar to:

```
You have reached your unauthenticated pull rate limit
```

This happens because anonymous image pulls from [Docker Hub](https://hub.docker.com/)
(`docker.io`) are subject to rate limiting. Once the limit is hit, further
pulls are rejected until the window resets.

See the official Docker documentation for full details:

- [Docker Hub usage and limits](https://docs.docker.com/docker-hub/usage/)
- [Docker Hub pull rate limits](https://docs.docker.com/docker-hub/usage/pulls/)
- [Download rate limit overview](https://www.docker.com/increase-rate-limits/)

### Solution

Authenticate against Docker Hub so that pulls count against your account's
higher limits, instead of the shared anonymous quota. Refer to Docker's
documentation for the available options:

- [Authenticate to increase your pull rate limit](https://docs.docker.com/docker-hub/usage/#authenticate-to-increase-your-pull-rate-limit)
- [Subscriptions and higher limits](https://docs.docker.com/subscription/)

Once you have credentials, configure SBOMscanner to use them by creating a
`kubernetes.io/dockerconfigjson` Secret in the SBOMscanner installation
namespace and referencing it from the relevant `Registry` resource (or from
the `authSecret` field of a `WorkloadScanConfiguration` to propagate the
credentials to all managed registries). The full procedure — including the
exact `kubectl create secret docker-registry` invocation and the `Registry`
spec — is documented in [Private Registries](../user-guide/private-registries.md).
