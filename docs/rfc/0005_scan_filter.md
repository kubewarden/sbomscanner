|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Scan Filter                     |
| Start Date   | Oct 27th, 2025                  |
| Category     | Architecture                    |
| RFC PR       | [#555](https://github.com/kubewarden/sbomscanner/pull/555) |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

Define a way to filter the images being scanned.

# Motivation

[motivation]: #motivation

The purpose of this RFC is to define a way to filter certain parameters in order to speed up the scan time.
Currently, when defining a Registry, the only way to limit the contents being scanned is to provide a list of repositories. However, all the images found inside these repositories are being scanned. This can lead to scanning a lot of irrelevant images, wasting a lot of time and resources.

We should provide a way to filter the images being scanned.

I would start focusing on two kinds of filters:

* platform: many repositories contain multi-architecture images. A single image could have been built for linux as an OS, but for different architectures (arm64, amd64, s390x, ppc64, and maybe other flavors of arm). For example, as a user running a `x86_64` cluster, I care about scanning only amd64 images since these are the only ones I can run inside of my cluster
* tags: certain repositories do not remove old images. It would be useful to provide a way to scan only the images tagged in a specific way. As a possible solution, we might consider allowing the usage of a CEL expression to determine whether a tag is relevant or not. By using CEL, the end user would be able to use different methods: regular expressions, semantic versioning checks, etc.

## Examples / User Stories

[examples]: #examples

- As a user, I want to scan only `linux/amd64` based images on my registry.
- As a user, I want to scan `linux/amd64` and `linux/arm` based images on my registry.
- As a user, I want to scan only the most recent tags of images on my registry.
- As a user, I want to scan only the most recent tags, `linux/amd64` based images on my registry.

# Detailed design

[design]: #detailed-design

## Platforms

The platform filters will be used to avoid the discovery of image platforms on the registry. This will save us several calls to the registry since to do so, we have to loop over each image found in there and retrieve its details to inspect the platform.

We will provide the user with a new field on the `Registry` CRD called `platforms`. The field will contain the list of platforms allowed.

The `Platoform` type is a structure of 3 elements to describe it with the following elements:

* `os`: specifies the operating system, for example `linux` or `windows`.

* `arch`: specifies the CPU architecture.

* `variant`: is an optional field specifying a variant of the CPU.

Here's an example of `Registry` configured to scan only for `linux/amd64` and `linux/arm/v7` platforms:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-first-registry
  namespace: default
spec:
  uri: dev-registry.default.svc.cluster.local:5000
  platforms:
    - arch: "amd64"
      os: "linux"
    - arch: "arm"
      os: "linux"
      variant: "v7"
```

A `platforms` field not set means that no filters are going to be applied to the scan. This will result in a complete scan with image catalogization.

## Tags

TBD

# Drawbacks

[drawbacks]: #drawbacks

There are no contraindications in developing this feature, since this can sensitively improve performace and does not introduce complexity in the code.

