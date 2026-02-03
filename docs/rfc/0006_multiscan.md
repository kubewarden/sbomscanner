|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Multi-Scan                      |
| Start Date   | 6 November 2025                 |
| Category     | Architecture                    |
| RFC PR       | [fill this in after opening PR] |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

Support grype as an additional tool to scan for SBOMs.

# Motivation

[motivation]: #motivation

We want to add support for `grype` in order to enrich the vulnerability reports, making them more complete and accurate.

This will allow us to be vendor-neutral, since we are currently relying only on `trivy` to generate SBOMs and scan for vulnerabilities.

Additionally, we discovered that `grype` is able to find more vulnerabilities than `trivy`. Below is a recap of our research:

| image | `trivy` | `grype` |
|-------|---------|---------|
| `golang:1.12-alpine` | 45   | 210 |
| `nginx:1.21.0` | 396 | 522 |
| `redis:6.2.0-alpine` | 44 | 127 |
| `postgres:13.0-alpine` | 63 | 151 |

## Examples / User Stories

[examples]: #examples

### User story 1

As a user, I want to make use of KEV and the EPSS score (which are currently provided by grype) to prioritize vulnerability remediation efforts.

# Detailed design

[design]: #detailed-design

For this new feature, we are providing a way to enable it when scanning.

This will impact the `ScanJob` CRD, adding a new boolean field called `multiScan`, set to `false` by default.

To enable it, the `ScanJob` should be set like this:

```yaml
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: ScanJob
metadata:
  name: scanjob-example
  namespace: default
spec:
  registry: example-registry
  multiScan: true
```

## Scan

For the multiscan feature, we are going to double the following operations:

* sbom generation

* sbom scan

This will let `grype` generate its own report, so that we can then compare and merge with the one obtained with trivy.

We can run the tools sequentially (1st trivy, 2nd grype) in case the `multiScan` field is set to `true` in the `ScanJob` CRD.

## Merge

The second phase of the multiscan process is about merging results.

If both the scans succeed, then we can merge them together. We already have defined our own `VulnerabilityReport` format [here](./0004_vulnerability_report.md). Starting from here, we are going to enrich the struct with information that is exclusively provided by `grype`:

* `kev` is a list of known exploits from the CISA KEV dataset.

* `epss` is a list of Exploit Prediction Scoring System (EPSS) scores for the vulnerability.

* `risk` is the score of the risk.

* `licenses` is a list of the licenses used by all the components within the affected software.

In addition to that, we are going to optionally update/overwrite already existing fields retrievied from `trivy`, in case `grype` has better results:

* `cvss` version and scores.

* `references` with additional links.

* `description` if not provided by trivy.

We cannot be sure that both tools will find the same results. For this reason, we have to adopt the following merging strategy:

```
vuln_report
for vuln in trivy.vulnerabilities:
  vuln_report add vuln
  if grype has vuln:
    vuln_report add grype.kev
    vuln_report add grype.epss
    ...
for vuln in grype.vulnerabilities:
  if vuln not in vuln_report:
    vuln_report add vuln
```

# Drawbacks

[drawbacks]: #drawbacks

<!---
Why should we **not** do this?

  * obscure corner cases
  * will it impact performance?
  * what other parts of the product will be affected?
  * will the solution be hard to maintain in the future?
--->

There are no specific concerns about this new feature.

By default, the `multiScan` is not enabled, so the user will not hit performance issues.

When the feature is enabled, an additional scan will run, and consequently, its results will be merged. This shouldn't have a huge impact, but users should keep this in mind when enabling it.

