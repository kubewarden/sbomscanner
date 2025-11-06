|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Multi-Scan                      |
| Start Date   | 6 November 2025                 |
| Category     | Architecture                    |
| RFC PR       | [fill this in after opening PR] |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

Support multiple scanning tools.

# Motivation

[motivation]: #motivation

We want to add support for multiple scanning tools (such as grype) in order to enrich the vulnerability reports, making it more complete and accurate.

This will also allow us to be less vendor centric, since we are currently relying only on trivy to generate SBOMs and scan for vulnerabilities.

## Examples / User Stories

[examples]: #examples

### User story 1

As a user, I want to make use of KEV and the EPSS score (which are currently provided by grype) to prioritize vulnerability remediation efforts.

# Detailed design

[design]: #detailed-design

## Scan

For the multiscan feature, we are going to double the following operations:

* sbom generation

* sbom scan

This will let grype to generate its own report, so that we can then compare and merge with the one obtained with trivy.

Since grype and trivy are different tools, we must to take care about their scan processes, synchronizing their flows, to be able to analyze and merge the results.

This will require a synchronization mechanism to allow both of them to generate and scan SBOMs. To achieve this, we must set a timeout for their execution and define a default tool from which to take the results. In this case, we can adopt the following logic to avoid starvation:

```
if trivy fails:
  return error
if grype fails:
  return trivy.result
if trivy succed && grype succed:
  return trivy.result and grype.result
```

## Merge

The second phase, of the multiscan process, is about merging results.

We already have defined our own `VulnerabilityReport` format [here](./0004_vulnerability_report.md). Starting from here, we are going to enrich the struct with information that are exclusively provided by `grype`:

* `kev` is a list of known exploits from the CISA KEV dataset.

* `epss` is a list of Exploit Prediction Scoring System (EPSS) scores for the vulnerability.

# Drawbacks

[drawbacks]: #drawbacks

<!---
Why should we **not** do this?

  * obscure corner cases
  * will it impact performance?
  * what other parts of the product will be affected?
  * will the solution be hard to maintain in the future?
--->

# Alternatives

[alternatives]: #alternatives

<!---
- What other designs/options have been considered?
- What is the impact of not doing this?
--->

# Unresolved questions

[unresolved]: #unresolved-questions

<!---
- What are the unknowns?
- What can happen if Murphy's law holds true?
--->
