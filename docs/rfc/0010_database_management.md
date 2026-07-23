|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Database Management             |
| Start Date   | July 16th, 2026                 |
| Category     | Architecture                    |
| RFC PR       | [fill this in after opening PR] |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

<!---
Brief (one-paragraph) explanation of the feature.
--->

Define the architecture for the SBOMScanner database management system: a mechanism to
distribute auxiliary data (e.g. KEV, EPSS) to SBOMScanner workers by packaging it as an
OCI artifact. A dedicated CLI builds and pushes the artifact, a CI pipeline rebuilds and
publishes it on a fixed schedule, and the worker component pulls it from a remote registry
and keeps a local copy up to date. The design is data-type agnostic (JSON, CSV, etc.) and
optimized for deduplication and low network overhead.

# Motivation

[motivation]: #motivation

<!---
- Why are we doing this?
- What use cases does it support?
- What is the expected outcome?
--->

SBOMScanner produces SBOMs and vulnerability reports, but a vulnerability's raw presence is
not enough to drive remediation. Additional context is needed to prioritize and assess risk,
for example:

* **KEV** (Known Exploited Vulnerabilities): whether a CVE is actively exploited in the wild.
* **EPSS** (Exploit Prediction Scoring System): the probability that a CVE will be exploited.

KEV and EPSS are only examples. Over time SBOMScanner will need to consume many different
auxiliary datasets, in different formats, updated at different cadences. We need a single,
uniform way to:

* package heterogeneous data files into one distributable unit,
* keep that unit fresh without requiring a new SBOMScanner release,
* deliver it to every worker efficiently, transferring only what actually changed, and
* let each worker decide, cheaply, whether it already has the latest data.

The expected outcome is a self-contained, versionless OCI artifact that CI keeps up to date
and that workers pull on demand, decoupling data updates from the SBOMScanner release cycle.

## Examples / User Stories

[examples]: #examples

<!---
Examples of how the feature will be used.
--->

### User story #1

As a maintainer, I want data files (KEV, EPSS, …) to be packaged and published automatically
on a schedule, so that SBOMScanner always has access to fresh data without a new release.

### User story #2

As a SBOMScanner operator, I want the worker to fetch auxiliary data automatically and only
when it is actually stale, so that I do not waste network bandwidth or registry pulls.

### User story #3

As a developer, I want to add a new data source to the database with minimal effort, so that
enriching scan results with new context is a low-friction operation.

### User story #4

As a SBOMScanner operator, I want the ability to enrich scan results with auxiliary data
(KEV, EPSS, …) when it is available, but I do not want a failed pull to block scans,
so that I can continue to operate even if the registry is temporarily unavailable.

# Detailed design

[design]: #detailed-design

<!---
This is the bulk of the RFC.
--->

## Overview

The database is distributed as a single **OCI artifact** stored in a remote registry. The
system has three moving parts:

1. **CLI**: a standalone tool (`sbomscannerdb`) that builds the OCI artifact from a set of
   data files, pushes it to the registry, and can pull/inspect it.
2. **CI pipeline**: runs the CLI on a fixed interval to rebuild the artifact with the latest
   data and push it to a well-known, unversioned tag.
3. **Worker integration**: new code in the SBOMScanner worker that pulls the artifact,
   stores it locally, and checks whether a newer version is available when a scan runs.

```
   ┌──────────────┐    build/push    ┌───────────────────┐    pull    ┌─────────────────┐
   │  CI pipeline │ ───────────────▶ │  Remote registry  │ ─────────▶ │ SBOMScanner     │
   │  (CLI)       │   (daily/…)      │  (single tag)     │            │ worker (local)  │
   └──────────────┘                  └───────────────────┘            └─────────────────┘
```

## OCI artifact structure

Each data file becomes its **own layer** in the OCI artifact. A layer contains exactly one
file. This layout is deliberate and gives us two properties:

* **Deduplication**: layers are content-addressed by digest. If a file is unchanged between
  two builds, its layer digest is identical and the registry (and the worker) reuse the
  existing blob instead of storing/transferring it again.
* **Minimal transfer**: when the worker pulls an updated artifact, only the layers whose
  digests changed are downloaded. Unchanged files cost nothing on the wire.

Before being added to the artifact, every data file is **packed and compressed as `tar.gz`**,
independently of its input format. Whether the source is JSON, CSV, or anything else, the file
is first archived and gzipped (e.g. `kev.json` becomes `kev.tar.gz`) and that `tar.gz` is what
becomes the layer blob. This gives a uniform packaging step for all data types and reduces the
on-the-wire and at-rest size of each layer.

Using `tar` (and not just `gzip`) is a deliberate design decision: a database is not necessarily
a single file. When a data source is made up of multiple files, `tar` lets us bundle them into
one archive so that a layer always maps to exactly **one** `tar.gz` blob. This keeps the
one-layer-per-database model uniform regardless of how many files a given database contains.

The `tar.gz` is built **reproducibly**: owner/group, timestamps, and any other environment-
dependent metadata are normalized (zeroed/fixed) so that the same input file always produces a
byte-identical archive. This is what makes the layer digest stable across rebuilds: without it,
a metadata change alone would alter the digest and defeat the content-addressed deduplication
the OCI format gives us. With it, an unchanged data file yields the same digest build after
build, so the registry and workers reuse the existing blob instead of re-transferring it.

Each layer carries a media type that records the file's format so the worker knows how to
handle it, e.g.:

```
application/vnd.sbomscanner.db.file.v1.json+gzip   # KEV feed  (kev.json  -> kev.tar.gz)
application/vnd.sbomscanner.db.file.v1.csv+gzip    # EPSS feed (epss.csv -> epss.tar.gz)
```

The media type still records the underlying file format so the worker knows how to parse the
file after decompressing the layer; the `+gzip` suffix reflects the `tar.gz` packaging.

The artifact is **format-agnostic**: adding a new data type is a matter of adding a file and
declaring its media type; no structural change to the artifact is required.

Adding a new file to the artifact is **backward-compatible**: on the next pull the new layer
simply appears in the worker's cache directory, but the worker just ignores files unknown to it.
The new data is therefore not consumed until SBOMScanner is updated with support for that format, 
so publishing a new file never breaks existing workers.

### Update annotations

The artifact manifest carries OCI annotations that describe its update window:

```
org.opencontainers.image.lastUpdate=2024-06-01T00:00:00Z
org.opencontainers.image.nextUpdate=2024-06-02T00:00:00Z
```

* `lastUpdate`: when the artifact was last rebuilt and pushed.
* `nextUpdate`: when the next rebuild is expected.

These annotations serve two purposes:

1. **Cheap staleness check for the worker.** The worker persists `nextUpdate` locally from
   its last pull, so the common-case check requires no registry contact at all: it compares
   the cached `nextUpdate` against the current time and, while `now < nextUpdate`, serves the
   scan straight from the local cache. Only once `now >= nextUpdate` does the worker reach out
   to the registry, first reading the manifest annotations (a small metadata request, not a
   full blob pull) to confirm a newer artifact exists, then pulling the changed layers. This
   keeps the registry off the critical path for the vast majority of scans.
2. **Driving the update cadence.** `nextUpdate` is computed from the shortest update interval
   among all bundled files. If any file's cadence changes (e.g. a feed moves from weekly to
   daily), `nextUpdate` adjusts automatically, and both CI and workers follow the new schedule
   without code changes.

### Versionless, single-tag distribution

The artifact is **not versioned**. Every rebuild pushes to the **same tag** in the registry
(e.g. `registry.example.com/sbomscanner/sbomscannerdb:latest`). SBOMScanner always pulls that one tag,
so there is no version negotiation, no version pinning, and no cleanup of stale versions to
manage. Freshness is expressed entirely through the annotations and layer digests, not
through tags.

This follows the same approach used by Trivy with their vulnerability database: https://github.com/aquasecurity/trivy-db

## Rebuild cadence

CI rebuilds and pushes the artifact on a fixed interval. The interval is the **shortest**
update cadence among all bundled files: if file A updates every 2–3 days and file B updates
daily, the artifact must be rebuilt daily so that B's updates are never delayed. Thanks to
layer deduplication, rebuilding daily is cheap even when most files are unchanged, only the
files that actually changed produce new layers and get transferred.

## Worker integration

The worker stores the OCI artifact **locally**, so that lookups against the data (e.g.
"is CVE-X in KEV?", "what is CVE-X's EPSS score?") are served from disk.

The worker is responsible for:

* **Initial pull**: on startup, pulling the artifact and unpacking its layers (decompressing
  each `tar.gz` layer back to its original file) to local storage.
* **Scan-triggered freshness check**: the worker verifies freshness only when a new scan is
  requested. It reads `nextUpdate` from the **locally cached manifest** (the manifest of the
  last pulled artifact) and compares it against the current time. While `now < nextUpdate` the
  worker uses the current local artifact content and does not contact the registry at all. Only
  when `now >= nextUpdate`, meaning a newer artifact is expected to have been released, does
  the worker pull the updated artifact from the registry before proceeding with the scan. There
  is no background timer; freshness is evaluated lazily at scan time, so registry activity is
  driven by actual scan demand.
* **Local management**: maintaining a persistent, content-addressed cache directory across
  pulls, so unchanged blobs are reused and only changed layers are fetched.

## Scan Workflow

1. CI rebuilds the OCI artifact with the latest data files, sets `lastUpdate`/`nextUpdate`,
   and pushes it to the single tag.
2. When a new scan is requested, the worker reads `nextUpdate` from its locally cached
   manifest and compares it against the current time.
3. If `now < nextUpdate`, the current local artifact is still considered fresh and the worker
   uses it as-is. If `now >= nextUpdate`, a newer artifact is expected, so the worker pulls the
   updated artifact from the registry before the scan, downloading only the changed layers.
4. The worker unpacks the layers, decompressing each `tar.gz` back to its original file, into
   its local cache directory.
5. During a scan, the worker enriches results using the locally stored data (KEV, EPSS, …)
   with no additional network requests.

The enrichment data is **not mandatory** to produce a vulnerability report: the files bundled
in the OCI artifact add context (KEV, EPSS, …) on top of results the worker can produce on its
own. A pull failure therefore never blocks a scan:

* **Pull fails, local cache present**: the worker proceeds with the stale local cache and logs
  the registry download failure. The scan completes with the previously available enrichment
  data.
* **Pull fails, no local cache (first run ever)**: the worker proceeds without any enrichment
  data and logs the registry download failure. The scan still completes; it simply produces an
  unenriched report.

## Signing and verification

Because the artifact is published to a mutable, versionless tag rather than pinned by digest,
a worker cannot rely on the reference alone to prove the data it pulled came from CI and was
not tampered with. To close that gap, CI signs the artifact after every rebuild and the worker
verifies the signature before consuming any data. The intended mechanism is `cosign`, which
stores the signature as an OCI referrer alongside the artifact on the same tag, so signing adds
no new distribution channel and composes with the single-tag model described above.

On the worker side, verification is a mandatory step that runs before layers are unpacked into
the local cache. If verification fails, the worker refuses to consume the pulled artifact and
keeps serving the last known-good local cache, mirroring the pull-failure behavior above: a
compromised or unverifiable update degrades to stale-but-trusted data rather than blocking
scans. The trust policy is configured on the SBOMScanner CRD — either an identity and issuer
for keyless signing, or a reference to a public-key `Secret` for key-pair signing.

# Implementation Details

## CLI (`sbomscannerdb`)

A new standalone CLI, distinct from the SBOMScanner/worker binary, used primarily by CI to
build and publish, and available for local inspection and debugging. Proposed commands:

* `sbomscannerdb build`: assemble the OCI artifact from a directory/manifest of data files,
  packing and gzipping each file as `tar.gz` (one layer per file), assigning media types by
  format and computing the freshness annotations.
* `sbomscannerdb push`: push the built artifact to the configured registry/tag.
* `sbomscannerdb pull`: pull the artifact (used by tooling and for verification).
* `sbomscannerdb inspect`: print the manifest, layers, media types, and annotations.

Keeping this as a separate tool avoids coupling the data-publishing lifecycle to the
SBOMScanner runtime binary and keeps CI's dependency surface small.

The CLI should build the artifact using an OCI artifact library (e.g. ORAS or an
equivalent go-containerregistry-based flow) so that the layer-per-file, annotation, and
content-addressing behavior comes for free from the OCI spec.

## CI pipeline

A scheduled pipeline that:

1. Fetches/refreshes each data source into its file form.
2. Runs `sbomscannerdb build` to produce the artifact (deduplicating unchanged layers).
3. Runs `sbomscannerdb push` to the single tag.
4. Sets `lastUpdate` to the build time and `nextUpdate` based on the shortest source cadence.

The schedule (e.g. daily) is driven by the shortest update interval among the bundled files.

## Worker code

New code in the worker to:

* Configure the registry reference (tag) and local cache directory path.
* Perform the initial pull on startup and unpack layers by media type.
* On each incoming scan, read `nextUpdate` from the locally cached manifest and pull a new
  artifact only when `now >= nextUpdate`; otherwise use the current local content unchanged.
* Expose an internal lookup interface over the locally stored data for use during scans.
* For each new data file, add a new adapter implementation that knows how to parse the file 
  format (eg. KEV adapter, EPSS adapter) and provide a uniform lookup API to the worker.

# Drawbacks

[drawbacks]: #drawbacks

<!---
Why should we **not** do this?
--->

* **Registry dependency.** Workers depend on reachability of the remote registry to stay
  fresh. If the registry is unavailable, workers continue with their last local copy, which
  may become stale.
* **Trust and provenance.** The worker consumes data built by CI; the artifact should be
  signed/verified to avoid consuming tampered data. This adds operational overhead.
* **Single-tag semantics.** Because the artifact is unversioned and always pushed to the same
  tag, there is no built-in rollback to a previous known-good dataset if a bad build is
  published; recovery means republishing a corrected artifact.

# Alternatives

[alternatives]: #alternatives

<!---
- What other designs/options have been considered?
- What is the impact of not doing this?
--->

* **Fetch each data source directly from its upstream at scan time.** Removes the packaging
  layer but introduces per-worker, per-scan network dependencies on many third-party
  endpoints, with no deduplication and inconsistent availability.
* **Versioned/tagged artifacts.** Would allow rollback but adds version negotiation and
  cleanup overhead; rejected in favor of single-tag simplicity plus freshness annotations.

# Future Considerations

[future]: #future-considerations

* **SQLite layers.** Convert each data file into a per-file SQLite database stored in the OCI
  artifact. The worker would then query the database directly rather than parsing raw JSON/CSV,
  improving lookup performance and reducing parsing complexity, while preserving the
  one-file-per-layer deduplication model.
* **Per-database update cadence.** Allow each data source to declare its own update cadence, so that
  the worker can pull only when a given database is expected to have changed, rather than
  rebuilding the entire artifact on the shortest cadence. This would require a more complex
  manifest and per-layer freshness tracking.

