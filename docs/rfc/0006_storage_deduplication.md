| Field        | Value                                                      |
| :----------- | :--------------------------------------------------------- |
| Feature Name | Storage deduplication                                      |
| Start Date   | 2025-01-18                                                 |
| Category     | Architecture                                               |
| RFC PR       | [#770](https://github.com/kubewarden/sbomscanner/pull/770) |
| State        | **ACCEPTED**                                               |

# Summary

[summary]: #summary

This RFC proposes a storage-level deduplication strategy for `Image`, `SBOM`, and `VulnerabilityReport` resources.
These resources reference container images by their digest, which allows multiple discoveries of the same image to share a single stored artifact.

# Motivation

[motivation]: #motivation

    A container image with the same [digest](https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests) (usually SHA-256) can appear in the system multiple times:

- Across different registries with different tags
- Within the same registry under different tags
- In the same registry with the same tag, but discovered by different users in separate namespaces

The current implementation treats each discovery as an independent resource.
This results in redundant scanning operations and duplicate storage of identical artifacts.

## Examples / User Stories

[examples]: #examples

- As a user I want the system to recognize when the same image (by digest) has already been processed so that I don't waste compute cycles scanning identical images multiple times.

# Pre-requisite: Repository pattern refactor

Implementing deduplication requires abstracting database operations from the Kubernetes `storage.Interface` implementation.

The current `store` struct contains all SQL logic directly, which prevents swapping storage strategies per resource type.
A `Repository` interface will be introduced to define standard operations: Create, Delete, Get, List, Update, and Count.

The repository abstraction must preserve full support for Kubernetes list semantics, including label selectors and field selectors.
Each repository implementation will be responsible for constructing queries that support these filtering capabilities.

The `store` will delegate to a `Repository` implementation, allowing different storage strategies:

- `GenericObjectRepository`: Single-table storage for resources that do not require deduplication (e.g., `Registry`, `ScanJob`)
- `ScanArtifactRepository`: Split-table storage with deduplication for scan artifacts

This pattern allows for additional repository implementations in the future, should other resources require specialized storage behavior.

# Detailed design

[design]: #detailed-design

## Split storage model

Resources that benefit from deduplication use two tables:

1. **Artifacts table**: Stores the deduplicated payload keyed by digest
2. **References table**: Stores per-discovery metadata with a foreign key to the artifacts table

```sql
CREATE TABLE <artifacts_table> (
    digest TEXT PRIMARY KEY,
    object JSONB NOT NULL
);

CREATE TABLE <references_table> (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(253) NOT NULL,
    namespace VARCHAR(253) NOT NULL,
    metadata JSONB NOT NULL,
    image_metadata JSONB NOT NULL,
    digest TEXT NOT NULL REFERENCES <artifacts_table>(digest),
    UNIQUE (name, namespace)
);
```

## Artifact storage

Before storing an object in the artifacts table, instance-specific fields are stripped from the payload.
This includes name, namespace, labels, annotations, finalizers, owner references, UID, and image metadata.
These fields vary between discoveries of the same image and are stored separately in the references table.

The resource version is preserved in the artifact payload.
This allows the Kubernetes API machinery to perform conflict resolution during updates.
As a consequence, any modification to an artifact bumps the global resource version sequence, even if the change originates from a different object referencing the same digest.
This is an acceptable trade-off since only the scanning workers interact with these resources programmatically.

## Object reconstruction

When reading an object, the repository joins both tables and merges the JSONB to reconstruct the full Kubernetes object.
Object reconstruction is performed according to the following process:

- Retrieves the artifact payload from the artifacts table using the digest
- Retrieves the instance-specific metadata from the references table
- Merges the metadata from the references table into the artifact, preserving the resource version from the artifact
- Restores the image metadata from the references table

Example SQL query for a Get operation:

```sql
SELECT artifacts.object || jsonb_build_object(
    'metadata', refs.metadata || jsonb_build_object(
        'resourceVersion', artifacts.object->'metadata'->>'resourceVersion'
    ),
    'imageMetadata', refs.image_metadata
) AS object
FROM references refs
INNER JOIN artifacts ON refs.digest = artifacts.digest
WHERE refs.name = ? AND refs.namespace = ?;
```

For list operations, a [subquery](https://www.postgresql.org/docs/current/queries-table-expressions.html#QUERIES-SUBQUERIES) computes the merged object first, then applies label and field selector filters on the result.
This approach ensures that WHERE clauses evaluate against the fully reconstructed Kubernetes object rather than the raw table columns.

## Concurrency

In the previous design, artifacts were namespaced to support multi-tenancy, and only one scan per registry could run at a time.
This guaranteed that no two workers would attempt to write the same artifact concurrently.

With deduplication, artifacts are keyed by their digest and shared across namespaces.
Multiple workers scanning different registries or namespaces may discover the same image and attempt to write to the same artifact simultaneously.
This introduces the possibility of write conflicts that did not exist before.

Worker handlers must be updated to handle these conflicts.
For `VulnerabilityReport` resources, the vulnerability database version must be stored in the object.
When a [conflict occurs](https://pkg.go.dev/k8s.io/client-go/util/retry), the worker should verify whether another worker has already completed the scan by comparing the database version.
If the existing artifact was produced with the same or a newer database version, the worker can skip the redundant scan.

## Garbage collection

When a reference record is deleted, the associated artifact may no longer be referenced by any other record.
Rather than relying on a separate background process to clean up orphaned artifacts, the repository performs reference counting within the same transaction as the delete operation.

After removing the reference row, the repository counts how many other rows still reference the same digest.
If the count is zero, the artifact row is deleted immediately.
This transactional approach guarantees that artifacts are removed as soon as they become unreferenced, without requiring external coordination or scheduled cleanup jobs.

# Drawbacks

[drawbacks]: #drawbacks

- Slightly more complex queries with joins
- Two tables per resource type increases schema complexity

# Alternatives

[alternatives]: #alternatives

An alternative considered was performing deduplication at the application level.
In this model, workers would query the API server before processing an image to determine whether an SBOM or VulnerabilityReport already exists for the given digest.

This approach introduces additional load on the API server, as every scan operation would require a lookup to check for existing resources.
It also increases complexity in the worker handler code, which would need to manage deduplication logic rather than delegating that responsibility to the storage layer.
