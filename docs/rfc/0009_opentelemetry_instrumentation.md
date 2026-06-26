| Field        | Value                                                      |
| :----------- | :--------------------------------------------------------- |
| Feature Name | OpenTelemetry instrumentation                              |
| Start Date   | 2026-06-09                                                 |
| Category     | Observability                                              |
| RFC PR       | [#1221](https://github.com/kubewarden/sbomscanner/pull/1221) |
| State        | **ACCEPTED**                                               |

# Summary

[summary]: #summary

Adopt [OpenTelemetry](https://opentelemetry.io/) as the standard observability framework for SBOMscanner.
OpenTelemetry is the vendor-neutral CNCF standard for traces and metrics (and, eventually, logs), supported by every major observability backend.
Adopting it instead of a Prometheus-only or vendor-specific approach gives the project a single SDK for both signals, keeps the export pipeline backend-agnostic, and aligns with how the rest of the cloud-native ecosystem instruments itself.

# Motivation

[motivation]: #motivation

SBOMscanner is a distributed system whose internal behaviour is opaque outside of structured logs.
There is no first-party tracing, and the only metrics come from the controller-runtime built-in `/metrics` endpoint on the controller; the other three binaries (worker, storage, mcp) expose nothing.

Operators need a way to understand what their cluster is doing and where time and resources are spent.
This applies across scan pipelines (today's `ScanJob`, the upcoming `NodeScanJob`, future scan workflows), the storage layer (APIServer requests, Postgres queries, watch fan-out), the MCP tool surface, and the NATS messaging backplane.

A single `ScanJob` is one concrete example: it crosses four processes connected by NATS JetStream, and correlating a slow scan back to a registry call, a Trivy invocation, or a database query today requires reading four log streams and reconstructing causality by timestamp.
Tracing and metrics make this kind of pipeline analysis a first-class capability and expose bottlenecks that logs alone cannot show.

## Examples / User Stories

[examples]: #examples

- As an operator, I want to understand where scans spend their time so I can identify bottlenecks across the catalog, SBOM, vulnerability, and node-scan stages.
- As a developer, I want trace IDs printed in every log line so I can pivot from `kubectl logs` to a trace view without manual correlation.
- As a cluster operator, I want pipeline metrics exported to any OTLP-compatible backend without scraping individual `/metrics` endpoints on each binary.
- As a user who does not run an observability stack, I want SBOMscanner to behave exactly as before when no OTLP endpoint is configured.

# Detailed design

[design]: #detailed-design

## Opt-in model

All instrumentation is gated on the [`OTEL_EXPORTER_OTLP_ENDPOINT`](https://opentelemetry.io/docs/specs/otel/protocol/exporter/) environment variable defined by the OpenTelemetry specification.
When unset, the binaries install no-op providers and behave exactly as before; no outbound connections are opened.
When set, traces and metrics are exported to an OTLP/gRPC collector.

No new CLI flags are introduced.
All runtime configuration uses the [standard `OTEL_*` environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

The existing controller-runtime `/metrics` endpoint is left untouched.
The collector is bring-your-own; SBOMscanner does not embed one.

## Plumbing: `internal/telemetry`

A single package, `internal/telemetry`, contains the OpenTelemetry plumbing shared by all four binaries.
The package provides:

- A `Setup` function each `cmd/*/main.go` calls once at startup to install the global providers (or no-ops when telemetry is disabled).
- An `slog.Handler` wrapper that decorates every log record with `trace_id` and `span_id` for log-to-trace correlation, while leaving the existing JSON-on-stdout pipeline intact so `kubectl logs`, Loki, and Datadog continue to work unchanged.
- A NATS header carrier that propagates the W3C `traceparent` over JetStream headers so a single trace survives the producer-to-consumer hop.
- `Tracer` and `Meter` helpers that take a package directory (e.g. `internal/handlers`) and produce instances whose [instrumentation scope](https://opentelemetry.io/docs/specs/otel/common/instrumentation-scope/) is the full Go import path of the calling package.

Tracers and meters are passed through constructors as struct fields, the same way `*slog.Logger` is already threaded through the codebase.
There are no package-level globals: the constructor-injection style keeps instrumentation testable and matches the maintainer guidance in [OpenTelemetry Go discussion #4532](https://github.com/open-telemetry/opentelemetry-go/discussions/4532).

## Metric label cardinality

Every metric label value must come from a fixed, low-cardinality set known at design time.
The test is the cumulative unique value count across the metric's retention window, not the snapshot count at any instant.
Background and rationale:
[Prometheus instrumentation best practices](https://prometheus.io/docs/practices/instrumentation/),
[Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/),
Brian Brazil's [Cardinality is Key](https://www.robustperception.io/cardinality-is-key/),
the [OpenTelemetry metric semantic conventions](https://opentelemetry.io/docs/specs/semconv/general/metrics/),
the [OpenTelemetry metrics SDK cardinality limits](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#cardinality-limits),
and Grafana Labs on [managing high-cardinality metrics](https://grafana.com/blog/2022/10/20/how-to-manage-high-cardinality-metrics-in-a-prometheus-environment/) and [cardinality spikes](https://grafana.com/blog/2022/02/15/what-are-cardinality-spikes-and-why-do-they-matter/).

The following attribute classes are banned from metric labels:

- Pod identifiers (`k8s.pod.name`, `k8s.pod.uid`) and anything else with a generated suffix. Every rollout or scale event mints new ones, so cardinality grows monotonically.
- Full image references with digest or tag. The label uses `repository`; the full reference goes on the span, the log record, or an [exemplar](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exemplars).
- Raw error strings. The label uses a finite `error.type` enum.
- Free-form input: session IDs, SQL statements, request paths with IDs, user IDs, IP addresses.

High-cardinality data belongs on spans, on log fields, or as exemplars.

Per-workload metrics (`worker.workload.*`) keep the owning controller's `kind`, `namespace`, and `name` on the label set.
Cardinality grows with the number of scanned workloads in the cluster, not over time: workload names are operator-set and only change on intentional rename.
This matches the label shape used by [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics) and by the [trivy-operator `trivy_image_vulnerabilities`](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/metrics/) family, so the metrics join cleanly against existing dashboards without rewrites.

## Traces and metrics catalogue

The traces and metrics listed below are illustrative and will evolve with the project.
They show the current direction per component, not a frozen contract.

### Controller

Traces:

| Span                                | Triggered by                                      | Key attributes                                                                                     |
| :---------------------------------- | :------------------------------------------------ | :------------------------------------------------------------------------------------------------- |
| `Reconcile ScanJob`                 | `ScanJobReconciler` reconcile call                | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `scanjob.phase`, `controller.result` |
| `Reconcile VulnerabilityReport`     | `VulnerabilityReportReconciler` reconcile call    | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`                  |
| `Reconcile WorkloadScan`            | `WorkloadScanReconciler` reconcile call           | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`, `workload.kind` |
| `Reconcile ImageWorkloadScan`       | `ImageWorkloadScanReconciler` reconcile call      | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`                  |
| `Reconcile NodeScan`                | `NodeScanReconciler` reconcile call               | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`                  |
| `Reconcile NodeScanConfiguration`   | `NodeScanConfigurationReconciler` reconcile call  | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`                  |
| `Reconcile NodeScanJob`             | `NodeScanJobReconciler` reconcile call            | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `nodescanjob.phase`, `controller.result` |
| `RegistryScanRunner tick`           | Periodic runner loop                              | `registry.name`, `registry.namespace`, `scan.scheduled`                                            |
| `NodeScanRunner tick`               | Periodic runner loop                              | `nodescanconfiguration.name`, `nodes.scheduled`                                                    |
| `Webhook Registry`                  | Validating webhook on `Registry`                  | `webhook.kind`, `webhook.operation`, `webhook.allowed`, `webhook.reason`                           |
| `Webhook ScanJob`                   | Validating webhook on `ScanJob`                   | `webhook.kind`, `webhook.operation`, `webhook.allowed`, `webhook.reason`                           |
| `Webhook WorkloadScanConfiguration` | Validating webhook on `WorkloadScanConfiguration` | `webhook.kind`, `webhook.operation`, `webhook.allowed`, `webhook.reason`                           |
| `Webhook NodeScanConfiguration`     | Validating webhook on `NodeScanConfiguration`     | `webhook.kind`, `webhook.operation`, `webhook.allowed`, `webhook.reason`                           |
| `Webhook NodeScanJob`               | Validating webhook on `NodeScanJob`               | `webhook.kind`, `webhook.operation`, `webhook.allowed`, `webhook.reason`                           |

Metrics:

| Metric                           | Type      | Labels (bounded)                         | Exemplars                                         |
| :------------------------------- | :-------- | :--------------------------------------- | :------------------------------------------------ |
| `controller.reconcile.duration`  | Histogram | `kind`, `controller`, `result`           | `trace_id`, `namespace`, `name`                   |
| `controller.reconcile.errors`    | Counter   | `kind`, `controller`, `error.type`       | `trace_id`, `namespace`, `name`                   |
| `controller.webhook.decisions`   | Counter   | `kind`, `operation`, `allowed`, `reason` | `trace_id`, `request.uid`                         |
| `controller.registry_scan.ticks` | Counter   | `result`                                 | `trace_id`, `registry.name`, `registry.namespace` |

### Worker

Traces:

| Span                    | Triggered by                                                            | Key attributes                                                                                      |
| :---------------------- | :---------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- |
| `Handler CreateCatalog` | NATS consume on `sbomscanner.scanjob.create-catalog`                    | `messaging.system`, `messaging.consumer.name`, `registry.host`, `scanjob.name`, `scanjob.namespace` |
| `Handler GenerateSBOM`  | NATS consume on `sbomscanner.scanjob.generate-sbom`                     | `messaging.consumer.name`, `oci.image.ref`, `oci.image.platform`, `scanjob.name`                    |
| `Handler ScanSBOM`      | NATS consume on `sbomscanner.scanjob.scan-sbom`                         | `messaging.consumer.name`, `oci.image.ref`, `vulnerability.count`, `vulnerability.count.critical`   |
| `Handler ScanJobFailure` | NATS consume on the `ScanJob` failure subject                          | `messaging.consumer.name`, `scanjob.name`, `scanjob.namespace`, `error.type`                        |
| `Handler GenerateNodeSBOM` | NATS consume on `sbomscanner.nodescanjob.generate-sbom`              | `messaging.consumer.name`, `k8s.node.name`, `nodescanjob.name`                                      |
| `Handler NodeScanSBOM`  | NATS consume on `sbomscanner.nodescanjob.scan-sbom`                     | `messaging.consumer.name`, `k8s.node.name`, `nodescanjob.name`, `vulnerability.count`, `vulnerability.count.critical` |
| `Handler NodeScanJobFailure` | NATS consume on the `NodeScanJob` failure subject                  | `messaging.consumer.name`, `nodescanjob.name`, `k8s.node.name`, `error.type`                        |
| `Registry HTTP`         | `otelhttp.NewTransport` wrapping `go-containerregistry`                 | `http.method`, `http.url`, `http.status_code`, `registry.host`, `registry.operation`                |
| `Trivy invoke`          | Each Trivy entry point call site in `generate_sbom.go` / `scan_sbom.go` / `generate_node_sbom.go` / `node_scan_sbom.go` | `trivy.command`, `trivy.target`, `trivy.db.version`, `result`                                       |

Metrics:

| Metric                            | Type      | Labels (bounded)                                          | Exemplars                                          |
| :-------------------------------- | :-------- | :-------------------------------------------------------- | :------------------------------------------------- |
| `worker.scan.duration`            | Histogram | `stage` (`catalog`/`generate_sbom`/`scan_sbom`/`generate_node_sbom`/`node_scan_sbom`), `result` | `trace_id`, `scanjob.name`, `oci.image.ref`        |
| `worker.images.scanned`           | Counter   | `registry_host`, `result`                                 | `trace_id`, `oci.image.ref`                        |
| `worker.vulnerabilities.found`    | Counter   | `severity`, `registry_host`                               | `trace_id`, `oci.image.ref`, `vulnerability.id`    |
| `worker.registry.call.duration`   | Histogram | `registry_host`, `operation`, `http.status_code`          | `trace_id`, `oci.image.ref`                        |
| `worker.trivy.invoke.duration`    | Histogram | `trivy.command`, `result`                                 | `trace_id`, `trivy.target`                         |
| `worker.handler.errors`           | Counter   | `handler`, `error.type`                                   | `trace_id`, `error.message`                        |
| `worker.workload.vulnerabilities` | Gauge     | `owner.kind`, `owner.namespace`, `owner.name`, `severity` | `trace_id`, `workload.uid`                         |
| `worker.workload.scans`           | Counter   | `owner.kind`, `owner.namespace`, `owner.name`, `result`   | `trace_id`, `scanjob.name`                         |
| `worker.image.vulnerabilities`    | Gauge     | `registry_host`, `repository`, `severity`                 | `trace_id`, `oci.image.ref` (full ref with digest) |
| `worker.image.scan.duration`      | Histogram | `registry_host`, `repository`, `result`                   | `trace_id`, `oci.image.ref`                        |

### Storage

Traces:

| Span                    | Triggered by                                                                            | Key attributes                                                                                     |
| :---------------------- | :-------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------- |
| `APIServer request`     | `otelhttp.NewHandler` on the aggregated `genericapiserver` chain                        | `http.method`, `http.route`, `http.status_code`, `k8s.api.verb`, `k8s.api.resource`                |
| `Storage <Kind>.<Verb>` | REST storage methods on `Image` / `SBOM` / `VulnerabilityReport` / `WorkloadScanReport` | `k8s.api.verb`, `k8s.api.resource`, `k8s.namespace.name`, `k8s.object.name`, `result`              |
| `Postgres <op>`         | `otelpgx.NewTracer()` on `pgxpool.Config.ConnConfig.Tracer`                             | `db.system=postgresql`, `db.operation`, `db.sql.table`, `db.rows_affected`                         |
| `Watch fan-out publish` | `internal/storage/watcher.go` publishing to NATS                                        | `messaging.system=nats`, `messaging.destination.name`, `event.type` (`added`/`modified`/`deleted`) |
| `Watch fan-out consume` | Storage-side NATS subscriber                                                            | `messaging.system=nats`, `messaging.consumer.name`, `event.type`                                   |

Metrics:

| Metric                               | Type      | Labels (bounded)                         | Exemplars                       |
| :----------------------------------- | :-------- | :--------------------------------------- | :------------------------------ |
| `storage.apiserver.request.duration` | Histogram | `verb`, `resource`, `code`               | `trace_id`, `namespace`, `name` |
| `storage.postgres.query.duration`    | Histogram | `db.operation`, `db.sql.table`, `result` | `trace_id`                      |
| `storage.watch.events`               | Counter   | `resource`, `event.type`                 | `trace_id`, `namespace`, `name` |
| `storage.watch.subscribers`          | Gauge     | `resource`                               | `trace_id`                      |

### MCP

Traces:

| Span              | Triggered by                                           | Key attributes                                                           |
| :---------------- | :----------------------------------------------------- | :----------------------------------------------------------------------- |
| `MCP HTTP`        | `otelhttp.NewHandler` on the Streamable HTTP transport | `http.method`, `http.route`, `http.status_code`                          |
| `MCP tool <name>` | Tracing middleware in `internal/mcp/middlewares.go`    | `mcp.tool.name`, `mcp.session.id`, `mcp.tool.result` (`success`/`error`) |

Metrics:

| Metric                      | Type      | Labels (bounded)      | Exemplars                |
| :-------------------------- | :-------- | :-------------------- | :----------------------- |
| `mcp.tool.calls`            | Counter   | `tool.name`, `result` | `trace_id`, `session.id` |
| `mcp.tool.call.duration`    | Histogram | `tool.name`, `result` | `trace_id`, `session.id` |
| `mcp.rate_limit.rejections` | Counter   | `tool.name`           | `trace_id`, `session.id` |

# Drawbacks

[drawbacks]: #drawbacks

- A misconfigured high-cardinality attribute on a metric can blow up a time-series database. The mitigation is the cardinality discipline documented above plus code review.
- The collector becomes a new operational dependency for users who opt in. The opt-in default and the bring-your-own collector model contain the blast radius for users who do not.

# Alternatives

[alternatives]: #alternatives

**Adopt [`go.opentelemetry.io/contrib/bridges/otelslog`](https://pkg.go.dev/go.opentelemetry.io/contrib/bridges/otelslog).**
The bridge replaces the `slog.Handler` entirely and ships records as OpenTelemetry `LogRecord`s over OTLP.
Logs would stop appearing in `kubectl logs`, in Loki tailing pods, and in Datadog's log-tail view, and the project would be implicitly opting into the OpenTelemetry Logs SDK as a third signal.
The `traceContextHandler` wrapper keeps the existing stdout JSON pipeline and only adds trace correlation.
Projects that take the same route as us include
[grafana/grafana-app-sdk](https://github.com/grafana/grafana-app-sdk),
[googleapis/mcp-toolbox](https://github.com/googleapis/mcp-toolbox-sdk-python),
[google/osv.dev](https://github.com/google/osv.dev),
[transparency-dev/tessera](https://github.com/transparency-dev/tessera),
[authgear/authgear-server](https://github.com/authgear/authgear-server),
[sablierapp/sablier](https://github.com/sablierapp/sablier),
and [speakeasy-api/gram](https://github.com/speakeasy-api/gram).

**Package-level `var tracer = otel.Tracer(...)` globals.**
Convenient but harder to fake in tests and relies on hidden global state.
The constructor-injection style is the maintainer-endorsed pattern for the testability axis of [OpenTelemetry Go discussion #4532](https://github.com/open-telemetry/opentelemetry-go/discussions/4532).

# Unresolved questions

[unresolved]: #unresolved-questions
