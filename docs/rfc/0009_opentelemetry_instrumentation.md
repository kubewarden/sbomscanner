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
- An annotation carrier that stores the W3C `traceparent` in the `sbomscanner.kubewarden.io/traceparent` object annotation, so a job trace survives hops between processes that communicate through the Kubernetes API (see [Job trace propagation](#job-trace-propagation)).
- `Tracer` and `Meter` helpers that take a package directory (e.g. `internal/handlers`) and produce instances whose [instrumentation scope](https://opentelemetry.io/docs/specs/otel/common/instrumentation-scope/) is the full Go import path of the calling package.

Tracers and meters are passed through constructors as struct fields, the same way `*slog.Logger` is already threaded through the codebase.
There are no package-level globals: the constructor-injection style keeps instrumentation testable and matches the maintainer guidance in [OpenTelemetry Go discussion #4532](https://github.com/open-telemetry/opentelemetry-go/discussions/4532).

## Span naming convention

Span names follow the `Component.Operation` convention, so every span name states the acting component:

- Reconcilers: `<Kind>Reconciler.Reconcile` (e.g. `ScanJobReconciler.Reconcile`).
- Runners: `RegistryScanRunner.CreateScanJob`, `NodeScanRunner.CreateNodeScanJob`.
- Webhooks use the Kubernetes-facing webhook kinds:
  `<Kind>ValidatingWebhook.<Verb>` and `<Kind>MutatingWebhook.<Verb>`
  with the admission verb (`Create` / `Update` / `Delete`), e.g. `ScanJobValidatingWebhook.Create`.

Names are static and low-cardinality, per the
[OpenTelemetry span name guidance](https://opentelemetry.io/docs/specs/otel/trace/api/#span)
("the most general string that identifies a (statistically) interesting class of Spans");
identities (object name, namespace, operation, outcome) live in attributes.
[Tekton names its reconcile spans the same way](https://github.com/tektoncd/pipeline/blob/main/pkg/reconciler/pipelinerun/tracing.go)
(`PipelineRun:Reconciler`).

## Job trace propagation

[job-trace-propagation]: #job-trace-propagation

A scan is a finite workflow that crosses process boundaries through a custom resource (`ScanJob` / `NodeScanJob`).
To keep every actor's spans in one trace, the trace context travels on the object itself:
the `sbomscanner.kubewarden.io/traceparent` annotation holds the W3C [`traceparent`](https://www.w3.org/TR/trace-context/#traceparent-header) of the job trace.
Only the job kinds carry it: long-lived objects (`Registry`, the configuration singletons) have no lifecycle to trace.

The annotation is written exactly once, when the job is created:
by the runner for scheduled jobs, or by the mutating webhook for jobs created any other way (kubectl, GitOps, MCP).
An existing annotation is never overwritten,
so a client that is already traced (e.g. a CI pipeline creating a `ScanJob`) can pre-set it
and adopt the whole scan into its own trace.
Reconcilers only ever read the annotation,
so the instrumentation cannot retrigger the reconcile loops it observes.

On the message hop, the trace context travels in the NATS headers instead:
publishers inject the current traceparent and worker consumer spans parent from it.

On the Kubernetes API hop, the trace context travels as the standard HTTP `traceparent` header:
the controller and the worker instrument their clients with the
[upstream Kubernetes client wrapper](https://pkg.go.dev/k8s.io/component-base/tracing#WrapperFor),
the kube-apiserver aggregation proxy forwards the header,
and the storage API server's spans join the caller's trace down to the SQL statements.
The client spans are sampled parent-based:
an API call made inside a trace produces a child span,
while background traffic (leader election renewals, informer resyncs) produces nothing,
instead of flooding the backend with one-span traces.
One carrier per transport: the annotation for the resource hop,
NATS headers for the message hop, HTTP headers for the API-call hop.

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
- Full image references with digest or tag. The label uses `repository`; the full reference goes on the span or the log record.
- Raw error strings. The label uses a finite `error.type` enum.
- Free-form input: session IDs, SQL statements, request paths with IDs, user IDs, IP addresses.

High-cardinality data belongs on spans or on log fields.

Per-workload metrics (`worker.workload.*`) keep the owning controller's `kind`, `namespace`, and `name` on the label set.
Cardinality grows with the number of scanned workloads in the cluster, not over time: workload names are operator-set and only change on intentional rename.
This matches the label shape used by [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics) and by the [trivy-operator `trivy_image_vulnerabilities`](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/metrics/) family, so the metrics join cleanly against existing dashboards without rewrites.

## Histograms

Histograms are exported as
[base2 exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#base2-exponential-bucket-histogram-aggregation)
by default:
bucket resolution adapts to the recorded values,
matching the native histograms the Prometheus bridge already emits for the controller-runtime metrics.
The default is applied in the shared telemetry setup only when the standard
[`OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION`](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/otlp/) environment variable is unset,
so the variable keeps its standard behaviour:
setting it to `explicit_bucket_histogram` restores classic histograms
for pipelines without exponential-histogram support.

## Exemplars

Histograms recorded inside a sampled span automatically carry
[exemplars](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exemplars):
occasional concrete measurements stamped with the trace and span identifiers.
This is the default SDK behaviour
([trace-based exemplar filter](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults)),
applies to every histogram in the catalogue below, and requires no per-metric code.
Backends that store exemplars
(e.g. Prometheus with [exemplar storage](https://prometheus.io/docs/prometheus/latest/feature_flags/#exemplars-storage))
keep them alongside the aggregated data,
and Grafana renders them as dots on latency panels that link straight to the trace,
turning "this percentile spiked" into "here is the exact slow request".
Exemplars carry only the trace identity;
high-cardinality request details stay on the linked span.

## Traces and metrics catalogue

The traces and metrics listed below are illustrative and will evolve with the project.
They show the current direction per component, not a frozen contract.

### Controller

Traces:

| Span                               | Triggered by                                                                                                   | Key attributes                                                                                                                                             |
| :--------------------------------- | :------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<Kind>Reconciler.Reconcile`       | Each reconcile (ScanJob, VulnerabilityReport, WorkloadScan, ImageWorkloadScan, NodeScan, NodeScanConfiguration, NodeScanJob) | `k8s.resource.kind`, `k8s.namespace.name`, `k8s.object.name`, `controller.result`; the job reconcilers add `scanjob.status` / `nodescanjob.status`           |
| `RegistryScanRunner.CreateScanJob` | `RegistryScanRunner` creating a job                                                                             | `scanjob.trigger=runner`, `registry.name`, `registry.namespace`, `k8s.object.name`                                                                            |
| `NodeScanRunner.CreateNodeScanJob` | `NodeScanRunner` creating a job                                                                                 | `nodescanjob.trigger=runner`, `k8s.node.name`, `k8s.object.name`                                                                                              |
| `<Kind>ValidatingWebhook.<Verb>`   | Validating admission (Registry, ScanJob, WorkloadScanConfiguration, NodeScanConfiguration, NodeScanJob)         | `webhook.type=validating`, `webhook.kind`, `webhook.operation`, `webhook.request.uid`, `webhook.allowed`, `webhook.reason`, `k8s.namespace.name`, `k8s.object.name` |
| `<Kind>MutatingWebhook.<Verb>`     | Mutating admission (Registry, ScanJob, NodeScanJob)                                                             | `webhook.type=mutating`, plus the validating-webhook attributes                                                                                               |

Each reconcile emits exactly one span,
parented into the job trace when the object carries the traceparent annotation
(see [Job trace propagation](#job-trace-propagation)) and standalone otherwise.
Webhook spans join the job trace the same way.

The runner spans are the roots of fresh job traces, one trace per job.
Jobs created by users (kubectl, GitOps, MCP) have no runner span:
their trace roots at the `<Kind>MutatingWebhook.Create` span that injected the traceparent,
so the root span name tells the job's origin apart at a glance,
backed by the bounded `scanjob.trigger` / `nodescanjob.trigger` attribute.

Metrics:

| Metric                           | Type    | Labels (bounded)                                                   |
| :------------------------------- | :------ | :------------------------------------------------------------------ |
| `controller.webhook.decisions`   | Counter | `type` (`validating` / `mutating`), `kind`, `operation`, `allowed`, `reason` |
| `controller.registry_scan.ticks` | Counter | `result`                                                             |
| `controller.node_scan.ticks`     | Counter | `result`                                                             |
| `sbomscanner.scanjobs`           | Counter | `result` (`complete` / `failed`), `source` (`registry` / `workload`) |
| `sbomscanner.nodescanjobs`       | Counter | `result` (`complete` / `failed`)                                     |

Reconcile durations and error counts are deliberately not duplicated here:
controller-runtime already exports them, along with the workqueue, rest-client, webhook-server,
and Go runtime families
(see the [kubebuilder metrics reference](https://book.kubebuilder.io/reference/metrics-reference)).
Instead, the controller bridges its whole controller-runtime Prometheus registry over OTLP with the
[Prometheus bridge](https://pkg.go.dev/go.opentelemetry.io/contrib/bridges/prometheus),
so one OTLP stream carries the built-in and the first-party metrics
(including controller-runtime's native histograms, translated to exponential histograms),
while the [controller-runtime metrics server](https://book.kubebuilder.io/reference/metrics)
keeps serving them for users on Prometheus pull.

### Worker

Traces:

| Span                                     | Triggered by                                                    | Key attributes                                       |
| :---------------------------------------- | :--------------------------------------------------------------- | :---------------------------------------------------- |
| `<Handler>.Handle`                       | Each consumed message (CreateCatalogHandler, GenerateSBOMHandler, ScanSBOMHandler, GenerateNodeSBOMHandler, NodeScanSBOMHandler) | `messaging.system=nats`, `handler.skip_reason` on the early-return paths |
| `<Handler>.HandleFailure`                | A message exhausting its redeliveries (ScanJobFailureHandler, NodeScanJobFailureHandler) | `messaging.system=nats`, `error.message`             |
| `Trivy.Image` / `Trivy.SBOM` / `Trivy.Filesystem` | Each Trivy invocation                                    | `trivy.command`                                       |

Consumer spans (`SpanKind=Consumer`) are parented from the traceparent carried in the NATS
message headers, injected by the publisher from the publishing context.
Handlers publishing the next pipeline message do so inside their own span,
so the job trace forms a tree over NATS:
reconcile → catalog → per-image SBOM generation → scan.

Metrics:

| Metric                          | Type      | Labels (bounded)                                                                                  |
| :------------------------------- | :-------- | :-------------------------------------------------------------------------------------------------- |
| `worker.scan.duration`          | Histogram | `stage` (`catalog` / `generate_sbom` / `scan_sbom` / `generate_node_sbom` / `node_scan_sbom`), `result` |
| `sbomscanner.images.scanned`    | Counter   | `registry` (host), `result`                                                                          |
| `worker.registry.call.duration` | Histogram | `operation` (`catalog` / `list_repository_contents` / `get_descriptor` / `get_image_details`), `result` |
| `worker.trivy.duration`         | Histogram | `command` (`image` / `sbom` / `filesystem`), `result`                                                |
| `worker.handler.errors`         | Counter   | `handler`, `error.type` (Kubernetes status reason, `canceled`, `deadline_exceeded`, or `unknown`)    |

### Storage

Traces:

| Span                                                       | Triggered by                                                                                                    | Key attributes                                                                                                   |
| :--------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------- |
| `GET` / `POST` / ... (HTTP method)                         | [otelhttp](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp) server handler, outermost on the aggregated API server handler chain | standard [HTTP server semantic conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/)          |
| `<Kind>Store.<Operation>`                                  | Each storage operation (`Create`, `Get`, `GetList`, `GuaranteedUpdate`, `Delete`, `Watch`) on the served resources | `k8s.namespace.name`, `k8s.object.name`, `storage.result` (`success` / `not_found` / `already_exists` / `error`)   |
| `query <KEYWORD>` (e.g. `query INSERT`)                    | [otelpgx](https://github.com/exaring/otelpgx) tracer on the pgx pool                                               | standard [database client semantic conventions](https://opentelemetry.io/docs/specs/semconv/database/database-spans/), full SQL statement |
| `NatsBroadcaster.Publish`                                  | Watch fan-out publish leg: each write publishes its event to NATS with the write's trace context in the headers    | `messaging.system=nats`, `messaging.destination.name`, `event.type` (`added` / `modified` / `deleted`)             |
| `NatsWatcher.HandleMessage`                                | Watch fan-out consume leg on every storage replica, parented from the publishing write                             | `messaging.system=nats`, `messaging.destination.name`, `event.type`                                                |
| `WorkloadScanReportWatcher.HandleVulnerabilityReportEvent` | VulnerabilityReport events fanned out as synthetic WorkloadScanReport events                                       | `messaging.system=nats`, `messaging.destination.name`                                                              |

The HTTP server span is extracted before any other filter runs, so it covers the whole request, authentication included.
Machinery requests (probes, discovery, OpenAPI aggregation) produce no server spans:
they are polled every few seconds without a trace context,
and each request would otherwise become a one-span root trace.
Direct client requests remain traced.
Not found and already exists are recorded as expected outcomes on the `storage.result` attribute, not as span errors:
a miss on a lookup is normal control flow and must not light up traces as failures.
Pool-acquire spans are disabled as noise; acquire latency stays observable through the pool metrics below.

Metrics:

| Metric                               | Type      | Labels (bounded)           |
| :----------------------------------- | :-------- | :------------------------- |
| `storage.apiserver.request.duration` | Histogram | `verb`, `resource`, `code` |
| `storage.watch.events`               | Counter   | `resource`, `event.type`   |

The request duration histogram covers resource requests only:
non-resource endpoints (health, discovery, OpenAPI) are skipped,
and so are long-running requests (watches), whose duration is a connection lifetime, not a latency.

The instrumentation libraries add the standard families on top:
otelhttp exports [`http.server.request.duration`](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/),
and otelpgx exports [`db.client.operation.duration`](https://opentelemetry.io/docs/specs/semconv/database/database-metrics/)
(labeled by the pgx operation type) together with the connection pool gauges.
A separate first-party Postgres histogram would duplicate that signal while requiring SQL parsing to label it,
so the semantic-convention metric is the source of truth for query latency;
per-statement detail lives on the spans.

### MCP

Traces:

| Span              | Triggered by                                           | Key attributes                                                           |
| :---------------- | :----------------------------------------------------- | :----------------------------------------------------------------------- |
| `MCP HTTP`        | `otelhttp.NewHandler` on the Streamable HTTP transport | `http.method`, `http.route`, `http.status_code`                          |
| `MCP tool <name>` | Tracing middleware in `internal/mcp/middlewares.go`    | `mcp.tool.name`, `mcp.session.id`, `mcp.tool.result` (`success`/`error`) |

Metrics:

| Metric                      | Type      | Labels (bounded)      |
| :-------------------------- | :-------- | :-------------------- |
| `mcp.tool.calls`            | Counter   | `tool.name`, `result` |
| `mcp.tool.call.duration`    | Histogram | `tool.name`, `result` |
| `mcp.rate_limit.rejections` | Counter   | `tool.name`           |

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
