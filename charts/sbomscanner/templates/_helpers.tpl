{{/*
Expand the name of the chart.
*/}}
{{- define "sbomscanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sbomscanner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sbomscanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Registry prefix for the chart images, with a trailing "/".
It takes the workload context dict (see "Values of the workloads" below).
The order is: the workload imageRegistry, common.imageRegistry,
global.cattle.systemDefaultRegistry (set by Rancher), then global.imageRegistry.
Renders "" when all are empty.
*/}}
{{- define "system_default_registry" -}}
{{- $l := include "sbomscanner._levels" (dict "ctx" . "key" "imageRegistry") | fromYamlArray -}}
{{- $cattle := dig "cattle" "systemDefaultRegistry" "" (.root.Values.global | default dict) -}}
{{- with index $l 2 | default (index $l 1) | default $cattle | default (index $l 0) -}}
{{- printf "%s/" . -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "sbomscanner.labels" -}}
helm.sh/chart: {{ include "sbomscanner.chart" . }}
{{ include "sbomscanner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: sbomscanner
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sbomscanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbomscanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sbomscanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sbomscanner.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Security Contexts
*/}}
{{- define "sbomscanner.securityContext" -}}
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
seccompProfile:
    type: RuntimeDefault
allowPrivilegeEscalation: false
capabilities:
    drop:
    - "ALL"
{{- end}}

{{/*
Values of the workloads

The workload templates read their values through the public helpers below.
Each public helper takes a context dict:
  root:      the root context ($)
  workload:  the name of the workload block in .Values, for example "workerNode"
  component: the value of the app.kubernetes.io/component label, for example "worker-node"

A template builds the context dict once:
  {{- $ctx := dict "root" $ "workload" "controller" "component" "controller" }}

Each public helper reads one key with one private helper. The private helper sets the rule:
  sbomscanner._scalar: the workload value, else the common value, else the global value.
  sbomscanner._list:   the same rule as sbomscanner._scalar, for a list.
  sbomscanner._map:    the global, common, and workload maps merged. The workload wins on a duplicate key.
  sbomscanner._concat: the global, common, and workload lists, in this order.
An empty value ("", [] or {}) counts as unset.

The private helpers take dict "ctx" <context dict> "key" <key>.
A key with a dot, for example "serviceAccount.annotations", reads a nested map.
Templates do not call the private helpers.
*/}}

{{/*
sbomscanner._levels renders a YAML list with three items:
the value of the key in global, in common, and in the workload block.
The other private helpers decode this list, so they work on copies of .Values.
*/}}
{{- define "sbomscanner._levels" -}}
{{- $values := .ctx.root.Values -}}
{{- $blocks := list ($values.global | default dict) ($values.common | default dict) (index $values .ctx.workload | default dict) -}}
{{- $out := list -}}
{{- range $block := $blocks -}}
{{- $value := $block -}}
{{- range $part := splitList "." $.key -}}
{{- $value = index ($value | default dict) $part -}}
{{- end -}}
{{- $out = append $out $value -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{- define "sbomscanner._scalar" -}}
{{- $l := include "sbomscanner._levels" . | fromYamlArray -}}
{{- index $l 2 | default (index $l 1) | default (index $l 0) | default "" -}}
{{- end -}}

{{- define "sbomscanner._list" -}}
{{- $l := include "sbomscanner._levels" . | fromYamlArray -}}
{{- toYaml (index $l 2 | default (index $l 1) | default (index $l 0) | default list) -}}
{{- end -}}

{{- define "sbomscanner._map" -}}
{{- $l := include "sbomscanner._levels" . | fromYamlArray -}}
{{- toYaml (mergeOverwrite (dict) (index $l 0 | default dict) (index $l 1 | default dict) (index $l 2 | default dict)) -}}
{{- end -}}

{{- define "sbomscanner._concat" -}}
{{- $l := include "sbomscanner._levels" . | fromYamlArray -}}
{{- toYaml (concat (index $l 0 | default list) (index $l 1 | default list) (index $l 2 | default list)) -}}
{{- end -}}

{{/*
sbomscanner._field renders "<name>:" and the value as YAML.
It renders nothing when the value is empty.
It takes dict "name" <field name> "value" <value>.
*/}}
{{- define "sbomscanner._field" -}}
{{- with .value -}}
{{ $.name }}:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/*
sbomscanner._labels renders "labels:" with the merged map of the key
and the fixed chart labels. The fixed chart labels win on a duplicate key.
*/}}
{{- define "sbomscanner._labels" -}}
{{- $labels := include "sbomscanner._map" . | fromYaml -}}
{{- $fixed := include "sbomscanner.labels" .ctx.root | fromYaml -}}
{{- $_ := set $fixed "app.kubernetes.io/component" .ctx.component -}}
labels:
  {{- toYaml (mergeOverwrite $labels $fixed) | nindent 2 }}
{{- end -}}

{{/* Public helpers that render a bare value. */}}

{{- define "sbomscanner.imagePullPolicy" -}}
{{- include "sbomscanner._scalar" (dict "ctx" . "key" "imagePullPolicy") -}}
{{- end -}}

{{- define "sbomscanner.logLevel" -}}
{{- include "sbomscanner._scalar" (dict "ctx" . "key" "logLevel") -}}
{{- end -}}

{{/* Public helpers that render a whole field, or nothing when the value is empty. */}}

{{- define "sbomscanner.priorityClassName" -}}
{{- with include "sbomscanner._scalar" (dict "ctx" . "key" "priorityClassName") -}}
priorityClassName: {{ . | quote }}
{{- end -}}
{{- end -}}

{{- define "sbomscanner.tolerations" -}}
{{- include "sbomscanner._field" (dict "name" "tolerations" "value" (include "sbomscanner._list" (dict "ctx" . "key" "tolerations") | fromYamlArray)) -}}
{{- end -}}

{{- define "sbomscanner.topologySpreadConstraints" -}}
{{- include "sbomscanner._field" (dict "name" "topologySpreadConstraints" "value" (include "sbomscanner._list" (dict "ctx" . "key" "topologySpreadConstraints") | fromYamlArray)) -}}
{{- end -}}

{{- define "sbomscanner.extraEnvFrom" -}}
{{- include "sbomscanner._field" (dict "name" "envFrom" "value" (include "sbomscanner._list" (dict "ctx" . "key" "extraEnvFrom") | fromYamlArray)) -}}
{{- end -}}

{{- define "sbomscanner.nodeSelector" -}}
{{- include "sbomscanner._field" (dict "name" "nodeSelector" "value" (include "sbomscanner._map" (dict "ctx" . "key" "nodeSelector") | fromYaml)) -}}
{{- end -}}

{{- define "sbomscanner.affinity" -}}
{{- include "sbomscanner._field" (dict "name" "affinity" "value" (include "sbomscanner._map" (dict "ctx" . "key" "affinity") | fromYaml)) -}}
{{- end -}}

{{- define "sbomscanner.workloadAnnotations" -}}
{{- include "sbomscanner._field" (dict "name" "annotations" "value" (include "sbomscanner._map" (dict "ctx" . "key" "annotations") | fromYaml)) -}}
{{- end -}}

{{- define "sbomscanner.podAnnotations" -}}
{{- include "sbomscanner._field" (dict "name" "annotations" "value" (include "sbomscanner._map" (dict "ctx" . "key" "podAnnotations") | fromYaml)) -}}
{{- end -}}

{{- define "sbomscanner.serviceAccountAnnotations" -}}
{{- include "sbomscanner._field" (dict "name" "annotations" "value" (include "sbomscanner._map" (dict "ctx" . "key" "serviceAccount.annotations") | fromYaml)) -}}
{{- end -}}

{{- define "sbomscanner.workloadLabels" -}}
{{- include "sbomscanner._labels" (dict "ctx" . "key" "labels") -}}
{{- end -}}

{{- define "sbomscanner.podLabels" -}}
{{- include "sbomscanner._labels" (dict "ctx" . "key" "podLabels") -}}
{{- end -}}

{{- define "sbomscanner.imagePullSecrets" -}}
{{- include "sbomscanner._field" (dict "name" "imagePullSecrets" "value" (include "sbomscanner._concat" (dict "ctx" . "key" "imagePullSecrets") | fromYamlArray)) -}}
{{- end -}}

{{/* Public helpers that render list entries, or nothing when the list is empty. */}}

{{- define "sbomscanner.extraEnv" -}}
{{- with include "sbomscanner._concat" (dict "ctx" . "key" "extraEnv") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "sbomscanner.extraVolumes" -}}
{{- with include "sbomscanner._concat" (dict "ctx" . "key" "extraVolumes") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "sbomscanner.extraVolumeMounts" -}}
{{- with include "sbomscanner._concat" (dict "ctx" . "key" "extraVolumeMounts") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}