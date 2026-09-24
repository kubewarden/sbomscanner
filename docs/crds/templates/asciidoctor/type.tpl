{{- define "type" -}}
{{- $type := . -}}
{{- if asciidocShouldRenderType $type -}}

[id="{{ asciidocTypeID $type | asciidocRenderAnchorID }}"]
==== {{ $type.Name  }}

{{ if $type.IsAlias }}_Underlying type:_ _{{ asciidocRenderType $type.UnderlyingType  }}_{{ end }}

{{ $type.Doc }}

{{ if $type.Validation -}}
.Validation:
{{- range $type.Validation }}
- {{ . }}
{{- end }}
{{- end }}

{{ if $type.References -}}
.Appears In:
****
{{- range $type.SortedReferences }}
{{- if asciidocShouldRenderType . }}
- {{ asciidocRenderTypeLink . }}
{{- else }}
- {{ .Name }}
{{- end }}
{{- end }}
****
{{- end }}

{{ if $type.Members -}}
[cols="20a,50a,15a,15a", options="header"]
|===
| Field | Description | Default | Validation
{{ if $type.GVK -}}
| *`apiVersion`* __string__ | `{{ $type.GVK.Group }}/{{ $type.GVK.Version }}` | |
| *`kind`* __string__ | `{{ $type.GVK.Kind }}` | |
{{ end -}}

{{ range $type.Members -}}
| *`{{ .Name }}`* __{{ asciidocRenderType .Type }}__
| {{ template "type_members" . }}
| {{ .Default }}
|{{- if .Validation }}
{{- range .Validation }}
{{ asciidocRenderValidation . }} +
{{- end }}
{{- end }}
{{ end -}}
|===
{{ end -}}

{{- end -}}
{{- end -}}
