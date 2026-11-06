{{- define "apc-action-security.name" -}}
apc-action-security
{{- end }}

{{- define "apc-action-security.fullname" -}}
{{- if .Values.nameOverride }}{{ .Values.nameOverride | trunc 63 | trimSuffix "-" }}{{- else }}{{ include "apc-action-security.name" . }}{{- end }}
{{- end }}

{{- define "apc-action-security.labels" -}}
app.kubernetes.io/name: {{ include "apc-action-security.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: apc
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "apc-action-security.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apc-action-security.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "apc-action-security.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "apc-action-security.fullname" .) .Values.serviceAccount.name }}{{- else }}{{ default "default" .Values.serviceAccount.name }}{{- end }}
{{- end }}

{{- define "apc-action-security.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end }}

{{- define "apc-action-security.runtimeMode" -}}
{{- if .Values.runtimeMode -}}{{ .Values.runtimeMode }}{{- else if eq .Values.profile "demo" -}}DEMO{{- else if eq .Values.profile "pilot" -}}PILOT{{- else -}}PRODUCTION{{- end -}}
{{- end -}}
