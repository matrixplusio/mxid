{{/*
Expand the name of the chart.
*/}}
{{- define "mxid.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "mxid.fullname" -}}
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
Create chart label value (name-version).
*/}}
{{- define "mxid.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — applied to all resources.
*/}}
{{- define "mxid.labels" -}}
helm.sh/chart: {{ include "mxid.chart" . }}
{{ include "mxid.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the backend (StatefulSet + ClusterIP Services).
These must remain stable across upgrades; do NOT include version here.
*/}}
{{- define "mxid.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mxid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend-specific selector labels (adds component=backend).
*/}}
{{- define "mxid.backendSelectorLabels" -}}
{{ include "mxid.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Web-specific selector labels (adds component=web).
*/}}
{{- define "mxid.webSelectorLabels" -}}
{{ include "mxid.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end }}

{{/*
Image registry+namespace prefix. Override image.registry to pull from a private
registry / Harbor (air-gapped). Default is the canonical GHCR namespace. The
image NAMES (mxid, mxid-ee, mxid-web) are appended by the helpers below, so a
mirror must keep the same repo names under image.registry.
*/}}
{{- define "mxid.imageRegistry" -}}
{{- .Values.image.registry | default "ghcr.io/imkerbos" }}
{{- end }}

{{/*
Backend image repository — switches between CE and EE based on .Values.edition.
*/}}
{{- define "mxid.backendImage" -}}
{{- $reg := include "mxid.imageRegistry" . }}
{{- $tag := .Values.image.backendTag | default .Values.image.tag | default .Chart.AppVersion }}
{{- if eq .Values.edition "ee" }}
{{- printf "%s/mxid-ee:%s" $reg $tag }}
{{- else }}
{{- printf "%s/mxid:%s" $reg $tag }}
{{- end }}
{{- end }}

{{/*
Web image. Falls back to the global image.tag; override with image.webTag to pin
the web image independently (e.g. skip re-tagging an unchanged SPA build).
*/}}
{{- define "mxid.webImage" -}}
{{- printf "%s/mxid-web:%s" (include "mxid.imageRegistry" .) (.Values.image.webTag | default .Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Name of the Secret that holds sensitive env vars.
*/}}
{{- define "mxid.secretName" -}}
{{- if and (not .Values.secrets.create) .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "mxid.fullname" . }}
{{- end }}
{{- end }}
