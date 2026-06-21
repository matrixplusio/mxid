import { client } from './client'
import type { ApiResponse, PaginatedData, App, AppGroup, AppAccess, AppCert, AppTemplate, AppTemplateListItem } from '../types'

// Outbound provisioning config (L2 offboarding). token_set flags whether a
// secret is stored without echoing it.
export interface AppProvisioning {
  app_id: string
  enabled: boolean
  connector: string
  base_url: string
  token_set: boolean
}

export interface AppProvisioningInput {
  enabled: boolean
  connector: string
  base_url: string
  token: string // blank = keep existing
}

export const appApi = {
  list: (params: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<App>>>('/apps', { params }).then(r => r.data.data),
  getById: (id: string) =>
    client.get<ApiResponse<App>>(`/apps/${id}`).then(r => r.data.data),
  create: (data: Record<string, unknown>) =>
    client.post<ApiResponse<App>>('/apps', data).then(r => r.data.data),
  update: (id: string, data: Record<string, unknown>) =>
    client.put<ApiResponse<App>>(`/apps/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/apps/${id}`).then(r => r.data),
  updateStatus: (id: string, status: number) =>
    client.put<ApiResponse<null>>(`/apps/${id}/status`, { status }).then(r => r.data),
  updateProtocolConfig: (id: string, config: Record<string, unknown>) =>
    client.put<ApiResponse<null>>(`/apps/${id}/config`, { protocol_config: config }).then(r => r.data),
  getProtocolConfig: (id: string) =>
    client.get<ApiResponse<Record<string, unknown>>>(`/apps/${id}/config`).then(r => r.data.data),

  // Outbound provisioning (L2 offboarding deprovision). EE-gated capability;
  // config schema is CE. Token never echoed back (token_set flags presence).
  getProvisioning: (id: string) =>
    client.get<ApiResponse<AppProvisioning>>(`/apps/${id}/provisioning`).then(r => r.data.data),
  putProvisioning: (id: string, data: AppProvisioningInput) =>
    client.put<ApiResponse<{ saved: boolean }>>(`/apps/${id}/provisioning`, data).then(r => r.data),
  regenerateSecret: (id: string) =>
    client.post<ApiResponse<{ client_secret: string }>>(`/apps/${id}/regenerate-secret`).then(r => r.data.data),
  quickstart: (id: string, lang: string) =>
    client.get<ApiResponse<{ language: string; sample: string }>>(`/apps/${id}/quickstart/${lang}`).then(r => r.data.data),
  listTemplates: () =>
    client.get<ApiResponse<AppTemplateListItem[]>>('/app-templates').then(r => r.data.data),
  getTemplate: (key: string) =>
    client.get<ApiResponse<AppTemplate>>(`/app-templates/${key}`).then(r => r.data.data),

  // Access policy bindings
  listAccess: (id: string) =>
    client.get<ApiResponse<AppAccess[]>>(`/apps/${id}/access`).then(r => r.data.data),
  addAccess: (id: string, data: { subject_type: string; subject_id: string }) =>
    client.post<ApiResponse<AppAccess>>(`/apps/${id}/access`, data).then(r => r.data.data),
  removeAccess: (id: string, accessId: string) =>
    client.delete<ApiResponse<null>>(`/apps/${id}/access/${accessId}`).then(r => r.data),

  // Certificates
  listCerts: (id: string) =>
    client.get<ApiResponse<AppCert[]>>(`/apps/${id}/certs`).then(r => r.data.data),
  createCert: (id: string) =>
    client.post<ApiResponse<AppCert>>(`/apps/${id}/certs`).then(r => r.data.data),
  deleteCert: (id: string, certId: string) =>
    client.delete<ApiResponse<null>>(`/apps/${id}/certs/${certId}`).then(r => r.data),
  rotateSigningKey: (id: string) =>
    client.post<ApiResponse<AppCert>>(`/apps/${id}/rotate-signing-key`).then(r => r.data.data),

  // SAML SP metadata import — POST raw XML, backend parses + patches
  // protocol_config in one shot. Returns the resulting config so the form
  // can refresh without an extra GET.
  importSAMLMetadata: (id: string, xml: string) =>
    client
      .post<ApiResponse<Record<string, unknown>>>(`/apps/${id}/saml/import-metadata`, xml, {
        headers: { 'Content-Type': 'application/xml' },
      })
      .then(r => r.data.data),
}

export const appGroupApi = {
  list: () =>
    client.get<ApiResponse<AppGroup[]>>('/app-groups').then(r => r.data.data),
  create: (data: { name: string; code: string; description?: string; sort_order?: number; parent_id?: string }) =>
    client.post<ApiResponse<AppGroup>>('/app-groups', data).then(r => r.data.data),
  update: (id: string, data: { name?: string; description?: string; sort_order?: number; parent_id?: string }) =>
    client.put<ApiResponse<AppGroup>>(`/app-groups/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/app-groups/${id}`).then(r => r.data),
  // Membership read-back. Backend returns the resolved App rows (not raw
  // rel records), so the caller renders the same fields it shows in the
  // global app list.
  listApps: (groupId: string) =>
    client.get<ApiResponse<App[]>>(`/app-groups/${groupId}/apps`).then(r => r.data.data),
  addApp: (groupId: string, app_id: string) =>
    client.post<ApiResponse<null>>(`/app-groups/${groupId}/apps`, { app_id }).then(r => r.data),
  removeApp: (groupId: string, appId: string) =>
    client.delete<ApiResponse<null>>(`/app-groups/${groupId}/apps/${appId}`).then(r => r.data),
}
