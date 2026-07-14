import axios from 'axios'
import { client } from './client'
import type { ApiResponse } from '../types'

// Unauthenticated clients for the login pages' external-IdP list/start. No
// session exists yet, so these can't go through the auth-gated `client`
// (/api/v1/console) or portalClient (/api/v1/portal). Both portal + console
// use a dedicated `-public` group. IDs come back as strings, so plain axios
// is safe (no json-bigint needed).
const consolePublicRoot = axios.create({ baseURL: '/api/v1/console-public' })
const portalPublicRoot = axios.create({ baseURL: '/api/v1/portal-public' })

// ExternalIDP — admin shape with full config + status + auto_create flags.
export interface ExternalIDP {
  id: string
  tenant_id: string
  type: string
  name: string
  code: string
  icon: string | null
  description: string | null
  config: Record<string, unknown>
  status: number
  auto_create: boolean
  default_org_id: string | null
  sort_order: number
  created_at: string
  updated_at: string
}

// PublicIDP — what the portal login page fetches. Identical shape except
// `config` is intentionally blank so secrets never reach the browser.
export type PublicIDP = ExternalIDP

export const externalIdpApi = {
  // Console (admin)
  list: () => client.get<ApiResponse<ExternalIDP[]>>('/external-idps').then(r => r.data.data),
  types: () => client.get<ApiResponse<string[]>>('/external-idps/types').then(r => r.data.data),
  get: (id: string) => client.get<ApiResponse<ExternalIDP>>(`/external-idps/${id}`).then(r => r.data.data),
  create: (data: Record<string, unknown>) =>
    client.post<ApiResponse<ExternalIDP>>('/external-idps', data).then(r => r.data.data),
  update: (id: string, data: Record<string, unknown>) =>
    client.put<ApiResponse<ExternalIDP>>(`/external-idps/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/external-idps/${id}`).then(r => r.data),

  // Portal (public) — list enabled IdPs for the login page.
  // tenant: optional tenant code; backend filters the list to that tenant's
  // IdPs only. Used by multi-tenant portals where each enterprise sees
  // only its own social login buttons.
  listPublic: (tenant?: string) =>
    portalPublicRoot
      .get<ApiResponse<PublicIDP[]>>('/auth/external', { params: tenant ? { tenant } : undefined })
      .then(r => r.data.data),
  // startURL returns the absolute redirect URL the browser should hit to
  // begin the OAuth dance. The backend issues a 302 from this endpoint, so
  // setting window.location.href is the simplest way to trigger it.
  //
  // tenant: optional code. Sent through to the callback so the
  // post-login session lands in the right tenant.
  startURL: (code: string, returnTo?: string, tenant?: string) => {
    const params = new URLSearchParams()
    if (returnTo) params.set('return_to', returnTo)
    if (tenant) params.set('tenant', tenant)
    const qs = params.toString()
    return `/api/v1/portal-public/auth/external/${encodeURIComponent(code)}/start${qs ? `?${qs}` : ''}`
  },

  // Portal (public) — complete a federated login that MFA policy parked pending
  // a TOTP challenge. The callback redirected the browser to the login page with
  // ?ext_mfa=<token>; the user enters their code and this finishes the login,
  // setting the session cookies. Returns where to send the browser next.
  verifyMFA: (data: { token: string; code: string }) =>
    portalPublicRoot
      .post<ApiResponse<{ redirect: string }>>('/auth/external/mfa/verify', data)
      .then(r => r.data.data),

  // Console (public) — same shape as the portal variants but the OAuth dance
  // lands a console session (admin-gated server-side). Used by the console
  // login page to offer "sign in with Lark" to admins.
  consoleListPublic: (tenant?: string) =>
    consolePublicRoot
      .get<ApiResponse<PublicIDP[]>>('/auth/external', { params: tenant ? { tenant } : undefined })
      .then(r => r.data.data),
  consoleStartURL: (code: string, returnTo?: string, tenant?: string) => {
    const params = new URLSearchParams()
    if (returnTo) params.set('return_to', returnTo)
    if (tenant) params.set('tenant', tenant)
    const qs = params.toString()
    return `/api/v1/console-public/auth/external/${encodeURIComponent(code)}/start${qs ? `?${qs}` : ''}`
  },
}
