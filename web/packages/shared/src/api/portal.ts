import { portalClient } from './client'
import type {
  ApiResponse,
  PortalApp,
  PortalAppGroup,
  SessionInfo,
  MFAInfo,
  IdentityInfo,
  UserDetail,
  FormFillExtToken,
} from '../types'

interface PortalUserInfo {
  id: string
  username: string
  email: string
  email_verified: boolean
  phone: string
  display_name: string
  avatar: string
  status: number
  last_login_at: string | null
}

interface ProfileResponse {
  user: PortalUserInfo
  detail: UserDetail
}

export const portalApi = {
  // Apps. `q` is an optional substring filter (server-side, pg_trgm-backed).
  listApps: (q?: string) =>
    portalClient
      .get<ApiResponse<PortalApp[]>>('/apps', { params: q ? { q } : undefined })
      .then(r => r.data.data),
  launchApp: (id: string) =>
    portalClient.get<ApiResponse<{ launch_url: string }>>(`/apps/${id}/launch`).then(r => r.data.data),
  // Form-fill (SWA) per-user credential. The user stores their own downstream
  // login here; the browser extension reveals + auto-submits it (reveal is
  // extension-only and never exposed to the portal UI).
  setAppCredential: (id: string, body: { account: string; credential: string }) =>
    portalClient.put<ApiResponse<null>>(`/apps/${id}/credential`, body).then(r => r.data),
  deleteAppCredential: (id: string) =>
    portalClient.delete<ApiResponse<null>>(`/apps/${id}/credential`).then(r => r.data),
  // Form-fill browser extensions the user has paired (binding tokens). Revoke is
  // step-up gated server-side.
  listExtTokens: () =>
    portalClient.get<ApiResponse<FormFillExtToken[]>>('/formfill/tokens').then(r => r.data.data),
  revokeExtToken: (id: string) =>
    portalClient.delete<ApiResponse<null>>(`/formfill/tokens/${id}`).then(r => r.data),
  listAppGroups: () =>
    portalClient.get<ApiResponse<PortalAppGroup[]>>('/app-groups').then(r => r.data.data),
  listFavorites: () =>
    portalClient.get<ApiResponse<{ app_ids: string[] }>>('/apps/favorites').then(r => r.data.data.app_ids),
  addFavorite: (id: string) =>
    portalClient.post<ApiResponse<null>>(`/apps/${id}/favorite`).then(r => r.data),
  removeFavorite: (id: string) =>
    portalClient.delete<ApiResponse<null>>(`/apps/${id}/favorite`).then(r => r.data),
  reorderFavorites: (app_ids: string[]) =>
    portalClient.patch<ApiResponse<null>>('/apps/favorites/order', { app_ids }).then(r => r.data),
  listRecentApps: (limit = 4) =>
    portalClient
      .get<ApiResponse<{ app_ids: string[] }>>('/apps/recent', { params: { limit } })
      .then(r => r.data.data.app_ids),

  // Profile
  getProfile: () =>
    portalClient.get<ApiResponse<ProfileResponse>>('/profile').then(r => r.data.data),
  updateProfile: (data: { display_name?: string; phone?: string; email?: string }) =>
    portalClient.put<ApiResponse<null>>('/profile', data).then(r => r.data),
  updateAvatar: (avatar: string) =>
    portalClient.put<ApiResponse<null>>('/profile/avatar', { avatar }).then(r => r.data),
  sendEmailVerification: () =>
    portalClient
      .post<ApiResponse<{ sent: boolean; email: string; ttl_seconds: number; dev_link: string }>>(
        '/profile/email/send-verification',
      )
      .then(r => r.data.data),

  // Security
  changePassword: (old_password: string, new_password: string) =>
    portalClient.put<ApiResponse<null>>('/security/password', { old_password, new_password }).then(r => r.data),
  listMFA: () =>
    portalClient.get<ApiResponse<MFAInfo[]>>('/security/mfa').then(r => r.data.data),
  setupTOTP: () =>
    portalClient.post<ApiResponse<{ secret: string; qr_url: string }>>('/security/mfa/totp/setup').then(r => r.data.data),
  verifyTOTP: (code: string) =>
    portalClient.post<ApiResponse<null>>('/security/mfa/totp/verify', { code }).then(r => r.data),
  deleteTOTP: () =>
    portalClient.delete<ApiResponse<null>>('/security/mfa/totp').then(r => r.data),
  listIdentities: () =>
    portalClient.get<ApiResponse<IdentityInfo[]>>('/security/identities').then(r => r.data.data),
  listSessions: () =>
    portalClient.get<ApiResponse<SessionInfo[]>>('/security/sessions').then(r => r.data.data),
  deleteSession: (sid: string) =>
    portalClient.delete<ApiResponse<null>>(`/security/sessions/${sid}`).then(r => r.data),

  // Consent
  consentPreview: (appId: string, scopes: string[]) =>
    portalClient
      .get<ApiResponse<{ app: { id: string; name: string; description: string; logo_url: string; home_url: string }; scopes: { scope: string; label: string }[] }>>(
        '/consent/preview',
        { params: { app_id: appId, scope: scopes } }
      )
      .then(r => r.data.data),
  grantConsent: (appId: string, scopes: string[], returnTo: string) =>
    portalClient
      .post<ApiResponse<{ redirect: string }>>('/consent', { app_id: appId, scopes, return_to: returnTo })
      .then(r => r.data.data),
  listConsents: () =>
    portalClient
      .get<ApiResponse<Array<{ app_id: string; app: { id: string; name: string; logo_url: string }; scopes: string[]; granted_at: string }>>>('/consent/granted')
      .then(r => r.data.data),
  revokeConsent: (appId: string) =>
    portalClient.delete<ApiResponse<null>>(`/consent/${appId}`).then(r => r.data),
}
