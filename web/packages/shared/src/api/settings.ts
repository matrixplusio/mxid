import { client } from './client'
import type { ApiResponse } from '../types'

// ─── Mail SMTP ───
export interface MailSMTP {
  enabled: boolean
  host: string
  port: number
  username: string
  password: string
  from_address: string
  from_name: string
  tls_mode: 'none' | 'starttls' | 'tls'
  skip_verify: boolean
  helo_hostname?: string
}

export interface MailTemplate {
  subject: string
  body: string
}

export interface MailTemplates {
  email_verify: MailTemplate
  password_reset: MailTemplate
  welcome: MailTemplate
}

// ─── Security ───
export interface SecurityPolicy {
  password: {
    min_length: number
    require_uppercase: boolean
    require_lowercase: boolean
    require_number: boolean
    require_special: boolean
    history_count: number
    expire_days: number
    expire_warn_days: number
  }
  login: {
    max_failed_attempts: number
    lockout_minutes: number
    captcha_after_failures: number
  }
  session: {
    idle_minutes: number
    absolute_hours: number
    remember_me_hours: number
  }
}

// ─── Branding ───
export interface Branding {
  logo_url: string
  primary_color: string
  product_name: string
  login_page_title: string
  login_footer_html: string
  custom_css: string
}

// ─── Login methods ───
export interface LoginMethods {
  password: boolean
  sms_otp: boolean
  email_magic_link: boolean
  external_idp_first: boolean
}

// ─── Protocol defaults ───
export interface ProtocolDefaults {
  oidc_access_token_ttl_seconds: number
  oidc_refresh_token_ttl_seconds: number
  oidc_id_token_ttl_seconds: number
  default_subject_strategy: string
  saml_assertion_ttl_seconds: number
  cas_ticket_ttl_seconds: number
}

// ─── SMS ───
export interface SMS {
  enabled: boolean
  provider: string
  access_key: string
  secret: string
  sign_name: string
  template: string
  region?: string
}

// ─── Offboarding webhook ───
export interface OffboardingWebhook {
  enabled: boolean
  url: string
  secret: string
}

// ─── Audit ───
export interface AuditPolicy {
  retention_days: number
  alert_webhook_url: string
  alert_on_event_types: string[]
  high_risk_recipients: string[]
}

// ─── MFA policy ───
export type MFAMode = 'off' | 'admin_only' | 'all'
export interface MFAPolicy {
  mode: MFAMode
  step_up_window_seconds: number
}

// ─── Conditional access (adaptive auth) ───
export interface ConditionalAccess {
  enabled: boolean
  on_new_country: boolean
  on_impossible_travel: boolean
  on_new_device: boolean
  impossible_travel_window_minutes: number
}

// ─── Localization ───
export interface Localization {
  default_language: string
  default_timezone: string
  date_format: string
}

// ─── External URLs ───
// Admin-configurable canonical URLs. Empty fields fall through to the
// backend bootstrap config baked into the binary.
export interface ExternalURLs {
  issuer_url: string
  portal_url: string
  console_url: string
}

// ─── License ───
export interface License {
  key: string
  registered_to: string
  issued_at: string
  expires_at: string
  max_users: number
  max_tenants: number
  enable_enterprise: boolean
  // Read-only: whether a token is stored (the API never returns the token itself).
  key_set?: boolean
  // Read-only: this installation's fingerprint (for requesting a bound license).
  install_id?: string
}

export const settingsApi = {
  // Mail
  getMailSMTP: () =>
    client.get<ApiResponse<{ config: MailSMTP; password_set: boolean }>>('/settings/mail/smtp').then(r => r.data.data),
  putMailSMTP: (cfg: MailSMTP) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/mail/smtp', cfg).then(r => r.data),
  testMailSMTP: (to: string) =>
    client.post<ApiResponse<{ sent: boolean }>>('/settings/mail/smtp/test', { to }).then(r => r.data),

  getMailTemplates: () =>
    client.get<ApiResponse<MailTemplates>>('/settings/mail/templates').then(r => r.data.data),
  putMailTemplates: (v: MailTemplates) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/mail/templates', v).then(r => r.data),

  // Security
  getSecurity: () => client.get<ApiResponse<SecurityPolicy>>('/settings/security').then(r => r.data.data),
  putSecurity: (v: SecurityPolicy) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/security', v).then(r => r.data),

  // Branding
  getBranding: () => client.get<ApiResponse<Branding>>('/settings/branding').then(r => r.data.data),
  putBranding: (v: Branding) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/branding', v).then(r => r.data),

  // Login methods
  getLoginMethods: () => client.get<ApiResponse<LoginMethods>>('/settings/login-methods').then(r => r.data.data),
  putLoginMethods: (v: LoginMethods) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/login-methods', v).then(r => r.data),

  // Protocol defaults
  getProtocolDefaults: () => client.get<ApiResponse<ProtocolDefaults>>('/settings/protocol-defaults').then(r => r.data.data),
  putProtocolDefaults: (v: ProtocolDefaults) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/protocol-defaults', v).then(r => r.data),

  // SMS
  getSMS: () => client.get<ApiResponse<{ config: SMS; secret_set: boolean }>>('/settings/sms').then(r => r.data.data),
  putSMS: (v: SMS) => client.put<ApiResponse<{ saved: boolean }>>('/settings/sms', v).then(r => r.data),

  // Offboarding webhook
  getOffboardingWebhook: () =>
    client.get<ApiResponse<{ config: OffboardingWebhook; secret_set: boolean }>>('/settings/offboarding-webhook').then(r => r.data.data),
  putOffboardingWebhook: (v: OffboardingWebhook) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/offboarding-webhook', v).then(r => r.data),

  // Audit
  getAuditPolicy: () => client.get<ApiResponse<AuditPolicy>>('/settings/audit-policy').then(r => r.data.data),
  putAuditPolicy: (v: AuditPolicy) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/audit-policy', v).then(r => r.data),

  // MFA policy
  getMFA: () => client.get<ApiResponse<MFAPolicy>>('/settings/mfa').then(r => r.data.data),
  putMFA: (v: MFAPolicy) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/mfa', v).then(r => r.data),

  // Conditional access
  getConditionalAccess: () =>
    client.get<ApiResponse<ConditionalAccess>>('/settings/conditional-access').then(r => r.data.data),
  putConditionalAccess: (v: ConditionalAccess) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/conditional-access', v).then(r => r.data),

  // Localization
  getLocalization: () => client.get<ApiResponse<Localization>>('/settings/localization').then(r => r.data.data),
  putLocalization: (v: Localization) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/localization', v).then(r => r.data),

  // License
  getLicense: () => client.get<ApiResponse<License>>('/settings/license').then(r => r.data.data),
  putLicense: (v: License) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/license', v).then(r => r.data),

  // External URLs
  getExternalURLs: () =>
    client.get<ApiResponse<ExternalURLs>>('/settings/external-urls').then(r => r.data.data),
  putExternalURLs: (v: ExternalURLs) =>
    client.put<ApiResponse<{ saved: boolean }>>('/settings/external-urls', v).then(r => r.data),
}
