// Unified API response
export interface ApiResponse<T = unknown> {
  code: number
  message: string
  data: T
  detail?: string
}

// Paginated response data
export interface PaginatedData<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

// Auth
export interface LoginRequest {
  username: string
  password: string
  auth_type?: string
  captcha_id: string
  captcha_code: string
  remember?: boolean
  // tenant: tenant code (e.g. "matrixplus") for multi-tenant portal login.
  // Empty = default tenant. Pulled from `?tenant=` URL param on the login page.
  tenant?: string
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
}

export interface LoginResponse {
  user_id?: string
  username?: string
  display_name?: string
  session_id?: string
  // MFA challenge — when set, password was accepted but a second factor
  // is required. UI must collect the code and POST it together with the
  // challenge to /auth/mfa/verify before the user is fully logged in.
  mfa_required?: boolean
  mfa_methods?: string[]
  challenge?: string
}

export interface CurrentUser {
  user_id: string
  username: string
  display_name: string
  status: number
  // is_admin reports whether the user holds any admin permission. Portal
  // SPA shows the "switch to console" button only when true.
  is_admin?: boolean
}

// User
//
// All ID fields use `string` because backend emits int64 Snowflake IDs as
// JSON strings (Twitter/Discord convention). Numbers > 2^53 lose precision
// if treated as JS number.
export interface User {
  id: string
  tenant_id: string
  username: string
  email: string | null
  phone: string | null
  display_name: string | null
  avatar: string | null
  status: number
  last_login_at: string | null
  last_login_ip: string | null
  password_changed_at: string | null
  must_change_pwd: boolean
  created_at: string
  updated_at: string
  created_by: string | null
  updated_by: string | null
  detail?: UserDetail
}

export interface UserDetail {
  gender: number | null
  birthday: string | null
  address: string | null
  employee_no: string | null
  job_title: string | null
  department: string | null
  extra?: string | null
}

export interface UpdateUserDetailRequest {
  gender?: number | null
  birthday?: string | null
  address?: string | null
  employee_no?: string | null
  job_title?: string | null
  department?: string | null
}

export interface UserMFA {
  type: string
  is_default: boolean
  verified: boolean
  created_at: string
  updated_at: string
}

export interface UserIdentity {
  id: string
  provider_type: string
  provider_id: string
  external_id: string
  external_name?: string
  created_at: string
}

export interface UserLoginRecord {
  id: string
  tenant_id: string
  user_id?: string
  username?: string
  success: boolean
  stage: string
  auth_type: string
  reason?: string
  ip?: string
  user_agent?: string
  created_at: string
}

export interface UserSession {
  id: string
  namespace: string
  user_id: string
  ip: string
  user_agent: string
  auth_type: string
  mfa_verified: boolean
  created_at: string
  expires_at: string
  last_active_at: string
}

export interface EffectiveRole {
  role: {
    id: string
    name: string
    code: string
    type: number
    description?: string | null
  }
  source: 'direct' | 'group' | 'org'
  source_id: string
  source_name?: string
}

export interface BatchUserResult {
  affected: number
  errors: { id: string; error: string }[]
}

export interface CreateUserRequest {
  username: string
  email?: string
  phone?: string
  display_name?: string
  password: string
  status?: number
}

export interface UpdateUserRequest {
  email?: string
  phone?: string
  display_name?: string
  avatar?: string
  status?: number
}

// Organization
export interface OrgNode {
  id: string
  tenant_id: string
  parent_id: string | null
  name: string
  code: string
  path: string
  sort_order: number
  status: number
  children?: OrgNode[]
}

// Group
//
// type: 1 = static (members managed manually); 2 = dynamic (members derived
// from an attached rule and refreshed by the sync engine).
export interface Group {
  id: string
  tenant_id: string
  name: string
  code: string
  description: string | null
  type: number
  member_count: number
  created_at: string
  updated_at: string
}

// Dynamic-group rule DSL — MVP supports a single AND-list of conditions.
export interface RuleCondition {
  field: string
  cmp: string
  value: unknown
}

export interface RuleExpr {
  op: 'and'
  conditions: RuleCondition[]
}

export interface GroupRule {
  group_id: string
  expr: RuleExpr
  status: number
  last_sync_at: string | null
  last_sync_added: number
  last_sync_removed: number
  last_sync_error?: string | null
}

export interface SyncReport {
  group_id: string
  added: number
  removed: number
}

// Group member info enriched with user fields.
export interface GroupMember {
  user_id: string
  username: string
  display_name?: string
  email?: string
  avatar?: string
  status: number
}

// Batch member operation response.
export interface BatchMembersResult {
  affected: number
  skipped: string[]
}

// App
export interface App {
  id: string
  tenant_id: string
  name: string
  code: string
  protocol: string
  client_type: string
  status: number
  icon: string | null
  description: string | null
  client_id: string | null
  // client_secret plaintext is returned ONLY in the create / regenerate-secret
  // responses. List / detail reads always send an empty string here.
  client_secret?: string
  home_url: string | null
  is_first_party: boolean
  require_consent: boolean
  protocol_config: Record<string, unknown>
  login_url: string | null
  redirect_uris: string[]
  logout_url: string | null
  access_policy: number
  created_at: string
  updated_at: string
}

// AppGroup — UI 分类容器，可挂多个 app。parent_id null → 顶级
export interface AppGroup {
  id: string
  tenant_id: string
  name: string
  code: string
  description: string | null
  parent_id: string | null
  sort_order: number
  created_at: string
  updated_at: string
}

// AppAccess — 授权某主体（用户/组/部门/角色）访问指定 app
export interface AppAccess {
  id: string
  app_id: string
  subject_type: string
  subject_id: string
  created_at: string
}

// AppCert — 应用证书 / 签名密钥
export interface AppCert {
  id: string
  app_id: string
  cert_type: string
  algorithm: string
  public_key: string
  private_key?: string
  kid: string | null
  not_before: string
  expires_at: string | null
  status: number
  encrypted: boolean
  created_at: string
}

// Permission
export interface Role {
  id: string
  tenant_id: string
  name: string
  code: string
  type: number
  description: string | null
  member_count: number
  created_at: string
  updated_at: string
}

export interface RoleBinding {
  id: string
  role_id: string
  subject_type: string
  subject_id: string
  scope_type?: 'org' | 'group' | null
  scope_id?: string | null
  created_at: string
}

export const RoleType = {
  System: 1,
  Custom: 2,
} as const

export interface Permission {
  id: string
  code: string
  name: string
  resource: string
  action: string
  description: string | null
}

// Audit
export interface AuditLog {
  id: string
  tenant_id: string
  event_type: string
  actor_id: string | null
  actor_name: string | null
  resource_type: string
  resource_id: string
  detail: Record<string, unknown>
  ip: string | null
  user_agent: string | null
  created_at: string
}

// Portal types
//
// All ID fields are typed as `string` because the backend serializes int64
// Snowflake IDs as JSON strings (they exceed 2^53 and lose precision when
// parsed as JS numbers). Compare with `===`, never with arithmetic.
export interface PortalApp {
  id: string
  name: string
  code: string
  protocol: string
  client_type: string
  icon: string
  logo_url: string
  description: string
  home_url: string
  login_url: string
  group_ids: string[]
}

export interface PortalAppGroup {
  id: string
  name: string
  code: string
  parent_id?: string | null
  sort_order: number
  app_count: number
}

export interface SessionInfo {
  id: string
  ip: string
  user_agent: string
  auth_type: string
  created_at: string
  last_active_at: string
}

export interface MFAInfo {
  type: string
  is_default: boolean
  verified: boolean
}

export interface IdentityInfo {
  provider_type: string
  provider_id: string
  external_name: string
}

// Status constants
export const UserStatus = {
  Active: 1,
  Locked: 2,
  Disabled: 3,
  Pending: 4,
} as const

export const AppStatus = {
  Enabled: 1,
  Disabled: 2,
} as const

export const AppProtocol = {
  OIDC: 'oidc',
  SAML: 'saml',
  CAS: 'cas',
} as const

// Mirror of backend domain enum consts (group/tenant/externalidp/offboarding/
// access model.go). Keep the numbers/strings in sync with the Go source.
export const GroupType = { Static: 1, Dynamic: 2 } as const
export const TenantStatus = { Enabled: 1, Disabled: 2 } as const
export const IdpStatus = { Enabled: 1, Disabled: 2 } as const
export const OffboardingTaskStatus = { Open: 0, Resolved: 1 } as const
export const OffboardingItemStatus = { Pending: 0, Done: 1 } as const
export const AccessRequestStatus = { Pending: 'pending', Approved: 'approved', Rejected: 'rejected' } as const

export interface AppTemplateField {
  key: string
  label: string
  type: 'text' | 'textarea'
  placeholder?: string
  target: string // "redirect_uris" | "home_url" | "protocol_config.<name>"
}

export interface AppTemplateListItem {
  key: string
  name: string
  icon?: string
  category: string
  protocol: string
  description?: string
}

export interface AppTemplate extends AppTemplateListItem {
  client_type: string
  subject_strategy?: string
  doc_md?: string
  defaults?: Record<string, unknown>
  fields?: AppTemplateField[]
}
