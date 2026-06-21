import { client } from './client'
import type {
  ApiResponse,
  PaginatedData,
  User,
  CreateUserRequest,
  UpdateUserRequest,
  UserDetail,
  UpdateUserDetailRequest,
  UserMFA,
  UserIdentity,
  UserLoginRecord,
  UserSession,
  EffectiveRole,
  BatchUserResult,
} from '../types'

// User IDs are snowflake int64 — they exceed JS Number safe range. Accept
// both number and string so legacy callers (paginated list rows that come
// in as numbers when within safe range) still compile, but the canonical
// shape is string. URL templating works on both.
type UID = string | number

export const userApi = {
  list: (params: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<User>>>('/users', { params }).then(r => r.data.data),
  getById: (id: UID) =>
    client.get<ApiResponse<User>>(`/users/${id}`).then(r => r.data.data),
  create: (data: CreateUserRequest) =>
    client.post<ApiResponse<User>>('/users', data).then(r => r.data.data),
  update: (id: UID, data: UpdateUserRequest) =>
    client.put<ApiResponse<User>>(`/users/${id}`, data).then(r => r.data.data),
  delete: (id: UID) =>
    client.delete<ApiResponse<null>>(`/users/${id}`).then(r => r.data),
  updateStatus: (id: UID, status: number) =>
    client.put<ApiResponse<null>>(`/users/${id}/status`, { status }).then(r => r.data),
  resetPassword: (id: UID, new_password: string, must_change = true) =>
    client.put<ApiResponse<null>>(`/users/${id}/password`, { new_password, must_change }).then(r => r.data),

  getDetail: (id: UID) =>
    client.get<ApiResponse<UserDetail>>(`/users/${id}/detail`).then(r => r.data.data),
  updateDetail: (id: UID, data: UpdateUserDetailRequest) =>
    client.put<ApiResponse<UserDetail>>(`/users/${id}/detail`, data).then(r => r.data.data),

  listIdentities: (id: UID) =>
    client.get<ApiResponse<UserIdentity[]>>(`/users/${id}/identities`).then(r => r.data.data),
  unbindIdentity: (id: UID, identityId: UID) =>
    client.delete<ApiResponse<null>>(`/users/${id}/identities/${identityId}`).then(r => r.data),

  listMFA: (id: UID) =>
    client.get<ApiResponse<UserMFA[]>>(`/users/${id}/mfa`).then(r => r.data.data),
  deleteMFA: (id: UID, type: string) =>
    client.delete<ApiResponse<null>>(`/users/${id}/mfa/${type}`).then(r => r.data),

  lock: (id: UID, reason: string) =>
    client.post<ApiResponse<null>>(`/users/${id}/lock`, { reason }).then(r => r.data),
  unlock: (id: UID) =>
    client.post<ApiResponse<null>>(`/users/${id}/unlock`).then(r => r.data),

  // One-click offboard: disable the account + kill every session.
  offboard: (id: UID) =>
    client.post<ApiResponse<{ offboarded: boolean }>>(`/users/${id}/offboard`).then(r => r.data),

  listSessions: (id: UID) =>
    client.get<ApiResponse<UserSession[]>>(`/users/${id}/sessions`).then(r => r.data.data),
  revokeAllSessions: (id: UID) =>
    client.delete<ApiResponse<null>>(`/users/${id}/sessions`).then(r => r.data),
  revokeSession: (id: UID, namespace: string, sid: string) =>
    client.delete<ApiResponse<null>>(`/users/${id}/sessions/${sid}`, { params: { namespace } }).then(r => r.data),

  listLoginHistory: (id: UID, params?: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<UserLoginRecord>>>(`/users/${id}/login-history`, { params }).then(r => r.data.data),

  listEffectiveRoles: (id: UID) =>
    client.get<ApiResponse<EffectiveRole[]>>(`/users/${id}/roles`).then(r => r.data.data),

  batch: (ids: string[], action: 'enable' | 'disable' | 'delete') =>
    client.post<ApiResponse<BatchUserResult>>(`/users/batch`, { ids, action }).then(r => r.data.data),
}
