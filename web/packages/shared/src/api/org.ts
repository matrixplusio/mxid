import { client } from './client'
import type { ApiResponse, PaginatedData, OrgNode, UserOrgInfo } from '../types'

export const orgApi = {
  tree: () =>
    client.get<ApiResponse<OrgNode[]>>('/orgs').then(r => r.data.data),
  create: (data: { parent_id?: string; name: string; code: string; sort_order?: number }) =>
    client.post<ApiResponse<OrgNode>>('/orgs', data).then(r => r.data.data),
  update: (id: string, data: { name?: string; sort_order?: number; status?: number }) =>
    client.put<ApiResponse<OrgNode>>(`/orgs/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/orgs/${id}`).then(r => r.data),
  move: (id: string, parent_id: string | null) =>
    client.put<ApiResponse<null>>(`/orgs/${id}/move`, { parent_id }).then(r => r.data),
  listMembers: (id: string, params?: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<string>>>(`/orgs/${id}/members`, { params }).then(r => r.data.data),
  addMember: (id: string, user_id: string, is_primary?: boolean) =>
    client.post<ApiResponse<null>>(`/orgs/${id}/members`, { user_id, is_primary }).then(r => r.data),
  removeMember: (id: string, userId: string) =>
    client.delete<ApiResponse<null>>(`/orgs/${id}/members/${userId}`).then(r => r.data),
  // List every org a user belongs to (feeds the user-detail Org tab).
  listByUser: (userId: string) =>
    client.get<ApiResponse<UserOrgInfo[]>>(`/users/${userId}/orgs`).then(r => r.data.data),
}
