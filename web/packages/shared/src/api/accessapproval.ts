import { client } from './client'
import type { ApiResponse } from '../types'
import type { Eligibility, AccessRequest, CreateEligibilityBody } from '../types/access'

export const accessApprovalApi = {
  listEligibilities: () =>
    client.get<ApiResponse<Eligibility[]>>('/access-eligibilities').then(r => r.data.data),
  createEligibility: (data: CreateEligibilityBody) =>
    client.post<ApiResponse<Eligibility>>('/access-eligibilities', data).then(r => r.data.data),
  updateEligibility: (id: string, data: CreateEligibilityBody) =>
    client.put<ApiResponse<Eligibility>>(`/access-eligibilities/${id}`, data).then(r => r.data.data),
  deleteEligibility: (id: string) =>
    client.delete<ApiResponse<null>>(`/access-eligibilities/${id}`).then(r => r.data),
  listRequests: (status: string) =>
    client.get<ApiResponse<AccessRequest[]>>('/access-requests', { params: { status } }).then(r => r.data.data),
  approve: (id: string, reason?: string) =>
    client.post<ApiResponse<AccessRequest>>(`/access-requests/${id}/approve`, { reason }).then(r => r.data.data),
  reject: (id: string, reason?: string) =>
    client.post<ApiResponse<unknown>>(`/access-requests/${id}/reject`, { reason }).then(r => r.data),
  revoke: (id: string) =>
    client.post<ApiResponse<unknown>>(`/access-requests/${id}/revoke`).then(r => r.data),
}
