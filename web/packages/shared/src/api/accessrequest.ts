import { portalClient } from './client'
import type { ApiResponse } from '../types'
import type { Eligibility, AccessRequest, CreateAccessRequestBody } from '../types/access'

export const accessRequestApi = {
  listEligibilities: () =>
    portalClient.get<ApiResponse<Eligibility[]>>('/access-eligibilities').then(r => r.data.data),
  listMine: () =>
    portalClient.get<ApiResponse<AccessRequest[]>>('/access-requests').then(r => r.data.data),
  create: (data: CreateAccessRequestBody) =>
    portalClient.post<ApiResponse<AccessRequest>>('/access-requests', data).then(r => r.data.data),
  cancel: (id: string) =>
    portalClient.post<ApiResponse<unknown>>(`/access-requests/${id}/cancel`).then(r => r.data),
}
