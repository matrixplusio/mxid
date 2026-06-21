import { client } from './client'
import type { ApiResponse } from '../types'

// Offboarding review trail (Phase 1.2, L3). A task is one offboard event; its
// items are the apps the user could reach, which an admin ticks off after
// confirming downstream cleanup.

export interface OffboardingTask {
  id: string
  tenant_id: string
  user_id: string
  username: string
  status: number // 0 open, 1 resolved
  sessions_killed: number
  item_count: number
  done_count: number
  created_by?: string
  created_at: string
}

export interface OffboardingItem {
  id: string
  task_id: string
  app_id: string
  app_name: string
  app_code: string
  tier: string // L1 / L2 / L3
  status: number // 0 pending, 1 done
  done_by?: string
  done_at?: string
  created_at: string
}

interface TaskListResponse {
  items: OffboardingTask[]
  total: number
  page: number
  page_size: number
}

export const offboardingApi = {
  listTasks: (page = 1, pageSize = 20) =>
    client
      .get<ApiResponse<TaskListResponse>>('/offboarding/tasks', { params: { page, page_size: pageSize } })
      .then((r) => r.data.data),

  listItems: (taskID: string) =>
    client
      .get<ApiResponse<{ items: OffboardingItem[] }>>(`/offboarding/tasks/${taskID}/items`)
      .then((r) => r.data.data.items),

  markItemDone: (itemID: string) =>
    client.post<ApiResponse<{ done: boolean }>>(`/offboarding/items/${itemID}/done`).then((r) => r.data),
}
