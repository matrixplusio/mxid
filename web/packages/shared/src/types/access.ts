export interface Eligibility {
  id: string
  tenant_id: string
  target_kind: 'console' | 'app'
  role_id: string
  scope_type?: string
  scope_id?: string
  app_id?: string
  requester_subject_type: 'any' | 'user' | 'group' | 'org'
  requester_subject_id: string
  allowed_durations: number[]
  max_duration_seconds: number
  approver_subject_type: 'role' | 'group' | 'user' | 'auto'
  approver_subject_id: string
  require_justification: boolean
  require_stepup: boolean
  status: number
  created_at: string
}

export interface AccessRequest {
  id: string
  tenant_id: string
  requester_id: string
  eligibility_id: string
  target_kind: 'console' | 'app'
  role_id: string
  app_id?: string
  requested_seconds: number
  justification: string
  status: 'pending' | 'approved' | 'rejected' | 'cancelled' | 'expired' | 'revoked'
  approver_id?: string
  decided_at?: string
  decision_reason: string
  activated_at?: string
  expires_at?: string
  created_at: string
}

export interface CreateAccessRequestBody {
  eligibility_id: string
  requested_seconds: number
  justification?: string
}

export interface CreateEligibilityBody {
  target_kind: 'console' | 'app'
  role_id: string
  app_id?: string
  requester_subject_type: 'any' | 'user' | 'group' | 'org'
  requester_subject_id?: string
  allowed_durations: number[]
  max_duration_seconds: number
  approver_subject_type?: 'role' | 'group' | 'user' | 'auto'
  approver_subject_id?: string
  require_justification?: boolean
  require_stepup?: boolean
}
