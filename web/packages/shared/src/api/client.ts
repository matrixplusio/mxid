import axios, { type AxiosInstance, type AxiosResponse } from 'axios'
import JSONbig from 'json-bigint'
import type { ApiResponse } from '../types'

// skipAuthEvent opts a single request out of the global mxid:unauthorized
// dispatch on 401. The SSO-bridge bootstrap uses it: a 401 from the initial
// /auth/me probe or the /auth/sso attempt must NOT trigger the app-wide
// redirect-to-login, or it would race the bridge. The AuthGuard owns the
// fallback in that flow instead.
//
// _stepUpRetried marks a request that has already been replayed once after a
// step-up challenge, so a persistent 40330 can't loop forever.
declare module 'axios' {
  interface AxiosRequestConfig {
    skipAuthEvent?: boolean
    _stepUpRetried?: boolean
  }
}

// Backend response codes the client reacts to globally.
export const CODE_STEP_UP_REQUIRED = 40330
export const CODE_MFA_ENROLL_REQUIRED = 40331
export const CODE_EE_FEATURE_REQUIRED = 40332

// Step-up handler: the console registers a callback (a modal) that resolves
// once the user passes an MFA challenge. The 403/step_up_required interceptor
// awaits it, then transparently replays the original high-risk request.
type StepUpHandler = () => Promise<void>
let stepUpHandler: StepUpHandler | null = null
export function setStepUpHandler(fn: StepUpHandler | null) {
  stepUpHandler = fn
}

// Server-issued IDs are snowflake int64 — they exceed JS Number.MAX_SAFE_INTEGER
// (2^53). axios' default JSON.parse silently rounds the last few digits, which
// breaks FK lookups (the rounded id no longer matches the DB row).
//
// json-bigint with storeAsString=true serialises every integer past the safe
// range as a string. Smaller integers (page counts, statuses, etc.) stay as
// numbers so existing code keeps compiling. Backend dtos that tag ID fields
// with `json:"id,string"` already return strings — that path is also safe.
const bigIntParser = JSONbig({ storeAsString: true })

function parseLargeIntsSafe(data: unknown): unknown {
  if (typeof data !== 'string') return data
  try {
    return bigIntParser.parse(data)
  } catch {
    return data
  }
}

// Local-storage key for the console-selected tenant id. The request
// interceptor below stamps it onto every request as X-Tenant-ID so the
// backend tenant middleware can route the request through the right tenant.
// Backend gates the override behind `tenant.manage` (super_admin), so a
// regular tenant admin can't escape their own tenant even if they tinker
// with localStorage.
export const ACTIVE_TENANT_KEY = 'mxid.active_tenant_id'

export function getActiveTenantID(): string | null {
  try {
    return localStorage.getItem(ACTIVE_TENANT_KEY)
  } catch {
    return null
  }
}
export function setActiveTenantID(id: string | null) {
  try {
    if (id) localStorage.setItem(ACTIVE_TENANT_KEY, id)
    else localStorage.removeItem(ACTIVE_TENANT_KEY)
  } catch {
    // ignore
  }
}

export function createApiClient(baseURL: string): AxiosInstance {
  const instance = axios.create({
    baseURL,
    timeout: 15000,
    withCredentials: true,
    headers: {
      'Content-Type': 'application/json',
    },
    transformResponse: [parseLargeIntsSafe],
  })

  instance.interceptors.request.use((config) => {
    const tid = getActiveTenantID()
    if (tid) {
      config.headers = config.headers ?? {}
      ;(config.headers as Record<string, string>)['X-Tenant-ID'] = tid
    }
    return config
  })

  instance.interceptors.response.use(
    (response: AxiosResponse<ApiResponse>) => {
      const data = response.data
      if (data.code !== 0) {
        return Promise.reject(new ApiError(data.code, data.message, data.detail))
      }
      return response
    },
    async (error) => {
      const status = error.response?.status
      const code = error.response?.data?.code

      if (status === 401 && !error.config?.skipAuthEvent) {
        window.dispatchEvent(new CustomEvent('mxid:unauthorized'))
      }

      // High-risk operation needs a fresh MFA. Run the step-up modal, then
      // replay the original request exactly once.
      if (
        status === 403 &&
        code === CODE_STEP_UP_REQUIRED &&
        stepUpHandler &&
        error.config &&
        !error.config._stepUpRetried
      ) {
        try {
          await stepUpHandler()
          error.config._stepUpRetried = true
          return instance(error.config)
        } catch {
          return Promise.reject(error)
        }
      }

      // Policy requires MFA but the user has none enrolled — route them to
      // enrollment; the SPA listens for this and navigates.
      if (status === 403 && code === CODE_MFA_ENROLL_REQUIRED) {
        window.dispatchEvent(new CustomEvent('mxid:mfa-enroll-required'))
      }

      // Surface the backend's structured error. On any non-2xx HTTP status the
      // server returns {code, message, detail}; without this the SPA only sees
      // axios' generic "Request failed with status code N" and callers reading
      // err.message localize nothing. Fall back to the raw AxiosError when the
      // body is absent (network error, non-JSON gateway page).
      const data = error.response?.data
      if (data && typeof data.code === 'number' && data.code !== 0) {
        return Promise.reject(new ApiError(data.code, data.message, data.detail))
      }

      return Promise.reject(error)
    },
  )

  return instance
}

export class ApiError extends Error {
  code: number
  detail?: string

  constructor(code: number, message: string, detail?: string) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.detail = detail
  }
}

// Default client for console (/api/v1/console)
export const client = createApiClient('/api/v1/console')

// Portal client (/api/v1/portal)
export const portalClient = createApiClient('/api/v1/portal')

// System client (/api/v1/system) — public unauthenticated metadata. Used by
// both console and portal SPAs to learn the canonical issuer / portal URLs
// before any login or interceptors run.
export const systemClient = createApiClient('/api/v1/system')
