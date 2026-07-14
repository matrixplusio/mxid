// Toast — global success/error/info notifications.
//
// Why local to console (not @mxid/shared): toasts need framer-motion + a
// portal root from the app shell. Both console and portal can adopt this
// later; for now console is where save flows live and need feedback.
//
// Usage:
//   import { toast } from '@/components/ui/toast'
//   toast.success('保存成功')
//   toast.error('保存失败：网络错误')
//
// Mount <Toaster /> ONCE near the app root (already done in MainLayout).

import { CheckCircle2, XCircle, Info, AlertTriangle, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import i18next from 'i18next'
import { cn } from '../utils'

type ToastKind = 'success' | 'error' | 'info' | 'warning'

interface ToastItem {
  id: number
  kind: ToastKind
  message: string
  detail?: string
}

// Tiny pub-sub. No external state lib needed — Toaster subscribes,
// `toast.*` helpers publish.
let nextId = 1
type Listener = (items: ToastItem[]) => void
let items: ToastItem[] = []
const listeners = new Set<Listener>()

function emit() {
  for (const l of listeners) l(items)
}

function push(kind: ToastKind, message: string, detail?: string) {
  const id = nextId++
  const safe = message && String(message).trim() ? message : kind === 'success' ? 'OK' : kind.toUpperCase()
  items = [...items, { id, kind, message: safe, detail }]
  emit()
  // 5s for success/info, 7s for error/warning so users have time to
  // notice the toast in a busy admin UI.
  const ttl = kind === 'error' || kind === 'warning' ? 7000 : 5000
  window.setTimeout(() => dismiss(id), ttl)
}

function dismiss(id: number) {
  items = items.filter((t) => t.id !== id)
  emit()
}

export const toast = {
  success: (msg: string, detail?: string) => push('success', msg, detail),
  error: (msg: string, detail?: string) => push('error', msg, detail),
  info: (msg: string, detail?: string) => push('info', msg, detail),
  warning: (msg: string, detail?: string) => push('warning', msg, detail),
}

// Backend codes with a dedicated localized message (the API text is only a
// fallback). Keep in sync with api/client.ts CODE_* constants.
const LOCALIZED_CODES: Record<number, string> = {
  40003: 'errors.totpCodeReused', // TOTP code already consumed this window — wait for the next
  40005: 'errors.passwordReused', // new-password matches a recent one (user.codePasswordReused)
  40012: 'errors.selfApproval', // JIT approve: separation of duties — can't approve own request
  40013: 'errors.approverNotEligible', // JIT approve: not in the eligibility's approver_subject
  40332: 'errors.eeFeatureRequired', // CODE_EE_FEATURE_REQUIRED
}

// extractMessage pulls a human-readable error message from an axios / ApiError
// failure. Known codes are localized; otherwise the backend message is used.
export function extractMessage(err: unknown, fallback?: string): string {
  const fb = fallback ?? i18next.t('common.operationFailed')
  const e = err as { code?: number | string; response?: { data?: { code?: number; message?: string } }; message?: string }
  // ApiError carries a numeric `.code`; a raw axios error's `.code` is a string
  // (e.g. "ERR_BAD_REQUEST") and the backend code lives in response.data.code.
  const code = (typeof e?.code === 'number' ? e.code : undefined) ?? e?.response?.data?.code
  if (code && LOCALIZED_CODES[code]) {
    return i18next.t(LOCALIZED_CODES[code])
  }
  return e?.response?.data?.message ?? e?.message ?? fb
}

/* ──────────────── Toaster (mounts at app root) ──────────────── */

// Semantic tokens (not raw bg-emerald-50 etc): the Toaster mounts outside
// <main> so the dark-mode literal-remap shim doesn't reach it — literals would
// render as light cards in dark mode. Token utilities are theme-aware.
const KIND_STYLE: Record<ToastKind, { icon: typeof CheckCircle2; box: string; iconCls: string }> = {
  success: { icon: CheckCircle2, box: 'border-success/30 bg-success/10', iconCls: 'text-success' },
  error:   { icon: XCircle,      box: 'border-danger/30 bg-danger/10',   iconCls: 'text-danger'  },
  info:    { icon: Info,         box: 'border-primary/30 bg-primary/10', iconCls: 'text-primary' },
  warning: { icon: AlertTriangle,box: 'border-warning/30 bg-warning/10', iconCls: 'text-warning' },
}

export function Toaster() {
  const [list, setList] = useState<ToastItem[]>(items)
  useEffect(() => {
    listeners.add(setList)
    return () => {
      listeners.delete(setList)
    }
  }, [])

  return (
    // aria-live so screen readers announce toasts. Errors are assertive
    // (interrupt), the rest polite — set per-toast via role below.
    <div
      aria-live="polite"
      aria-atomic="false"
      className="pointer-events-none fixed left-1/2 top-6 z-[9999] flex w-[420px] max-w-[90vw] -translate-x-1/2 flex-col gap-2"
    >
      {list.map((t) => {
        const { icon: Icon, box, iconCls } = KIND_STYLE[t.kind]
        return (
          <div
            key={t.id}
            role={t.kind === 'error' ? 'alert' : 'status'}
            className={cn('pointer-events-auto flex items-start gap-3 rounded-lg border-2 px-5 py-4 shadow-xl', box)}
          >
            <Icon className={cn('mt-0.5 h-6 w-6 shrink-0', iconCls)} />
            <div className="min-w-0 flex-1">
              <p className="text-[15px] font-semibold text-ink">{t.message}</p>
              {t.detail && <p className="mt-1 text-sm text-muted">{t.detail}</p>}
            </div>
            <button
              type="button"
              aria-label={i18next.t('common.dismiss')}
              onClick={() => dismiss(t.id)}
              className="shrink-0 rounded p-0.5 text-faint hover:bg-surface-muted hover:text-muted"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}
