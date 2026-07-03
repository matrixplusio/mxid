// Semantic tone helpers — turn business state into a color intent in ONE place
// so pages stop scattering `status === 'active' ? 'green' : 'red'` ternaries.
// A tone maps to alpha-token classes that adapt to light/dark automatically.
import type { ReactNode } from 'react'
import { cn } from '@mxid/shared'

export type StatusTone = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'primary'

const TONE_CLASS: Record<StatusTone, string> = {
  success: 'bg-success/10 text-success',
  warning: 'bg-warning/10 text-warning',
  danger: 'bg-danger/10 text-danger',
  info: 'bg-info/10 text-info',
  primary: 'bg-primary/10 text-primary',
  neutral: 'bg-muted/10 text-muted',
}

// httpTone — classic status-code bucketing (2xx ok / 3xx info / 4xx warn / 5xx err).
export function httpTone(code: number): StatusTone {
  if (code < 300) return 'success'
  if (code < 400) return 'info'
  if (code < 500) return 'warning'
  return 'danger'
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export function severityTone(level: Severity): StatusTone {
  switch (level) {
    case 'critical': return 'danger'
    case 'high': return 'warning'
    case 'medium': return 'info'
    case 'low': return 'neutral'
  }
}

// statusTone — best-effort mapping of the string states our APIs return
// (user status, task status, connection status, …) to a tone. Unknown → neutral.
const STATUS_TONE: Record<string, StatusTone> = {
  active: 'success', enabled: 'success', online: 'success', success: 'success',
  succeeded: 'success', ok: 'success', healthy: 'success', approved: 'success',
  pending: 'info', processing: 'info', running: 'info', in_progress: 'info',
  waiting: 'info', queued: 'info',
  warning: 'warning', degraded: 'warning', expiring: 'warning', partial: 'warning',
  inactive: 'neutral', disabled: 'neutral', offline: 'neutral', draft: 'neutral',
  archived: 'neutral', unknown: 'neutral',
  failed: 'danger', error: 'danger', deleted: 'danger', rejected: 'danger',
  expired: 'danger', blocked: 'danger', revoked: 'danger',
}

export function statusTone(status: string): StatusTone {
  return STATUS_TONE[status?.toLowerCase?.()] ?? 'neutral'
}

const PILL = 'inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium'

// StatusTag — the generic status pill. Pass a tone (or derive one via the
// helpers above). `dot` adds a leading indicator dot.
export function StatusTag({
  tone = 'neutral',
  dot,
  children,
}: {
  tone?: StatusTone
  dot?: boolean
  children: ReactNode
}) {
  return (
    <span className={cn(PILL, TONE_CLASS[tone])}>
      {dot && <span className="mr-1 h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}
