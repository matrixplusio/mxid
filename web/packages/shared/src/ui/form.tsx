// Form primitives — FormField (label + control + inline error), Switch, Tabs
// (pill segmented control), RangePicker (date range with presets).
import { cn, useTranslation } from '@mxid/shared'
import type { ReactNode } from 'react'

// FormField — vertical label / control / error group. Required shows a star;
// error renders inline below in danger color.
export function FormField({
  label,
  required,
  error,
  hint,
  children,
}: {
  label: ReactNode
  required?: boolean
  error?: ReactNode
  hint?: ReactNode
  children: ReactNode
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-ink">
        {label}
        {required && <span className="ml-0.5 text-danger">*</span>}
      </label>
      {children}
      {error ? (
        <p className="mt-1 text-xs text-danger">{error}</p>
      ) : (
        hint && <p className="mt-1 text-xs text-faint">{hint}</p>
      )}
    </div>
  )
}

export function Switch({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'inline-flex h-5 w-9 shrink-0 items-center rounded-full px-0.5 transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-primary' : 'bg-border-strong',
      )}
    >
      <span
        className={cn(
          'h-4 w-4 rounded-full bg-white shadow transition-transform',
          checked ? 'translate-x-4' : 'translate-x-0',
        )}
      />
    </button>
  )
}

// Tabs — pill segmented control. Controlled via active/onChange.
export function Tabs({
  items,
  active,
  onChange,
  className,
}: {
  items: { key: string; label: ReactNode }[]
  active: string
  onChange: (key: string) => void
  className?: string
}) {
  return (
    <div className={cn('inline-flex gap-1 rounded-control bg-surface-muted p-1', className)}>
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          onClick={() => onChange(item.key)}
          className={cn(
            'h-8 rounded-[7px] px-3 text-sm transition-colors',
            item.key === active
              ? 'bg-surface font-medium text-ink shadow-sm'
              : 'text-muted hover:text-ink',
          )}
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}

export interface DateRange {
  start: string
  end: string
}

function toLocalDateStr(d: Date): string {
  return [d.getFullYear(), String(d.getMonth() + 1).padStart(2, '0'), String(d.getDate()).padStart(2, '0')].join('-')
}

// lastNDays — inclusive range ending today. Exported for callers to seed state.
export function lastNDays(n: number): DateRange {
  const end = new Date()
  const start = new Date()
  start.setDate(end.getDate() - (n - 1))
  return { start: toLocalDateStr(start), end: toLocalDateStr(end) }
}

const RANGE_INPUT =
  'h-9 rounded-control border border-border-strong bg-surface px-3 text-sm text-ink outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary/20'
const RANGE_PRESET =
  'h-8 rounded-control border border-border bg-surface px-3 text-sm text-muted transition-colors hover:bg-surface-muted hover:text-ink'

export function RangePicker({
  value,
  onChange,
  presets = true,
  className,
}: {
  value: DateRange
  onChange: (v: DateRange) => void
  presets?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  const presetList = [
    { label: t('common.last7Days'), days: 7 },
    { label: t('common.last30Days'), days: 30 },
    { label: t('common.last90Days'), days: 90 },
  ]
  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)}>
      {presets &&
        presetList.map(({ label, days }) => (
          <button key={days} type="button" className={RANGE_PRESET} onClick={() => onChange(lastNDays(days))}>
            {label}
          </button>
        ))}
      <input
        type="date"
        aria-label={t('common.startDate')}
        value={value.start}
        max={value.end || undefined}
        onChange={(e) => onChange({ ...value, start: e.target.value })}
        className={RANGE_INPUT}
      />
      <span className="text-sm text-muted">–</span>
      <input
        type="date"
        aria-label={t('common.endDate')}
        value={value.end}
        min={value.start || undefined}
        onChange={(e) => onChange({ ...value, end: e.target.value })}
        className={RANGE_INPUT}
      />
    </div>
  )
}
