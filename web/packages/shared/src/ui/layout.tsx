// Layout / card primitives — the visual language of every page: floating
// rounded cards, KPI stat cards, page headers, filter bars. Token-driven.
import { Search } from 'lucide-react'
import { cn } from '@mxid/shared'
import type { HTMLAttributes, ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { Input } from './index'

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-card border border-border bg-surface shadow-card transition-shadow hover:shadow-hover',
        className,
      )}
      {...rest}
    />
  )
}

export function CardHeader({ title, extra }: { title: ReactNode; extra?: ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-border px-5 py-4">
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      {extra}
    </div>
  )
}

// PageHeader — title + description on the left, primary action(s) on the right.
export function PageHeader({
  title,
  description,
  extra,
}: {
  title: ReactNode
  description?: ReactNode
  extra?: ReactNode
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-bold text-ink">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {extra}
    </div>
  )
}

type StatTone = 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info'

const STAT_TONE: Record<StatTone, string> = {
  default: 'text-primary bg-gradient-to-br from-primary/15 to-primary/5',
  primary: 'text-primary bg-gradient-to-br from-primary/15 to-primary/5',
  success: 'text-success bg-gradient-to-br from-success/15 to-success/5',
  warning: 'text-warning bg-gradient-to-br from-warning/15 to-warning/5',
  danger: 'text-danger bg-gradient-to-br from-danger/15 to-danger/5',
  info: 'text-info bg-gradient-to-br from-info/15 to-info/5',
}

// StatCard — a KPI tile: tinted icon chip + big tabular number + label.
export function StatCard({
  label,
  value,
  icon: Icon,
  tone = 'default',
  sub,
}: {
  label: ReactNode
  value: ReactNode
  icon: LucideIcon
  tone?: StatTone
  sub?: ReactNode
}) {
  return (
    <Card className="flex items-center gap-4 p-5 hover:-translate-y-0.5">
      <div className={cn('flex h-11 w-11 shrink-0 items-center justify-center rounded-control', STAT_TONE[tone])}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <div className="truncate text-sm text-muted">{label}</div>
        <div className="mt-0.5 text-2xl font-bold tabular-nums text-ink">{value}</div>
        {sub && <div className="truncate text-xs text-faint">{sub}</div>}
      </div>
    </Card>
  )
}

// FilterBar — horizontal row for search + selects; `extra` sticks to the right.
export function FilterBar({ children, extra }: { children: ReactNode; extra?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {children}
      {extra && <div className="ml-auto">{extra}</div>}
    </div>
  )
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
}) {
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="pl-9"
      />
    </div>
  )
}

// ChartCard — library-agnostic chart wrapper. Pass the chart element as
// children (we render recharts directly at call sites); this owns the frame.
export function ChartCard({
  title,
  extra,
  height = 260,
  children,
}: {
  title: ReactNode
  extra?: ReactNode
  height?: number
  children: ReactNode
}) {
  return (
    <Card>
      <CardHeader title={title} extra={extra} />
      <div className="px-3 pb-4 pt-3" style={{ height }}>
        {children}
      </div>
    </Card>
  )
}
