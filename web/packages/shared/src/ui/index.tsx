// Shared UI primitives — every page MUST import from here instead of
// hand-rolling button / modal / form classes. Keeps the look consistent
// without us having to police it in code review.
import { motion } from 'framer-motion'
import { Loader2, Moon, Sun, X } from 'lucide-react'
import { cn, useTheme } from '@mxid/shared'
import type { ReactNode, ButtonHTMLAttributes, InputHTMLAttributes, TextareaHTMLAttributes, SelectHTMLAttributes } from 'react'

/* ──────────────── Motion presets ──────────────── */

// Standard page-enter animation. Spread onto the page-root <motion.div> so
// every page fades+rises identically instead of each picking its own y/duration.
//   <motion.div {...pageMotion}>
export const pageMotion = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.2 },
} as const

// Standard modal/dialog enter+exit (matches the shared Modal).
export const dialogMotion = {
  initial: { opacity: 0, scale: 0.95 },
  animate: { opacity: 1, scale: 1 },
  exit: { opacity: 0, scale: 0.95 },
} as const

/* ──────────────── Input / Textarea / Select base classes ──────────────── */

export const INPUT_CLASS =
  'w-full rounded-lg border border-border-strong bg-surface px-3 py-2 text-sm text-ink outline-none placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20 disabled:cursor-not-allowed disabled:bg-surface-muted disabled:text-faint'

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn(INPUT_CLASS, props.className)} />
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cn(INPUT_CLASS, props.className)} />
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cn(INPUT_CLASS, props.className)} />
}

/* ──────────────── Field (label + hint + child) ──────────────── */

export function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string
  hint?: ReactNode
  required?: boolean
  children: ReactNode
}) {
  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-ink">
        {label}
        {required && <span className="ml-0.5 text-danger">*</span>}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-faint">{hint}</p>}
    </div>
  )
}

/* ──────────────── Button ──────────────── */

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'warning' | 'success'

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary:   'bg-primary text-white hover:bg-primary-hover disabled:opacity-60',
  secondary: 'border border-border bg-surface text-ink hover:bg-surface-muted disabled:opacity-60',
  danger:    'border border-danger/30 bg-danger/10 text-danger hover:bg-danger/20 disabled:opacity-60',
  warning:   'border border-warning/30 bg-warning/10 text-warning hover:bg-warning/20 disabled:opacity-60',
  success:   'border border-success/30 bg-success/10 text-success hover:bg-success/20 disabled:opacity-60',
  ghost:     'text-muted hover:bg-surface-muted hover:text-ink disabled:opacity-60',
}

const SIZE_CLASS = {
  sm: 'gap-1 rounded-md px-2 py-1 text-xs',
  md: 'gap-1.5 rounded-lg px-3 py-1.5 text-sm',
  lg: 'gap-2 rounded-lg px-4 py-2 text-sm font-medium',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
  icon?: ReactNode
}

export function Button({
  variant = 'primary',
  size = 'lg',
  loading,
  icon,
  children,
  className,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cn(
        'inline-flex shrink-0 items-center justify-center whitespace-nowrap font-medium transition-colors disabled:cursor-not-allowed',
        SIZE_CLASS[size],
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : icon}
      {children}
    </button>
  )
}

/* ──────────────── Modal ──────────────── */

export function Modal({
  open,
  title,
  onClose,
  children,
  size = 'md',
}: {
  open: boolean
  title: string
  onClose: () => void
  children: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
}) {
  if (!open) return null
  const widths = {
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-2xl',
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        onClick={(e) => e.stopPropagation()}
        className={cn(
          'w-full max-h-[90vh] overflow-y-auto rounded-card bg-surface p-6 shadow-float',
          widths[size],
        )}
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-ink">{title}</h3>
          <button onClick={onClose} className="rounded p-1 text-muted hover:bg-surface-muted">
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </motion.div>
    </div>
  )
}

/* ──────────────── Status helpers ──────────────── */

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="py-16 text-center text-sm text-faint">{children}</div>
}

export function LoadingState() {
  return (
    <div className="flex items-center justify-center py-12">
      <Loader2 className="h-5 w-5 animate-spin text-faint" />
    </div>
  )
}

export function CodeBadge({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-surface-muted px-1.5 py-0.5 text-xs text-muted">{children}</code>
  )
}

/* ──────────────── Tag (status pill) ──────────────── */

type TagVariant = 'primary' | 'green' | 'amber' | 'red' | 'blue' | 'purple' | 'gray'

const TAG_CLASS: Record<TagVariant, string> = {
  primary: 'bg-primary/10 text-primary',
  green:   'bg-success/10 text-success',
  amber:   'bg-warning/10 text-warning',
  red:     'bg-danger/10 text-danger',
  blue:    'bg-info/10 text-info',
  purple:  'bg-purple-500/10 text-purple-500',
  gray:    'bg-muted/10 text-muted',
}

export function Tag({ variant = 'gray', children }: { variant?: TagVariant; children: ReactNode }) {
  return (
    <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium', TAG_CLASS[variant])}>
      {children}
    </span>
  )
}

/* ──────────────── ThemeToggle (light/dark switch) ──────────────── */

// ThemeToggle is a self-contained light/dark switch. Drop it anywhere (sidebar,
// header) — it reads/writes the shared useTheme store, so every instance stays
// in sync and persists to localStorage. `variant="ghost"` suits dark surfaces
// (sidebar); default suits light surfaces (header).
export function ThemeToggle({
  variant = 'default',
  className,
}: {
  variant?: 'default' | 'ghost'
  className?: string
}) {
  const mode = useTheme((s) => s.mode)
  const toggle = useTheme((s) => s.toggle)
  const isDark = mode === 'dark'
  return (
    <button
      type="button"
      onClick={toggle}
      title={isDark ? '切换到浅色' : '切换到深色'}
      aria-label={isDark ? '切换到浅色' : '切换到深色'}
      className={cn(
        'inline-flex h-8 w-8 items-center justify-center rounded-control transition-colors',
        variant === 'ghost'
          ? 'text-gray-400 hover:bg-white/10 hover:text-white'
          : 'text-muted hover:bg-surface-muted hover:text-ink',
        className,
      )}
    >
      {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  )
}

/* ──────────────── CodeField (code input + generators) ──────────────── */

// slugify normalizes arbitrary names to a code:
//   - latin chars lowercased
//   - whitespace + punctuation → '-'
//   - leading digits prefixed (codes must start with a letter)
//   - non-ASCII (e.g. Chinese) stripped — caller can fall back to randomCode
// Output trimmed to 30 chars to stay well under the 50-char ceiling and to
// leave room for user edits afterwards.
export function slugify(input: string): string {
  let s = input
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/[^a-z0-9-]+/g, '')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
  if (!s) return ''
  if (/^[0-9]/.test(s)) s = 'x-' + s
  return s.slice(0, 30)
}

// randomCode produces a deterministic-shape code like "g-x7k4a9p2".
// The prefix is purely decorative — callers pass "app" / "grp" / "ug" so the
// generated string still reads as belonging to the resource type.
export function randomCode(prefix = 'g'): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const rand = new Uint32Array(8)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(rand)
  } else {
    // Skip Math.random — callers in dev/test fall back via a deterministic fill.
    for (let i = 0; i < rand.length; i++) rand[i] = i * 7919
  }
  const body = Array.from(rand, (n) => alphabet[n % alphabet.length]).join('')
  return `${prefix}-${body}`
}

// CodeField wraps the standard text Input with two generators side-by-side:
//   - "按名称" → slug(name)
//   - "随机"   → randomCode(prefix)
// Pass `nameForSlug` so the slug button can compose the name as the user
// types it. If the slug would be empty (e.g. pure Chinese name), the slug
// button is disabled and the user gets a hint to use the random button.
export function CodeField({
  value,
  onChange,
  nameForSlug,
  prefix,
  placeholder = 'lark / harbor / jira ...',
  disabled,
}: {
  value: string
  onChange: (v: string) => void
  nameForSlug?: string
  prefix?: string
  placeholder?: string
  disabled?: boolean
}) {
  const slugCandidate = nameForSlug ? slugify(nameForSlug) : ''
  const canSlug = !!slugCandidate
  return (
    <div className="flex gap-2">
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={cn(INPUT_CLASS, 'flex-1 font-mono')}
      />
      <button
        type="button"
        onClick={() => canSlug && onChange(slugCandidate)}
        disabled={disabled || !canSlug}
        title={canSlug ? `生成：${slugCandidate}` : '名称不含英文字符，无法生成 slug'}
        className="shrink-0 rounded-lg border border-border bg-surface px-3 py-2 text-xs text-muted hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
      >
        按名称
      </button>
      <button
        type="button"
        onClick={() => onChange(randomCode(prefix ?? 'g'))}
        disabled={disabled}
        title="生成随机编码"
        className="shrink-0 rounded-lg border border-border bg-surface px-3 py-2 text-xs text-muted hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
      >
        随机
      </button>
    </div>
  )
}

/* ──────────────── Kit re-exports (P1) ────────────────
   Split into topic files to keep this module manageable; the barrel keeps a
   single import surface so pages still do `from '@mxid/shared/ui'`. Placed at
   the bottom so the primitives above are defined before the kit modules
   (which import Button/Input/Modal/EmptyState from here) evaluate. */
export * from './tone'
export * from './data'
export * from './overlay'
export * from './layout'
export * from './form'
