import { useEffect, useRef, useState } from 'react'
import { Check, ChevronDown, Search } from 'lucide-react'

export interface SearchOption {
  value: string
  label: string
}

/* SearchSelect — a single-select dropdown with a type-to-filter box. Drop-in for
   a native <select> where the option list can grow long (apps, users, roles…).
   Keeps the same visual language as the plain selects (border/rounded/padding). */
export function SearchSelect({
  value,
  onChange,
  options,
  placeholder,
  searchPlaceholder,
  emptyText,
  disabled = false,
}: {
  value: string
  onChange: (value: string) => void
  options: SearchOption[]
  placeholder: string
  searchPlaceholder: string
  emptyText: string
  disabled?: boolean
}) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const wrapRef = useRef<HTMLDivElement>(null)

  const selected = options.find((o) => o.value === value)
  const needle = q.trim().toLowerCase()
  const filtered = needle ? options.filter((o) => o.label.toLowerCase().includes(needle)) : options

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false)
        setQ('')
      }
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => !disabled && setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-left text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <span className={`truncate ${selected ? 'text-ink' : 'text-faint'}`}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown className={`h-4 w-4 shrink-0 text-faint transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute z-50 mt-1 w-full overflow-hidden rounded-lg border border-border bg-surface shadow-float">
          <div className="flex items-center gap-2 border-b border-border px-3 py-2">
            <Search className="h-3.5 w-3.5 shrink-0 text-faint" />
            <input
              autoFocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={searchPlaceholder}
              className="w-full bg-transparent text-sm text-ink outline-none placeholder:text-faint"
            />
          </div>
          <div className="max-h-56 overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <div className="px-3 py-2 text-xs text-faint">{emptyText}</div>
            ) : (
              filtered.map((o) => (
                <button
                  type="button"
                  key={o.value}
                  onClick={() => {
                    onChange(o.value)
                    setOpen(false)
                    setQ('')
                  }}
                  className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-surface-muted ${
                    o.value === value ? 'text-primary' : 'text-ink'
                  }`}
                >
                  <span className="truncate">{o.label}</span>
                  {o.value === value && <Check className="h-3.5 w-3.5 shrink-0" />}
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
