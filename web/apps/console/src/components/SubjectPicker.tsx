import { useEffect, useMemo, useRef, useState } from 'react'
import { Loader2, X, Search } from 'lucide-react'
import { userApi, groupApi, orgApi, cn, useTranslation, AccessPolicySubjectType } from '@mxid/shared'
import type { OrgNode } from '@mxid/shared'

export type SubjectType = 'user' | 'group' | 'org'

export interface SubjectOption {
  id: string
  label: string
  secondary?: string
}

interface Props {
  subjectType: SubjectType
  /** Currently selected id (empty = nothing chosen). */
  value: string
  /** Label of the current selection, shown as a chip. */
  selectedLabel?: string
  onChange: (id: string, label: string) => void
  placeholder?: string
}

// Flatten an org tree into a list so it can be searched like the paginated
// user/group lists (the org API only exposes a tree, not a keyword list).
function flattenOrgs(nodes: OrgNode[], acc: SubjectOption[] = []): SubjectOption[] {
  for (const n of nodes) {
    acc.push({ id: n.id, label: n.name, secondary: n.code })
    if (n.children?.length) flattenOrgs(n.children, acc)
  }
  return acc
}

/**
 * SubjectPicker — searchable selector for a role-binding subject. Replaces the
 * raw numeric-id input so admins pick "who" by name instead of memorising
 * snowflake ids. Backed by the existing list APIs: user (?search=), group
 * (?keyword=), org (tree, filtered client-side).
 */
export default function SubjectPicker({ subjectType, value, selectedLabel, onChange, placeholder }: Props) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [options, setOptions] = useState<SubjectOption[]>([])
  const [orgCache, setOrgCache] = useState<SubjectOption[] | null>(null)
  const boxRef = useRef<HTMLDivElement>(null)

  // Close the dropdown on outside click.
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  // Reset transient state whenever the subject type flips.
  useEffect(() => {
    setQuery('')
    setOptions([])
    setOpen(false)
  }, [subjectType])

  // Debounced search. Depends on query + subjectType.
  useEffect(() => {
    if (!open) return
    let cancelled = false
    const handle = setTimeout(async () => {
      setLoading(true)
      try {
        let opts: SubjectOption[] = []
        if (subjectType === AccessPolicySubjectType.User) {
          const data = await userApi.list({ search: query, page: 1, page_size: 10 })
          opts = data.items.map((u) => ({
            id: u.id,
            label: u.display_name || u.username,
            secondary: u.email || u.username,
          }))
        } else if (subjectType === AccessPolicySubjectType.Group) {
          const data = await groupApi.list({ keyword: query, page: 1, page_size: 10 })
          opts = data.items.map((g) => ({ id: g.id, label: g.name, secondary: g.code }))
        } else {
          let all = orgCache
          if (!all) {
            const tree = await orgApi.tree()
            all = flattenOrgs(tree)
            if (!cancelled) setOrgCache(all)
          }
          const q = query.trim().toLowerCase()
          opts = (q ? all.filter((o) => o.label.toLowerCase().includes(q) || (o.secondary || '').toLowerCase().includes(q)) : all).slice(0, 10)
        }
        if (!cancelled) setOptions(opts)
      } catch {
        if (!cancelled) setOptions([])
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [query, subjectType, open, orgCache])

  const hasSelection = value !== '' && !!selectedLabel

  const ph = useMemo(
    () => placeholder || t('permissions.subjectPicker.placeholder'),
    [placeholder, t],
  )

  if (hasSelection) {
    return (
      <div className="flex items-center justify-between rounded-lg border border-primary/30 bg-primary/5 px-3 py-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-ink">{selectedLabel}</p>
          <p className="truncate text-xs text-faint">#{value}</p>
        </div>
        <button
          type="button"
          onClick={() => onChange('', '')}
          className="ml-2 rounded p-1 text-faint hover:bg-surface-muted hover:text-ink"
          aria-label={t('common.cancel')}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    )
  }

  return (
    <div ref={boxRef} className="relative">
      <div className="flex items-center rounded-lg border border-border px-3 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/20">
        <Search className="h-4 w-4 shrink-0 text-faint" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => setOpen(true)}
          placeholder={ph}
          className="w-full bg-transparent px-2 py-2 text-sm outline-none"
        />
        {loading && <Loader2 className="h-4 w-4 shrink-0 animate-spin text-faint" />}
      </div>
      {open && (
        <div className="absolute z-20 mt-1 max-h-60 w-full overflow-auto rounded-lg border border-border bg-surface py-1 shadow-lg">
          {options.length === 0 ? (
            <p className="px-3 py-4 text-center text-xs text-faint">
              {loading ? t('common.loading') : t('permissions.subjectPicker.noResults')}
            </p>
          ) : (
            options.map((o) => (
              <button
                key={o.id}
                type="button"
                onClick={() => {
                  onChange(o.id, o.label)
                  setOpen(false)
                  setQuery('')
                }}
                className={cn(
                  'flex w-full flex-col items-start px-3 py-2 text-left hover:bg-surface-muted',
                )}
              >
                <span className="text-sm text-ink">{o.label}</span>
                {o.secondary && <span className="text-xs text-faint">{o.secondary} · #{o.id}</span>}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  )
}
