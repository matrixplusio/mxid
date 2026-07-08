import { useEffect, useMemo, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import type { OrgNode, RuleExpr, RuleCondition } from '@mxid/shared'
import { groupApi, orgApi, useTranslation } from '@mxid/shared'

// Field labels shown in the dropdown — keys must match the backend
// rule-fields allow-list (see internal/domain/group/rule.go).
//
// `org_id` and `detail.department` look similar but mean different things:
//   - org_id          → 用户挂在哪个组织树节点（结构化、与组织树同源）
//   - detail.department → HR 系统传入的部门字符串（自由文本、可能与树不一致）
function useFieldLabels(): Record<string, string> {
  const { t } = useTranslation()
  return {
    username: t('groupRules.fields.username'),
    email: t('groupRules.fields.email'),
    display_name: t('groupRules.fields.displayName'),
    status: t('groupRules.fields.status'),
    org_id: t('groupRules.fields.orgId'),
    'detail.department': t('groupRules.fields.department'),
    'detail.job_title': t('groupRules.fields.jobTitle'),
    'detail.employee_no': t('groupRules.fields.employeeNo'),
  }
}

function useCmpLabels(): Record<string, string> {
  const { t } = useTranslation()
  return {
    eq: t('groupRules.cmps.eq'),
    ne: t('groupRules.cmps.ne'),
    in: t('groupRules.cmps.in'),
    contains: t('groupRules.cmps.contains'),
    startswith: t('groupRules.cmps.startswith'),
    endswith: t('groupRules.cmps.endswith'),
    in_subtree: t('groupRules.cmps.inSubtree'),
  }
}

// status accepts numeric value; provide a labelled picker.
function useStatusOptions() {
  const { t } = useTranslation()
  return [
    { value: 1, label: t('groupRules.statusOptions.active') },
    { value: 2, label: t('groupRules.statusOptions.locked') },
    { value: 3, label: t('groupRules.statusOptions.disabled') },
    { value: 4, label: t('groupRules.statusOptions.pending') },
  ]
}

// pickDefaultCmp chooses the initial operator when a field is (re)selected.
// For org_id we default to in_subtree ("包含子部门") rather than the allow-list's
// first entry (eq): the common intent "该部门下的所有人" must include members
// pinned to sub-departments. Plain eq matches only the exact node and silently
// excludes sub-org members — the classic "0 members" surprise.
function pickDefaultCmp(field: string, allowed: string[]): string {
  if (field === 'org_id' && allowed.includes('in_subtree')) return 'in_subtree'
  return allowed[0] ?? 'eq'
}

export interface RuleEditorProps {
  value: RuleExpr
  onChange: (v: RuleExpr) => void
}

export default function RuleEditor({ value, onChange }: RuleEditorProps) {
  const { t } = useTranslation()
  const FIELD_LABELS = useFieldLabels()
  const CMP_LABELS = useCmpLabels()
  const [fields, setFields] = useState<Record<string, string[]>>({})

  useEffect(() => {
    groupApi.ruleFields().then(setFields).catch(() => {})
  }, [])

  const fieldKeys = Object.keys(fields)

  const updateCondition = (i: number, patch: Partial<RuleCondition>) => {
    const next = value.conditions.slice()
    next[i] = { ...next[i], ...patch }
    onChange({ op: 'and', conditions: next })
  }

  const addCondition = () => {
    const firstField = fieldKeys[0] ?? 'email'
    const firstCmp = pickDefaultCmp(firstField, fields[firstField] ?? [])
    onChange({
      op: 'and',
      conditions: [...value.conditions, { field: firstField, cmp: firstCmp, value: '' }],
    })
  }

  const removeCondition = (i: number) => {
    const next = value.conditions.slice()
    next.splice(i, 1)
    onChange({ op: 'and', conditions: next })
  }

  return (
    <div className="space-y-2 rounded-lg border border-border bg-surface-muted p-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-muted">{t('groupRules.title')}</p>
        <button
          type="button"
          onClick={addCondition}
          className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2 py-1 text-xs text-primary hover:bg-primary/20"
        >
          <Plus className="h-3 w-3" />
          {t('groupRules.addCondition')}
        </button>
      </div>

      {value.conditions.length === 0 && (
        <p className="py-2 text-center text-xs text-faint">{t('groupRules.emptyCondition')}</p>
      )}

      <div className="space-y-2">
        {value.conditions.map((c, i) => {
          const cmps = fields[c.field] ?? []
          return (
            <div key={i} className="grid grid-cols-[1fr_1fr_1.4fr_auto] gap-2 rounded-md border border-border bg-surface p-2">
              <select
                value={c.field}
                onChange={(e) => {
                  const newField = e.target.value
                  const allowed = fields[newField] ?? []
                  updateCondition(i, {
                    field: newField,
                    cmp: allowed.includes(c.cmp) ? c.cmp : pickDefaultCmp(newField, allowed),
                    value: newField === 'status' ? 1 : '',
                  })
                }}
                className="rounded-md border border-border px-2 py-1 text-xs outline-none focus:border-primary"
              >
                {fieldKeys.map((f) => (
                  <option key={f} value={f}>
                    {FIELD_LABELS[f] ?? f}
                  </option>
                ))}
              </select>

              <select
                value={c.cmp}
                onChange={(e) => updateCondition(i, { cmp: e.target.value })}
                className="rounded-md border border-border px-2 py-1 text-xs outline-none focus:border-primary"
              >
                {cmps.map((op) => (
                  <option key={op} value={op}>
                    {CMP_LABELS[op] ?? op}
                  </option>
                ))}
              </select>

              <ConditionValue
                field={c.field}
                cmp={c.cmp}
                value={c.value}
                onChange={(v) => updateCondition(i, { value: v })}
              />

              <button
                type="button"
                onClick={() => removeCondition(i)}
                className="rounded-md p-1 text-faint hover:bg-red-50 hover:text-red-500"
                title={t('groupRules.deleteCondition')}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          )
        })}
      </div>

      <p className="text-xs text-faint">
        {t('groupRules.footerHint')}
      </p>
    </div>
  )
}

/* ─────────────────────────── Value input ────────────────────────────── */

function ConditionValue({
  field,
  cmp,
  value,
  onChange,
}: {
  field: string
  cmp: string
  value: unknown
  onChange: (v: unknown) => void
}) {
  const { t } = useTranslation()
  const STATUS_OPTIONS = useStatusOptions()
  if (field === 'status') {
    return (
      <select
        value={typeof value === 'number' ? value : Number(value) || 1}
        onChange={(e) => onChange(Number(e.target.value))}
        className="rounded-md border border-border px-2 py-1 text-xs outline-none focus:border-primary"
      >
        {STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    )
  }
  if (field === 'org_id') {
    return <OrgSelector cmp={cmp} value={value} onChange={onChange} />
  }
  return (
    <input
      type="text"
      value={typeof value === 'string' ? value : String(value ?? '')}
      onChange={(e) => onChange(e.target.value)}
      placeholder={t('groupRules.valuePlaceholder')}
      className="rounded-md border border-border px-2 py-1 text-xs outline-none focus:border-primary"
    />
  )
}

/* ─────────────────────────── OrgSelector ────────────────────────────── */

// Flat node with the depth pre-computed so the select can indent visually.
interface FlatOrg {
  id: string
  name: string
  code: string
  depth: number
}

function flattenOrgTree(nodes: OrgNode[] | undefined, depth: number, acc: FlatOrg[]): FlatOrg[] {
  if (!nodes) return acc
  for (const n of nodes) {
    acc.push({ id: String(n.id), name: n.name, code: n.code, depth })
    if (n.children && n.children.length > 0) {
      flattenOrgTree(n.children, depth + 1, acc)
    }
  }
  return acc
}

function OrgSelector({
  cmp,
  value,
  onChange,
}: {
  cmp: string
  value: unknown
  onChange: (v: unknown) => void
}) {
  const { t } = useTranslation()
  const [tree, setTree] = useState<OrgNode[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)

  useEffect(() => {
    orgApi
      .tree()
      .then((data) => setTree(data ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const flat = useMemo(() => flattenOrgTree(tree, 0, []), [tree])
  const selected = flat.find((n) => n.id === String(value ?? ''))

  const filtered = useMemo(() => {
    if (!query.trim()) return flat
    const q = query.toLowerCase()
    return flat.filter((n) => n.name.toLowerCase().includes(q) || n.code.toLowerCase().includes(q))
  }, [flat, query])

  const placeholder = cmp === 'in_subtree' ? t('groupRules.selectOrgSubtree') : t('groupRules.selectOrg')

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full truncate rounded-md border border-border px-2 py-1 text-left text-xs hover:border-primary focus:border-primary focus:outline-none"
      >
        {selected ? `${'· '.repeat(selected.depth)}${selected.name}` : <span className="text-faint">{placeholder}</span>}
      </button>
      {open && (
        <div className="absolute z-20 mt-1 w-72 rounded-md border border-border bg-surface shadow-lg">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('groupRules.searchOrgPlaceholder')}
            className="w-full border-b border-border px-2 py-1.5 text-xs outline-none"
            autoFocus
          />
          <div className="max-h-56 overflow-y-auto">
            {loading ? (
              <div className="py-3 text-center text-xs text-faint">{t('groupRules.loading')}</div>
            ) : filtered.length === 0 ? (
              <div className="py-3 text-center text-xs text-faint">{t('groupRules.noMatchOrg')}</div>
            ) : (
              filtered.map((n) => (
                <button
                  type="button"
                  key={n.id}
                  onClick={() => {
                    onChange(n.id)
                    setOpen(false)
                    setQuery('')
                  }}
                  className={
                    'flex w-full items-center justify-between px-2 py-1.5 text-left text-xs hover:bg-surface-muted ' +
                    (selected?.id === n.id ? 'bg-primary/5 text-primary' : 'text-ink')
                  }
                >
                  <span className="truncate">
                    {'· '.repeat(n.depth)}{n.name}
                  </span>
                  <code className="ml-2 shrink-0 rounded bg-surface-muted px-1 py-0.5 text-[10px] text-muted">
                    {n.code}
                  </code>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
