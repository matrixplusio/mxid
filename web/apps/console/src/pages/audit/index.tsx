import { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import { motion } from 'framer-motion'
import { Eye } from 'lucide-react'
import { auditApi, formatDate, useTranslation } from '@mxid/shared'
import {
  pageMotion,
  Modal,
  Card,
  DataTable,
  Pagination,
  FilterBar,
  SearchInput,
  Select,
  Switch,
  RangePicker,
} from '@mxid/shared/ui'
import type { Column, DateRange } from '@mxid/shared/ui'
import type { AuditLog, PaginatedData } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { useUrlState } from '../../hooks/useUrlState'

// Event-type → tint class. Token-based so it reads correctly in light and dark
// without leaning on the compat shim. Categories exceed the 6 semantic tones,
// so purple/teal fall back to fixed-hue tints (still alpha, dark-friendly).
function eventTypeTint(eventType: string): string {
  if (eventType === 'login.risk') return 'bg-danger/10 text-danger'
  if (eventType.startsWith('user.')) return 'bg-info/10 text-info'
  if (eventType.startsWith('app.')) return 'bg-purple-500/10 text-purple-500'
  if (eventType.startsWith('role.')) return 'bg-warning/10 text-warning'
  if (eventType.startsWith('group.')) return 'bg-teal-500/10 text-teal-500'
  if (eventType.startsWith('org.')) return 'bg-success/10 text-success'
  return 'bg-muted/10 text-muted'
}

function useEventTypes() {
  const { t } = useTranslation()
  return useMemo(() => ([
    { value: '', label: t('audit.events.all') },
    { value: 'login.risk', label: t('audit.events.loginRisk') },
    { value: 'user.login', label: t('audit.events.userLogin') },
    { value: 'user.logout', label: t('audit.events.userLogout') },
    { value: 'user.create', label: t('audit.events.userCreate') },
    { value: 'user.update', label: t('audit.events.userUpdate') },
    { value: 'user.delete', label: t('audit.events.userDelete') },
    { value: 'user.status_change', label: t('audit.events.userStatusChange') },
    { value: 'user.password_reset', label: t('audit.events.userPasswordReset') },
    { value: 'app.create', label: t('audit.events.appCreate') },
    { value: 'app.update', label: t('audit.events.appUpdate') },
    { value: 'app.delete', label: t('audit.events.appDelete') },
    { value: 'role.create', label: t('audit.events.roleCreate') },
    { value: 'role.update', label: t('audit.events.roleUpdate') },
    { value: 'role.delete', label: t('audit.events.roleDelete') },
    { value: 'role.permission_set', label: t('audit.events.rolePermissionSet') },
    { value: 'role.member_add', label: t('audit.events.roleMemberAdd') },
    { value: 'role.member_remove', label: t('audit.events.roleMemberRemove') },
    { value: 'group.create', label: t('audit.events.groupCreate') },
    { value: 'group.delete', label: t('audit.events.groupDelete') },
    { value: 'group.member_add', label: t('audit.events.groupMemberAdd') },
    { value: 'group.member_remove', label: t('audit.events.groupMemberRemove') },
    { value: 'org.create', label: t('audit.events.orgCreate') },
    { value: 'org.delete', label: t('audit.events.orgDelete') },
  ]), [t])
}

function EventPill({ eventType, label }: { eventType: string; label: string }) {
  return (
    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${eventTypeTint(eventType)}`}>
      {label}
    </span>
  )
}

function DetailRow({ label, children, wide }: { label: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? 'col-span-2' : undefined}>
      <p className="text-xs font-medium text-faint">{label}</p>
      <p className="mt-1 text-sm text-ink">{children}</p>
    </div>
  )
}

function DetailModal({ log, onClose }: { log: AuditLog; onClose: () => void }) {
  const { t } = useTranslation()
  const eventTypes = useEventTypes()
  const getEventLabel = (et: string) => eventTypes.find((x) => x.value === et)?.label ?? et
  return (
    <Modal open title={t('audit.detailModalTitle')} onClose={onClose} size="xl">
      <div className="mb-6 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs font-medium text-faint">{t('audit.fields.eventType')}</p>
          <p className="mt-1"><EventPill eventType={log.event_type} label={getEventLabel(log.event_type)} /></p>
        </div>
        <DetailRow label={t('audit.fields.time')}>{formatDate(log.created_at)}</DetailRow>
        <DetailRow label={t('audit.fields.actor')}>{log.actor_name || '-'}</DetailRow>
        <DetailRow label={t('audit.fields.ip')}>{log.ip || '-'}</DetailRow>
        <DetailRow label={t('audit.fields.resourceType')}>{log.resource_type}</DetailRow>
        <div>
          <p className="text-xs font-medium text-faint">{t('audit.fields.resourceId')}</p>
          <p className="mt-1">
            <code className="rounded bg-surface-muted px-2 py-0.5 text-xs text-muted">{log.resource_id}</code>
          </p>
        </div>
        {log.user_agent && (
          <DetailRow label={t('audit.fields.userAgent')} wide>
            <span className="break-all">{log.user_agent}</span>
          </DetailRow>
        )}
      </div>
      <div>
        <p className="mb-2 text-xs font-medium text-faint">{t('audit.fields.detailData')}</p>
        {Object.keys(log.detail).length > 0 ? (
          <pre className="max-h-64 overflow-auto rounded-lg bg-surface-muted p-4 text-xs leading-relaxed text-ink">
            {JSON.stringify(log.detail, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-faint">{t('audit.fields.noDetail')}</p>
        )}
      </div>
    </Modal>
  )
}

export default function AuditPage() {
  const { t } = useTranslation()
  const eventTypes = useEventTypes()
  const getEventLabel = (et: string) => eventTypes.find((x) => x.value === et)?.label ?? et

  // Filters + pagination live in the URL (shareable / back-forward safe).
  const [q, setQ] = useUrlState({ page: 1, event_type: '', keyword: '', start: '', end: '', hide_api: 1 })
  const [data, setData] = useState<PaginatedData<AuditLog>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  const [detailLog, setDetailLog] = useState<AuditLog | null>(null)

  // Local echo for the debounced keyword box.
  const [kw, setKw] = useState(q.keyword)
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page: q.page, page_size: 20 }
      if (q.event_type) params.event_type = q.event_type
      if (q.start) params.start_time = q.start
      if (q.end) params.end_time = q.end
      if (q.keyword) params.keyword = q.keyword
      if (q.hide_api) params.hide_api = true
      const result = await auditApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [q.page, q.event_type, q.start, q.end, q.keyword, q.hide_api])

  useEffect(() => {
    loadData()
  }, [loadData])

  const onKeyword = (val: string) => {
    setKw(val)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setQ({ keyword: val, page: 1 }), 400)
  }

  const range: DateRange = { start: q.start, end: q.end }

  const columns: Column<AuditLog>[] = [
    {
      key: 'created_at',
      title: t('audit.cols.time'),
      render: (l) => <span className="whitespace-nowrap text-muted">{formatDate(l.created_at)}</span>,
    },
    {
      key: 'event_type',
      title: t('audit.cols.eventType'),
      render: (l) => <EventPill eventType={l.event_type} label={getEventLabel(l.event_type)} />,
    },
    { key: 'actor_name', title: t('audit.cols.actor'), render: (l) => <span className="text-muted">{l.actor_name || '-'}</span> },
    { key: 'resource_type', title: t('audit.cols.resourceType'), render: (l) => <span className="text-muted">{l.resource_type}</span> },
    {
      key: 'resource_id',
      title: t('audit.cols.resourceId'),
      render: (l) => <code className="rounded bg-surface-muted px-2 py-0.5 text-xs text-muted">{l.resource_id}</code>,
    },
    { key: 'ip', title: t('audit.cols.ip'), render: (l) => <span className="text-faint">{l.ip || '-'}</span> },
    {
      key: 'detail',
      title: t('audit.cols.detail'),
      align: 'right',
      render: (l) => (
        <button
          onClick={(e) => {
            e.stopPropagation()
            setDetailLog(l)
          }}
          className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/10"
        >
          <Eye className="h-3.5 w-3.5" />
          {t('audit.viewDetail')}
        </button>
      ),
    },
  ]

  return (
    <motion.div {...pageMotion}>
      <PageHeader title={t('audit.title')} description={t('audit.subtitle')} />

      <div className="space-y-4">
        <FilterBar
          extra={
            <label className="flex cursor-pointer select-none items-center gap-2 text-sm text-muted">
              {t('audit.filters.hideApi')}
              <Switch checked={!!q.hide_api} onChange={(v) => setQ({ hide_api: v ? 1 : 0, page: 1 })} />
            </label>
          }
        >
          <SearchInput
            value={kw}
            onChange={onKeyword}
            placeholder={t('audit.filters.keywordPlaceholder')}
            className="w-56"
          />
          <Select
            value={q.event_type}
            onChange={(e) => setQ({ event_type: e.target.value, page: 1 })}
            className="w-auto"
          >
            {eventTypes.map((et) => (
              <option key={et.value} value={et.value}>{et.label}</option>
            ))}
          </Select>
          <RangePicker value={range} onChange={(r) => setQ({ start: r.start, end: r.end, page: 1 })} presets={false} />
        </FilterBar>

        <Card className="overflow-hidden hover:shadow-card">
          <DataTable
            columns={columns}
            rows={data.items}
            rowKey={(l) => l.id}
            loading={loading}
            onRowClick={(l) => setDetailLog(l)}
          />
          {data.total > 0 && (
            <div className="border-t border-border">
              <Pagination page={q.page} pageSize={data.page_size} total={data.total} onChange={(p) => setQ({ page: p })} />
            </div>
          )}
        </Card>
      </div>

      {detailLog && <DetailModal log={detailLog} onClose={() => setDetailLog(null)} />}
    </motion.div>
  )
}
