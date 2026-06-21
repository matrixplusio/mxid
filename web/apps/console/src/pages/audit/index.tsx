import { useEffect, useState, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, X, Eye } from 'lucide-react'
import { auditApi, formatDate, useTranslation } from '@mxid/shared'
import { pageMotion, Button } from '@mxid/shared/ui'
import type { AuditLog, PaginatedData } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

function getEventTypeColor(eventType: string): { bg: string; text: string } {
  if (eventType === 'login.risk') return { bg: 'bg-red-50', text: 'text-red-700' }
  if (eventType.startsWith('user.')) return { bg: 'bg-blue-50', text: 'text-blue-700' }
  if (eventType.startsWith('app.')) return { bg: 'bg-purple-50', text: 'text-purple-700' }
  if (eventType.startsWith('role.')) return { bg: 'bg-amber-50', text: 'text-amber-700' }
  if (eventType.startsWith('group.')) return { bg: 'bg-teal-50', text: 'text-teal-700' }
  if (eventType.startsWith('org.')) return { bg: 'bg-emerald-50', text: 'text-emerald-700' }
  return { bg: 'bg-gray-50', text: 'text-gray-700' }
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

function DetailModal({
  log,
  onClose,
}: {
  log: AuditLog
  onClose: () => void
}) {
  const { t } = useTranslation()
  const eventTypes = useEventTypes()
  const getEventLabel = (et: string) => eventTypes.find((x) => x.value === et)?.label ?? et
  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.div
          className="relative mx-4 max-h-[80vh] w-full max-w-2xl overflow-hidden rounded-2xl bg-white shadow-xl"
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ duration: 0.2 }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
            <h3 className="text-lg font-semibold text-gray-900">{t('audit.detailModalTitle')}</h3>
            <button
              onClick={onClose}
              className="rounded-lg p-1 text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-600"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <div className="overflow-y-auto p-6">
            <div className="mb-6 grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.eventType')}</p>
                <p className="mt-1">
                  <span
                    className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${getEventTypeColor(log.event_type).bg} ${getEventTypeColor(log.event_type).text}`}
                  >
                    {getEventLabel(log.event_type)}
                  </span>
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.time')}</p>
                <p className="mt-1 text-sm text-gray-700">{formatDate(log.created_at)}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.actor')}</p>
                <p className="mt-1 text-sm text-gray-700">{log.actor_name || '-'}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.ip')}</p>
                <p className="mt-1 text-sm text-gray-700">{log.ip || '-'}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.resourceType')}</p>
                <p className="mt-1 text-sm text-gray-700">{log.resource_type}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-400">{t('audit.fields.resourceId')}</p>
                <p className="mt-1">
                  <code className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                    {log.resource_id}
                  </code>
                </p>
              </div>
              {log.user_agent && (
                <div className="col-span-2">
                  <p className="text-xs font-medium text-gray-400">{t('audit.fields.userAgent')}</p>
                  <p className="mt-1 break-all text-sm text-gray-700">{log.user_agent}</p>
                </div>
              )}
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-gray-400">{t('audit.fields.detailData')}</p>
              {Object.keys(log.detail).length > 0 ? (
                <pre className="max-h-64 overflow-auto rounded-lg bg-gray-50 p-4 text-xs leading-relaxed text-gray-700">
                  {JSON.stringify(log.detail, null, 2)}
                </pre>
              ) : (
                <p className="text-sm text-gray-400">{t('audit.fields.noDetail')}</p>
              )}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default function AuditPage() {
  const { t } = useTranslation()
  const eventTypes = useEventTypes()
  const [data, setData] = useState<PaginatedData<AuditLog>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [eventType, setEventType] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [keyword, setKeyword] = useState('')
  const [hideApi, setHideApi] = useState(true)
  const [detailLog, setDetailLog] = useState<AuditLog | null>(null)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: 20 }
      if (eventType) params.event_type = eventType
      if (startDate) params.start_time = startDate
      if (endDate) params.end_time = endDate
      if (keyword) params.keyword = keyword
      if (hideApi) params.hide_api = true
      const result = await auditApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [page, eventType, startDate, endDate, keyword, hideApi])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleFilter = () => {
    setPage(1)
  }

  const getEventLabel = (et: string) => eventTypes.find((x) => x.value === et)?.label ?? et

  const totalPages = Math.ceil(data.total / data.page_size) || 1

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('audit.title')}
        description={t('audit.subtitle')}
      />

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-end gap-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500">{t('audit.filters.keyword')}</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              placeholder={t('audit.filters.keywordPlaceholder')}
              className="w-56 rounded-lg border border-gray-200 py-2 pl-10 pr-4 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500">{t('audit.filters.eventType')}</label>
          <select
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            className="rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          >
            {eventTypes.map((et) => (
              <option key={et.value} value={et.value}>{et.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500">{t('audit.filters.startDate')}</label>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500">{t('audit.filters.endDate')}</label>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>
        <Button onClick={handleFilter}>
          {t('audit.filters.filterBtn')}
        </Button>
        <label className="flex cursor-pointer select-none items-center gap-2 pb-2 text-sm text-gray-600">
          <input
            type="checkbox"
            checked={hideApi}
            onChange={(e) => {
              setPage(1)
              setHideApi(e.target.checked)
            }}
            className="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary/20"
          />
          {t('audit.filters.hideApi')}
        </label>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('audit.cols.time')}</th>
                <th className="px-6 py-3">{t('audit.cols.eventType')}</th>
                <th className="px-6 py-3">{t('audit.cols.actor')}</th>
                <th className="px-6 py-3">{t('audit.cols.resourceType')}</th>
                <th className="px-6 py-3">{t('audit.cols.resourceId')}</th>
                <th className="px-6 py-3">{t('audit.cols.ip')}</th>
                <th className="px-6 py-3">{t('audit.cols.detail')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.empty')}
                  </td>
                </tr>
              ) : (
                data.items.map((log) => {
                  const color = getEventTypeColor(log.event_type)
                  return (
                    <tr key={log.id} className="hover:bg-gray-50/50">
                      <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-600">
                        {formatDate(log.created_at)}
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${color.bg} ${color.text}`}
                        >
                          {getEventLabel(log.event_type)}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-600">
                        {log.actor_name || '-'}
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-600">{log.resource_type}</td>
                      <td className="px-6 py-3">
                        <code className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                          {log.resource_id}
                        </code>
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-400">{log.ip || '-'}</td>
                      <td className="px-6 py-3">
                        <button
                          onClick={() => setDetailLog(log)}
                          className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/5"
                        >
                          <Eye className="h-3.5 w-3.5" />
                          {t('audit.viewDetail')}
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data.total > 0 && (
          <div className="flex items-center justify-between border-t border-gray-100 px-6 py-3">
            <p className="text-sm text-gray-500">
              {t('audit.pagingSummary', { total: data.total, page, pages: totalPages })}
            </p>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="md" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                {t('audit.prevPage')}
              </Button>
              <Button variant="secondary" size="md" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                {t('audit.nextPage')}
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {detailLog && (
        <DetailModal log={detailLog} onClose={() => setDetailLog(null)} />
      )}
    </motion.div>
  )
}
