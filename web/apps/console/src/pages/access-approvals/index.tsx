import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { accessApprovalApi, formatDate, useTranslation, useEdition } from '@mxid/shared'
import type { AccessRequest } from '@mxid/shared'
import { pageMotion, Button } from '@mxid/shared/ui'
import PageHeader from '../../components/layout/PageHeader'
import { toast, extractMessage } from '../../components/ui/toast'

const STATUSES = ['pending', 'approved', 'rejected', 'expired', 'revoked'] as const

export default function AccessApprovalsPage() {
  const { t } = useTranslation()
  const edition = useEdition()
  const [status, setStatus] = useState<string>('pending')
  const [rows, setRows] = useState<AccessRequest[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setRows((await accessApprovalApi.listRequests(status)) ?? [])
    } catch (e) {
      toast.error(t('approvals.loadFailed'), extractMessage(e))
    } finally {
      setLoading(false)
    }
  }, [status, t])

  useEffect(() => {
    void load()
  }, [load])

  const handleApprove = async (id: string) => {
    try {
      await accessApprovalApi.approve(id)
      toast.success(t('approvals.approved'))
      void load()
    } catch (e) {
      toast.error(t('approvals.approveFailed'), extractMessage(e))
    }
  }

  const handleReject = async (id: string) => {
    const reason = window.prompt(t('approvals.rejectReason')) ?? ''
    try {
      await accessApprovalApi.reject(id, reason)
      toast.success(t('approvals.rejected'))
      void load()
    } catch (e) {
      toast.error(t('approvals.rejectFailed'), extractMessage(e))
    }
  }

  const handleRevoke = async (id: string) => {
    if (!confirm(t('approvals.confirmRevoke'))) return
    try {
      await accessApprovalApi.revoke(id)
      toast.success(t('approvals.revoked'))
      void load()
    } catch (e) {
      toast.error(t('approvals.revokeFailed'), extractMessage(e))
    }
  }

  if (!edition.has('conditional_access')) {
    return (
      <motion.div {...pageMotion} className="p-6">
        <p className="text-gray-500">{t('approvals.featureDisabled')}</p>
      </motion.div>
    )
  }

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('approvals.title')}
        description={t('approvals.subtitle')}
      />

      {/* Status filter */}
      <div className="mb-4 flex items-center gap-4">
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`access.status.${s}`)}
            </option>
          ))}
        </select>
      </div>

      {/* Request list */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('approvals.columns.requester')}</th>
                <th className="px-6 py-3">{t('approvals.columns.target')}</th>
                <th className="px-6 py-3">{t('approvals.columns.role')}</th>
                <th className="px-6 py-3">{t('approvals.columns.duration')}</th>
                <th className="px-6 py-3">{t('approvals.columns.justification')}</th>
                <th className="px-6 py-3">{t('approvals.columns.expiresAt')}</th>
                <th className="px-6 py-3">{t('approvals.columns.requestedAt')}</th>
                <th className="px-6 py-3 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={8} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('approvals.empty')}
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50/50">
                    <td className="px-6 py-3 text-sm font-medium text-gray-700">
                      {r.requester_id}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {r.target_kind === 'console'
                        ? t('access.targetConsole')
                        : t('access.targetApp')}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{r.role_id}</td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-600">
                      {Math.round(r.requested_seconds / 60)}m
                    </td>
                    <td className="max-w-xs truncate px-6 py-3 text-sm text-gray-500">
                      {r.justification || '—'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                      {r.expires_at ? formatDate(r.expires_at) : '—'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                      {formatDate(r.created_at)}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {r.status === 'pending' && (
                          <>
                            <Button size="sm" onClick={() => handleApprove(r.id)}>
                              {t('approvals.approve')}
                            </Button>
                            <Button
                              size="sm"
                              variant="secondary"
                              onClick={() => handleReject(r.id)}
                            >
                              {t('approvals.reject')}
                            </Button>
                          </>
                        )}
                        {r.status === 'approved' && (
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => handleRevoke(r.id)}
                          >
                            {t('approvals.revoke')}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  )
}
