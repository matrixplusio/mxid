import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { accessApprovalApi, formatDate, useTranslation, useEdition, AccessRequestStatus } from '@mxid/shared'
import type { AccessRequest } from '@mxid/shared'
import { pageMotion, Button, Modal, Field, Textarea, Card, DataTable, FilterBar, Select, ConfirmDialog } from '@mxid/shared/ui'
import type { Column } from '@mxid/shared/ui'
import PageHeader from '../../components/layout/PageHeader'
import { toast, extractMessage } from '../../components/ui/toast'

const STATUSES = ['pending', 'approved', 'rejected', 'cancelled', 'expired', 'revoked'] as const

export default function AccessApprovalsPage() {
  const { t } = useTranslation()
  const edition = useEdition()
  const [status, setStatus] = useState<string>('pending')
  const [rows, setRows] = useState<AccessRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [rejectTargetId, setRejectTargetId] = useState<string | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [rejecting, setRejecting] = useState(false)
  const [revokeTargetId, setRevokeTargetId] = useState<string | null>(null)
  const [revoking, setRevoking] = useState(false)

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

  const openRejectModal = (id: string) => {
    setRejectTargetId(id)
    setRejectReason('')
  }

  const closeRejectModal = () => {
    // Closing/cancelling the modal aborts with no API call.
    setRejectTargetId(null)
    setRejectReason('')
  }

  const confirmReject = async () => {
    if (!rejectTargetId) return
    setRejecting(true)
    try {
      await accessApprovalApi.reject(rejectTargetId, rejectReason)
      toast.success(t('approvals.rejected'))
      closeRejectModal()
      void load()
    } catch (e) {
      toast.error(t('approvals.rejectFailed'), extractMessage(e))
    } finally {
      setRejecting(false)
    }
  }

  const confirmRevoke = async () => {
    if (!revokeTargetId) return
    setRevoking(true)
    try {
      await accessApprovalApi.revoke(revokeTargetId)
      toast.success(t('approvals.revoked'))
      setRevokeTargetId(null)
      void load()
    } catch (e) {
      toast.error(t('approvals.revokeFailed'), extractMessage(e))
    } finally {
      setRevoking(false)
    }
  }

  if (!edition.has('conditional_access')) {
    return (
      <motion.div {...pageMotion} className="p-6">
        <p className="text-muted">{t('approvals.featureDisabled')}</p>
      </motion.div>
    )
  }

  const columns: Column<AccessRequest>[] = [
    {
      key: 'requester',
      title: t('approvals.columns.requester'),
      render: (r) => <span className="font-medium text-ink">{r.requester_name || r.requester_id}</span>,
    },
    {
      key: 'target',
      title: t('approvals.columns.target'),
      render: (r) => <span className="text-muted">{r.target_kind === 'console' ? t('access.targetConsole') : t('access.targetApp')}</span>,
    },
    { key: 'role_id', title: t('approvals.columns.role'), render: (r) => <span className="text-muted">{r.role_id}</span> },
    {
      key: 'duration',
      title: t('approvals.columns.duration'),
      render: (r) => <span className="whitespace-nowrap text-muted">{Math.round(r.requested_seconds / 60)}m</span>,
    },
    {
      key: 'justification',
      title: t('approvals.columns.justification'),
      render: (r) => <span className="block max-w-xs truncate text-muted">{r.justification || '—'}</span>,
    },
    {
      key: 'expires_at',
      title: t('approvals.columns.expiresAt'),
      render: (r) => <span className="whitespace-nowrap text-muted">{r.expires_at ? formatDate(r.expires_at) : '—'}</span>,
    },
    {
      key: 'created_at',
      title: t('approvals.columns.requestedAt'),
      render: (r) => <span className="whitespace-nowrap text-muted">{formatDate(r.created_at)}</span>,
    },
    {
      key: 'actions',
      title: t('common.actions'),
      align: 'right',
      render: (r) => (
        <div className="flex items-center justify-end gap-2">
          {r.status === AccessRequestStatus.Pending && (
            <>
              <Button size="sm" onClick={() => handleApprove(r.id)}>{t('approvals.approve')}</Button>
              <Button size="sm" variant="secondary" onClick={() => openRejectModal(r.id)}>{t('approvals.reject')}</Button>
            </>
          )}
          {r.status === AccessRequestStatus.Approved && (
            <Button size="sm" variant="danger" onClick={() => setRevokeTargetId(r.id)}>{t('approvals.revoke')}</Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <motion.div {...pageMotion}>
      <PageHeader title={t('approvals.title')} description={t('approvals.subtitle')} />

      <div className="space-y-4">
        <FilterBar>
          <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-auto">
            {STATUSES.map((s) => (
              <option key={s} value={s}>{t(`access.status.${s}`, { defaultValue: s })}</option>
            ))}
          </Select>
        </FilterBar>

        <Card className="overflow-hidden hover:shadow-card">
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(r) => r.id}
            loading={loading}
            emptyText={t('approvals.empty')}
          />
        </Card>
      </div>

      <Modal
        open={rejectTargetId !== null}
        onClose={closeRejectModal}
        title={t('approvals.rejectModal.title')}
      >
        <div className="space-y-4">
          <Field label={t('approvals.rejectModal.reasonLabel')}>
            <Textarea
              rows={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder={t('approvals.rejectModal.reasonPlaceholder')}
            />
          </Field>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={closeRejectModal} disabled={rejecting}>
              {t('approvals.rejectModal.cancel')}
            </Button>
            <Button variant="danger" onClick={confirmReject} loading={rejecting}>
              {t('approvals.rejectModal.confirm')}
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={revokeTargetId !== null}
        title={t('approvals.revoke')}
        desc={t('approvals.confirmRevoke')}
        loading={revoking}
        onConfirm={confirmRevoke}
        onCancel={() => setRevokeTargetId(null)}
      />
    </motion.div>
  )
}
