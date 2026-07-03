import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { accessRequestApi } from '@mxid/shared/api'
import type { Eligibility, AccessRequest } from '@mxid/shared/api'
import { Button, Modal, Field, Select, Textarea, pageMotion, LoadingState } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import { formatDate, useTranslation } from '@mxid/shared'

const DURATION_LABELS: Record<number, string> = {
  3600: '1h',
  14400: '4h',
  86400: '24h',
  259200: '72h',
  604800: '7d',
}

function durationLabel(seconds: number): string {
  return DURATION_LABELS[seconds] ?? `${seconds}s`
}

const STATUS_VARIANT: Record<string, string> = {
  pending: 'bg-amber-100 text-amber-700',
  approved: 'bg-emerald-100 text-emerald-700',
  rejected: 'bg-red-100 text-red-700',
  cancelled: 'bg-gray-100 text-gray-600',
  expired: 'bg-gray-100 text-gray-500',
  revoked: 'bg-red-100 text-red-600',
}

export default function AccessRequestsPage() {
  const { t } = useTranslation()
  const [requests, setRequests] = useState<AccessRequest[]>([])
  const [eligibilities, setEligibilities] = useState<Eligibility[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [selEligID, setSelEligID] = useState('')
  const [duration, setDuration] = useState(0)
  const [justification, setJustification] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [cancelling, setCancelling] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const [reqs, eligs] = await Promise.all([
        accessRequestApi.listMine(),
        accessRequestApi.listEligibilities(),
      ])
      setRequests(reqs ?? [])
      setEligibilities(eligs ?? [])
    } catch (e) {
      toast.error(t('access.loadFailed'), extractMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const selectedElig = eligibilities.find(e => e.id === selEligID)

  const closeModal = () => {
    setModalOpen(false)
    setSelEligID('')
    setDuration(0)
    setJustification('')
  }

  const submit = async () => {
    if (!selEligID || !duration) {
      toast.error(t('access.pickEligAndDuration'))
      return
    }
    setSubmitting(true)
    try {
      await accessRequestApi.create({
        eligibility_id: selEligID,
        requested_seconds: duration,
        justification: justification.trim() || undefined,
      })
      toast.success(t('access.requestSubmitted'))
      closeModal()
      load()
    } catch (e) {
      toast.error(t('access.requestFailed'), extractMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  const cancel = async (id: string) => {
    setCancelling(id)
    try {
      await accessRequestApi.cancel(id)
      toast.success(t('access.cancelled'))
      load()
    } catch (e) {
      toast.error(t('access.cancelFailed'), extractMessage(e))
    } finally {
      setCancelling(null)
    }
  }

  return (
    <motion.div {...pageMotion} className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">{t('access.title')}</h1>
          <p className="mt-0.5 text-sm text-gray-500">{t('access.subtitle')}</p>
        </div>
        <Button onClick={() => setModalOpen(true)} disabled={eligibilities.length === 0 && !loading}>
          {t('access.newRequest')}
        </Button>
      </div>

      {loading ? (
        <LoadingState />
      ) : (
        <div className="space-y-2">
          {requests.length === 0 && (
            <div className="rounded-lg border border-dashed border-gray-200 px-4 py-10 text-center text-sm text-gray-400">
              {t('access.empty')}
            </div>
          )}
          {requests.map(r => (
            <div
              key={r.id}
              className="flex items-center justify-between rounded-lg border border-gray-200 bg-white px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-gray-900 text-sm">
                    {r.target_kind === 'console' ? t('access.targetConsole') : t('access.targetApp')}
                  </span>
                  <span className="text-gray-400 text-xs">·</span>
                  <span className="text-gray-600 text-sm">{r.role_id}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${STATUS_VARIANT[r.status] ?? 'bg-gray-100 text-gray-600'}`}
                  >
                    {t(`access.status.${r.status}`, { defaultValue: r.status })}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-gray-500 flex items-center gap-2">
                  <span>{durationLabel(r.requested_seconds)}</span>
                  {r.expires_at && (
                    <>
                      <span>·</span>
                      <span>{t('access.expiresAt')} {formatDate(r.expires_at)}</span>
                    </>
                  )}
                  <span>·</span>
                  <span>{formatDate(r.created_at)}</span>
                </div>
                {r.justification && (
                  <div className="mt-1 text-xs text-gray-400 truncate max-w-lg">{r.justification}</div>
                )}
              </div>
              {r.status === 'pending' && (
                <Button
                  variant="secondary"
                  size="sm"
                  loading={cancelling === r.id}
                  onClick={() => cancel(r.id)}
                >
                  {t('common.cancel')}
                </Button>
              )}
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={closeModal} title={t('access.newRequest')}>
        <div className="space-y-4">
          <Field label={t('access.eligibility')} required>
            <Select
              value={selEligID}
              onChange={e => {
                setSelEligID(e.target.value)
                setDuration(0)
              }}
            >
              <option value="">{t('access.selectEligibility')}</option>
              {eligibilities.map(el => (
                <option key={el.id} value={el.id}>
                  {el.target_kind === 'console' ? t('access.targetConsole') : t('access.targetApp')} · {el.role_id}
                </option>
              ))}
            </Select>
          </Field>

          {selectedElig && (
            <Field label={t('access.duration')} required>
              <Select
                value={duration}
                onChange={e => setDuration(Number(e.target.value))}
              >
                <option value={0}>{t('access.selectDuration')}</option>
                {selectedElig.allowed_durations.map(d => (
                  <option key={d} value={d}>
                    {durationLabel(d)}
                  </option>
                ))}
              </Select>
            </Field>
          )}

          <Field label={t('access.justification')}>
            <Textarea
              rows={3}
              value={justification}
              onChange={e => setJustification(e.target.value)}
              placeholder={t('access.justificationPlaceholder')}
            />
          </Field>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={closeModal} disabled={submitting}>
              {t('common.cancel')}
            </Button>
            <Button onClick={submit} loading={submitting}>
              {t('access.submit')}
            </Button>
          </div>
        </div>
      </Modal>
    </motion.div>
  )
}
