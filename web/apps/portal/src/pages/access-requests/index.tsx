import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { accessRequestApi } from '@mxid/shared/api'
import type { Eligibility, AccessRequest } from '@mxid/shared/api'
import { Button, Modal, Field, Select, SearchSelect, Textarea, pageMotion, LoadingState } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import { formatDate, useTranslation, AccessTargetKind, AccessRequestStatus } from '@mxid/shared'

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
  cancelled: 'bg-surface-muted text-muted',
  expired: 'bg-surface-muted text-muted',
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
          <h1 className="text-xl font-semibold text-ink">{t('access.title')}</h1>
          <p className="mt-0.5 text-sm text-muted">{t('access.subtitle')}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Button onClick={() => setModalOpen(true)} disabled={eligibilities.length === 0 && !loading}>
            {t('access.newRequest')}
          </Button>
          {!loading && eligibilities.length === 0 && (
            <p className="max-w-[220px] text-right text-xs text-faint">
              {t('access.noEligibilitiesHint')}
            </p>
          )}
        </div>
      </div>

      {loading ? (
        <LoadingState />
      ) : (
        <div className="space-y-2">
          {requests.length === 0 && (
            <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-faint">
              {t('access.empty')}
            </div>
          )}
          {requests.map(r => (
            <div
              key={r.id}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-ink text-sm">
                    {r.target_kind === AccessTargetKind.Console
                      ? t('access.targetConsole')
                      : r.app_name || t('access.targetApp')}
                  </span>
                  <span className="text-faint text-xs">·</span>
                  <span className="text-muted text-sm">{r.target_name || r.role_id}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${STATUS_VARIANT[r.status] ?? 'bg-surface-muted text-muted'}`}
                  >
                    {t(`access.status.${r.status}`, { defaultValue: r.status })}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-muted flex items-center gap-2">
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
                  <div className="mt-1 text-xs text-faint truncate max-w-lg">{r.justification}</div>
                )}
              </div>
              {r.status === AccessRequestStatus.Pending && (
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
            <SearchSelect
              value={selEligID}
              onChange={(v) => {
                setSelEligID(v)
                setDuration(0)
              }}
              options={eligibilities.map((el) => ({
                value: el.id,
                label: `${el.target_kind === AccessTargetKind.Console ? t('access.targetConsole') : el.app_name || t('access.targetApp')} · ${el.target_name || el.role_id}`,
              }))}
              placeholder={t('access.selectEligibility')}
              searchPlaceholder={t('common.search')}
              emptyText={t('common.empty')}
            />
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
