import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi, setStepUpHandler, useTranslation } from '@mxid/shared'
import { Modal, Input, Button } from './ui'
import { toast, extractMessage } from './ui/toast'

// StepUpModal owns the global step-up MFA flow. On mount it registers a handler
// the API client invokes whenever a high-risk operation returns
// step_up_required: the handler opens this modal and resolves once the user
// passes MFA, at which point the client transparently replays the original
// request. It also listens for mfa-enroll-required and routes the user to set
// up MFA when policy demands it but they have no factor.
export default function StepUpModal() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const pending = useRef<{ resolve: () => void; reject: () => void } | null>(null)

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<void>((resolve, reject) => {
          pending.current = { resolve, reject }
          setCode('')
          setOpen(true)
        }),
    )
    return () => setStepUpHandler(null)
  }, [])

  useEffect(() => {
    const onEnroll = () => {
      toast.error(t('stepup.enrollRequired'))
      navigate('/account')
    }
    window.addEventListener('mxid:mfa-enroll-required', onEnroll)
    return () => window.removeEventListener('mxid:mfa-enroll-required', onEnroll)
  }, [navigate, t])

  // settle resolves (ok) or rejects (cancel) the pending client promise so the
  // interceptor either replays the original request or surfaces the 403.
  const settle = (ok: boolean) => {
    setOpen(false)
    const p = pending.current
    pending.current = null
    if (!p) return
    if (ok) p.resolve()
    else p.reject()
  }

  const submit = async () => {
    if (code.length !== 6) return
    setSubmitting(true)
    try {
      await authApi.stepUp(code)
      toast.success(t('stepup.success'))
      settle(true)
    } catch (e) {
      toast.error(t('stepup.failed'), extractMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal open={open} title={t('stepup.title')} onClose={() => settle(false)} size="sm" elevated>
      <div className="space-y-4">
        <p className="text-sm text-muted">{t('stepup.hint')}</p>
        <Input
          autoFocus
          inputMode="numeric"
          maxLength={6}
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
        />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => settle(false)} disabled={submitting}>
            {t('common.cancel')}
          </Button>
          <Button onClick={submit} loading={submitting} disabled={code.length !== 6}>
            {t('stepup.verify')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
