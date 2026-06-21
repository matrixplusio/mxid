import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { appApi, useTranslation, type AppProvisioning } from '@mxid/shared'
import { Field, Input, Button } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

// ProvisioningTab — per-app outbound provisioning config (L2 offboarding
// deprovision). Only mounted when the EE SCIM connector is unlocked. The token
// is write-only: the API never echoes it (token_set flags presence), so a blank
// token on save keeps the existing one.
export default function ProvisioningTab({ appId }: { appId: string }) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [cfg, setCfg] = useState<AppProvisioning | null>(null)
  const [token, setToken] = useState('')

  useEffect(() => {
    let alive = true
    setLoading(true)
    appApi
      .getProvisioning(appId)
      .then((c) => {
        if (alive) setCfg(c)
      })
      .catch(() => {
        if (alive) setCfg(null)
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [appId])

  const save = async () => {
    if (!cfg) return
    setSaving(true)
    try {
      await appApi.putProvisioning(appId, {
        enabled: cfg.enabled,
        connector: cfg.connector || 'scim2',
        base_url: cfg.base_url,
        token, // blank keeps existing
      })
      setToken('')
      // Reflect that a token now exists if one was just set.
      setCfg((c) => (c ? { ...c, token_set: c.token_set || token !== '' } : c))
      toast.success(t('common.saveSuccess'))
    } catch (e) {
      toast.error(t('common.saveFailed'), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-gray-400" />
      </div>
    )
  }
  if (!cfg) return null

  return (
    <div className="max-w-xl space-y-5">
      <p className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700">
        {t('apps.detail.provisioning.warning')}
      </p>

      <label className="flex items-center gap-3">
        <input
          type="checkbox"
          checked={cfg.enabled}
          onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })}
          className="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary/20"
        />
        <span className="text-sm font-medium text-gray-800">{t('apps.detail.provisioning.enabled')}</span>
      </label>

      <Field label={t('apps.detail.provisioning.baseUrl')} hint={t('apps.detail.provisioning.baseUrlHint')}>
        <Input
          value={cfg.base_url}
          onChange={(e) => setCfg({ ...cfg, base_url: e.target.value })}
          placeholder="https://scim.example.com/scim/v2"
        />
      </Field>

      <Field
        label={t('apps.detail.provisioning.token')}
        hint={cfg.token_set ? t('apps.detail.provisioning.tokenSet') : t('apps.detail.provisioning.tokenHint')}
      >
        <Input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={cfg.token_set ? '••••••••' : ''}
        />
      </Field>

      <Button onClick={save} disabled={saving}>
        {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
        {t('common.save')}
      </Button>
    </div>
  )
}
