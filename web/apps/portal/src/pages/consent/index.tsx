import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { CheckCircle2, Loader2, XCircle } from 'lucide-react'
import { portalApi, useTranslation, AppIcon } from '@mxid/shared'
import { Button } from '@mxid/shared/ui'

interface ConsentApp {
  id: string
  name: string
  description: string
  logo_url: string
  home_url: string
}

interface ScopeItem {
  scope: string
  label: string
}

// FAIL-CLOSED return_to validator — mirrors saferedirect.ValidateRelativeOrOrigin
// (pkg/saferedirect) on the client. The legitimate return_to is always the
// backend /protocol/oidc/authorize URL, which is same-origin with the portal.
// An unvalidated value here is an open redirect / javascript: sink on the IdP
// origin (e.g. /consent?return_to=https://evil or return_to=javascript:...).
// Accepts a single-slash-rooted relative path OR an absolute http(s) URL whose
// origin === the portal origin; everything else falls back to /apps.
function safeReturnTo(raw: string): string {
  const fallback = '/apps'
  if (!raw) return fallback
  // Reject ASCII control chars (CR/LF/TAB/NUL etc.) used for header/parser
  // tricks. Done without a control-char regex literal to keep the source
  // free of raw control bytes.
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return fallback
  }
  if (raw.startsWith('//') || raw.startsWith('/\\') || raw.startsWith('\\')) return fallback
  // Same-origin relative path.
  if (raw.startsWith('/')) {
    if (raw.includes('\\')) return fallback
    return raw
  }
  // Absolute URL: must parse, be http(s), carry no userinfo, and share the
  // portal's exact origin.
  try {
    const u = new URL(raw, window.location.origin)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return fallback
    if (u.username || u.password) return fallback
    if (u.origin !== window.location.origin) return fallback
    return u.href
  } catch {
    return fallback
  }
}

// Consent screen — OIDC Core 1.0 §3.1.2.4.
//
// User arrives via redirect from /protocol/oidc/authorize when the app
// requires consent and a matching grant does not yet exist. After 同意,
// posts to /api/v1/portal/consent and navigates back to `return_to`
// (the original authorize URL) so the IdP can resume the flow.
//
// 拒绝 cancels the OIDC flow per spec (returns the user to the RP with
// error=access_denied — handled here by sending the user home).
export default function ConsentPage() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const appId = params.get('app_id') || ''
  const scopeQ = params.get('scope') || ''
  const returnTo = safeReturnTo(params.get('return_to') || '')
  const scopes = scopeQ.split(/[\s+]+/).filter(Boolean)

  const [loading, setLoading] = useState(true)
  const [app, setApp] = useState<ConsentApp | null>(null)
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([])
  const [submitting, setSubmitting] = useState<'allow' | 'deny' | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    // scopes may be empty: SAML/CAS have no scopes, the page is then a pure
    // "log in to App X?" confirmation (OIDC carries scopes to grant).
    if (!appId) {
      setError(t('common.error'))
      setLoading(false)
      return
    }
    portalApi
      .consentPreview(appId, scopes)
      .then((data) => {
        setApp(data.app)
        setScopeItems(data.scopes || [])
      })
      .catch((err: Error) => setError(err.message || t('common.failed')))
      .finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appId, scopeQ])

  const handleAllow = async () => {
    if (submitting) return
    setSubmitting('allow')
    try {
      // Backend records the scope grant, mints a one-time confirm token, and
      // returns the protocol replay URL with it appended — follow that so the
      // SSO flow proceeds without re-confirming.
      const { redirect } = await portalApi.grantConsent(appId, scopes, returnTo)
      window.location.href = redirect || returnTo
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('common.failed')
      setError(msg)
      setSubmitting(null)
    }
  }

  const handleDeny = () => {
    setSubmitting('deny')
    // 用户拒绝 → 回 /authorize 带 sso_deny=1; 后端用已校验的 redirect_uri 给 RP
    // 发 access_denied (规范), 不在前端构造重定向 (避免开放重定向).
    const sep = returnTo.includes('?') ? '&' : '?'
    window.location.href = returnTo + sep + 'sso_deny=1'
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (error || !app) {
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <XCircle className="mx-auto h-12 w-12 text-red-400" />
        <p className="mt-3 text-sm text-muted">{error || t('common.empty')}</p>
      </div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="mx-auto max-w-lg"
    >
      <div className="rounded-2xl border border-border bg-surface p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-4">
          <AppIcon value={app.logo_url} fallbackName={app.name} size={56} className="rounded-xl" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold text-ink">{app.name}</h1>
            <p className="mt-0.5 text-xs text-muted">{app.description || t('portal.consent.subtitle')}</p>
          </div>
        </div>

        <p className="mb-3 text-sm font-medium text-ink">
          {scopeItems.length > 0 ? t('portal.consent.subtitle') : t('portal.consent.loginPrompt')}
        </p>
        {scopeItems.length > 0 && (
          <ul className="mb-8 space-y-2">
            {scopeItems.map((s) => (
              <li
                key={s.scope}
                className="flex items-start gap-3 rounded-lg border border-border bg-surface-muted px-3 py-2.5"
              >
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                <div className="min-w-0">
                  <p className="text-sm text-ink">{s.label}</p>
                  <p className="font-mono text-[10px] text-faint">{s.scope}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
        {scopeItems.length === 0 && <div className="mb-8" />}

        <div className="flex gap-3">
          <Button type="button" variant="secondary" className="flex-1" onClick={handleDeny} disabled={!!submitting}>
            {t('portal.consent.denyBtn')}
          </Button>
          <Button type="button" className="flex-1" onClick={handleAllow} loading={submitting === 'allow'} disabled={!!submitting}>
            {t('portal.consent.grantBtn')}
          </Button>
        </div>
      </div>

      <p className="mt-4 text-center text-xs text-faint">
        {app.name}
      </p>
    </motion.div>
  )
}
