import { useState, useEffect, useCallback, useMemo, type FormEvent } from 'react'
import { useNavigate, useLocation, useSearchParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { authApi, externalIdpApi, ExternalIdpButtons, useAuthStore, useBootstrap, useTranslation } from '@mxid/shared'
import type { PublicIDP } from '@mxid/shared'
import { Eye, EyeOff, Loader2, RefreshCw } from 'lucide-react'
import logo from '../../assets/logo.png'

// resumeSSOIfAny inspects the URL for an in-flight protocol handshake
// (?protocol=cas|oidc|saml plus app_code + service) and, when present,
// fires a hard navigation back to the backend protocol endpoint so the
// ticket / code can be issued. Returns true when it took over the redirect.
function resumeSSOIfAny(sp: URLSearchParams): boolean {
  const protocol = sp.get('protocol')
  const appCode = sp.get('app_code')
  const service = sp.get('service')
  if (protocol === 'cas' && appCode && service) {
    window.location.replace(`/protocol/cas/${appCode}/login?service=${encodeURIComponent(service)}`)
    return true
  }
  if (protocol === 'saml' && appCode) {
    const rid = sp.get('request_id') ?? ''
    const rs = sp.get('relay_state') ?? ''
    window.location.replace(
      `/protocol/saml/${appCode}/resume?request_id=${encodeURIComponent(rid)}&relay_state=${encodeURIComponent(rs)}`,
    )
    return true
  }
  // OIDC (and any generic flow) hands back the full backend URL to resume in
  // return_to (e.g. /protocol/oidc/authorize?...). Redirect there after login so
  // the SP flow continues instead of dumping the user on /apps.
  const rt = safeSameOriginURL(sp.get('return_to'))
  if (rt) {
    window.location.replace(rt)
    return true
  }
  return false
}

// safeSameOriginURL returns raw only if it is a same-origin http(s) URL (or a
// single-slash-rooted relative path); anything else (cross-origin, javascript:,
// //evil, userinfo) yields '' so a tampered return_to can't open-redirect.
function safeSameOriginURL(raw: string | null): string {
  if (!raw) return ''
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return ''
  }
  if (raw.startsWith('//') || raw.startsWith('/\\') || raw.startsWith('\\')) return ''
  if (raw.startsWith('/')) return raw.includes('\\') ? '' : raw
  try {
    const u = new URL(raw, window.location.origin)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    if (u.username || u.password) return ''
    if (u.origin !== window.location.origin) return ''
    return u.href
  } catch {
    return ''
  }
}

// loginErrorMessage maps the backend error code to a specific, localized
// message so the user sees whether the captcha or the credentials were wrong,
// not a bare "Request failed with status code 400".
function loginErrorMessage(err: unknown, t: (k: string) => string): string {
  const e = err as { code?: number; response?: { data?: { code?: number; message?: string } } }
  const code = e?.response?.data?.code ?? e?.code
  switch (code) {
    case 40003:
    case 40004:
      return t('login.invalidCaptcha')
    case 40101:
      return t('login.invalidCredentials')
    case 40102:
      return t('login.invalidMfaCode')
    case 40301:
      return t('login.accountLocked')
    case 40302:
      return t('login.passwordExpired')
    case 40303:
      return t('login.accountDisabled')
    default:
      return e?.response?.data?.message || t('login.failedRetry')
  }
}

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams, setSearchParams] = useSearchParams()
  // Multi-tenant: URL ?tenant=<code> routes the login to that tenant. Used
  // by enterprises that share a single portal host (e.g. mxid.io/?tenant=matrixplus).
  const tenantCode = useMemo(() => searchParams.get('tenant') ?? '', [searchParams])
  const { setUser } = useAuthStore()
  // Live admin-controlled toggle: when disabled, swap form for a notice
  // so the user doesn't waste time typing into a dead form.
  const bootstrap = useBootstrap()
  const passwordEnabled = bootstrap.login_methods.password
  const idpFirst = bootstrap.login_methods.external_idp_first
  const magicLinkEnabled = bootstrap.login_methods.email_magic_link
  const smsEnabled = bootstrap.login_methods.sms_otp
  const { t } = useTranslation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaImage, setCaptchaImage] = useState('')
  const [captchaCode, setCaptchaCode] = useState('')
  // Progressive captcha: hidden until the backend demands it (40003), matching
  // the server's "captcha only after N failed attempts" policy.
  const [captchaRequired, setCaptchaRequired] = useState(false)
  const [remember, setRemember] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // MFA challenge state. Populated when /auth/login returns mfa_required.
  // Clearing the challenge returns the UI to the password step.
  const [mfaChallenge, setMfaChallenge] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  // External-IdP MFA: when a federated login (Lark, ...) is gated by a "force
  // MFA" policy, the callback bounces back here with ?ext_mfa=<token>. Present ⇒
  // show the SAME TOTP step, but finish via the external verify endpoint instead
  // of the local password-login challenge.
  const [extMfaToken, setExtMfaToken] = useState(() => searchParams.get('ext_mfa') || '')
  const showMfa = !!mfaChallenge || !!extMfaToken

  // External IdPs (social login). Empty array = no buttons rendered.
  // Filtered to the current tenant when ?tenant= is set.
  const [idps, setIdps] = useState<PublicIDP[]>([])
  useEffect(() => {
    externalIdpApi.listPublic(tenantCode || undefined).then(setIdps).catch(() => {})
  }, [tenantCode])

  const loadCaptcha = useCallback(async () => {
    try {
      const data = await authApi.portalCaptcha()
      setCaptchaId(data.captcha_id)
      setCaptchaImage(data.captcha_image)
      setCaptchaCode('')
    } catch {
      // ignore
    }
  }, [])

  // No captcha on mount — progressive: it loads only when the backend says it's
  // required (see handleSubmit's 40003/40004 handling below).

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    if (captchaRequired && !captchaCode) {
      setError(t('login.enterCaptcha'))
      return
    }

    setLoading(true)
    setError('')

    try {
      const resp = await authApi.portalLogin({
        username: username.trim(),
        password,
        captcha_id: captchaId,
        captcha_code: captchaCode,
        remember,
        tenant: tenantCode || undefined,
      })
      // Server short-circuits before setting cookies when MFA is on. Swap
      // the UI into "enter TOTP code" mode and stash the opaque challenge.
      if (resp?.mfa_required && resp.challenge) {
        setMfaChallenge(resp.challenge)
        setMfaCode('')
        setError('')
        return
      }
      const user = await authApi.portalMe()
      setUser(user)
      if (resumeSSOIfAny(searchParams)) return
      const from = (location.state as { from?: string })?.from || '/apps'
      navigate(from, { replace: true })
    } catch (err: unknown) {
      setError(loginErrorMessage(err, t))
      // Backend demands captcha (40003) or rejected it (40004) → reveal + load.
      const code = (err as { response?: { data?: { code?: number } } })?.response?.data?.code
      if (code === 40003 || code === 40004) setCaptchaRequired(true)
      if (captchaRequired || code === 40003 || code === 40004) loadCaptcha()
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyMfa = async (e?: FormEvent) => {
    e?.preventDefault()
    if (mfaCode.length !== 6) return
    setLoading(true)
    setError('')
    try {
      // External-IdP challenge: finish the parked federated login. The verify
      // response sets the session cookies and returns where to send the browser
      // (may be an SSO resume URL captured when the login started).
      if (extMfaToken) {
        const res = await externalIdpApi.verifyMFA({ token: extMfaToken, code: mfaCode })
        window.location.assign(res?.redirect || '/apps')
        return
      }
      await authApi.portalVerifyMFA({
        challenge: mfaChallenge,
        code: mfaCode,
        remember,
      })
      const user = await authApi.portalMe()
      setUser(user)
      if (resumeSSOIfAny(searchParams)) return
      const from = (location.state as { from?: string })?.from || '/apps'
      navigate(from, { replace: true })
    } catch (err: unknown) {
      setError(loginErrorMessage(err, t))
      if (extMfaToken) {
        // External verify keeps the pending token on a wrong code (retryable
        // within the TTL, rate-limited) — just clear the code to re-enter.
        setMfaCode('')
      } else {
        // Local verify consumes the challenge on any attempt — a wrong code
        // means restarting from the password step.
        setMfaChallenge('')
        setMfaCode('')
        setPassword('')
        loadCaptcha()
      }
    } finally {
      setLoading(false)
    }
  }

  // Auto-submit once 6 digits are entered — a TOTP code has no other length, so
  // there's nothing to review; save the user the extra click.
  useEffect(() => {
    if (showMfa && mfaCode.length === 6 && !loading) handleVerifyMfa()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mfaCode])

  const cancelMfa = () => {
    setMfaChallenge('')
    setMfaCode('')
    setError('')
    if (extMfaToken) {
      // Drop the parked federated login and strip the token from the URL so a
      // refresh doesn't drop straight back into the MFA step.
      setExtMfaToken('')
      searchParams.delete('ext_mfa')
      setSearchParams(searchParams, { replace: true })
    } else {
      loadCaptcha()
    }
  }

  return (
    <div className="flex min-h-screen">
      {/* Left — Logo */}
      <div className="hidden lg:flex lg:w-1/2 items-center justify-center" style={{ backgroundColor: '#FAFAF7' }}>
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
          className="flex items-center justify-center"
        >
          <img src={bootstrap.branding.logo_url || logo} alt={bootstrap.branding.product_name || 'MXID'} className="w-[520px] max-w-[80%] h-auto" />
        </motion.div>
      </div>

      {/* Right — Login Form */}
      <div className="flex w-full lg:w-1/2 items-center justify-center px-6" style={{ backgroundColor: '#0F1B3D' }}>
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-sm"
        >
          {/* Mobile logo */}
          <div className="mb-8 text-center lg:hidden">
            <img src={bootstrap.branding.logo_url || logo} alt={bootstrap.branding.product_name || 'MXID'} className="mx-auto h-14 w-auto" />
          </div>

          <div className="mb-8">
            <h2 className="text-3xl font-semibold tracking-tight text-white">
              {showMfa ? t('login.mfa') : (bootstrap.branding.login_page_title || t('login.welcomePortal'))}
            </h2>
            <p className="mt-2 text-sm text-white/55">
              {showMfa
                ? t('login.mfaHint')
                : t('login.subtitlePortal')}
            </p>
          </div>

          {!showMfa && idpFirst && (
            <ExternalIdpButtons
              idps={idps}
              hrefFor={(idp) => externalIdpApi.startURL(idp.code, undefined, tenantCode || undefined)}
              dividerLabel={t('login.socialDivider')}
            />
          )}

          {showMfa ? (
            <form onSubmit={handleVerifyMfa} className="flex flex-col gap-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('account.mfa.verifyCode')}
                </label>
                <input
                  autoFocus
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) =>
                    setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                  }
                  placeholder="••••••"
                  className="w-full rounded-lg border border-white/25 bg-surface/[0.08] px-3 py-2.5 text-center text-lg font-mono tracking-widest text-white placeholder:text-white/40 outline-none transition-colors focus:border-white/60 focus:bg-surface/[0.12]"
                />
              </div>
              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
                >
                  {error}
                </motion.div>
              )}
              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                {loading ? t('login.mfaSubmitting') : t('login.mfaSubmit')}
              </button>
              <button
                type="button"
                onClick={cancelMfa}
                className="text-center text-xs text-white/55 hover:text-white"
              >
{t('login.mfaBack')}
              </button>
            </form>
          ) : passwordEnabled ? (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.username')}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t('login.placeholderUsername')}
                autoComplete="username"
                autoFocus
                className="w-full rounded-lg border border-white/25 bg-surface/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-surface/[0.12]"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.password')}
              </label>
              <div className="relative">
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('login.placeholderPassword')}
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-white/25 bg-surface/[0.08] px-3 py-2.5 pr-10 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-surface/[0.12]"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd(!showPwd)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-white/60 hover:text-white"
                >
                  {showPwd ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {captchaRequired && (
            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
                {t('login.captcha')}
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={captchaCode}
                  onChange={(e) => setCaptchaCode(e.target.value)}
                  placeholder={t('login.captchaPlaceholder')}
                  maxLength={5}
                  autoComplete="off"
                  className="flex-1 rounded-lg border border-white/25 bg-surface/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-surface/[0.12]"
                />
                <div className="flex items-center gap-1">
                  {captchaImage ? (
                    <img
                      src={captchaImage}
                      alt={t('login.captcha')}
                      className="h-[38px] w-[100px] cursor-pointer rounded-lg border border-white/25 bg-surface"
                      onClick={loadCaptcha}
                      title={t('login.captchaClickRefresh')}
                    />
                  ) : (
                    <div className="flex h-[38px] w-[100px] items-center justify-center rounded-lg border border-white/25 bg-surface/[0.08] text-xs text-white/60">
{t('login.captchaLoading')}
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={loadCaptcha}
                    className="rounded-lg p-2 text-white/60 transition-colors hover:bg-surface/10 hover:text-white"
                    title={t('login.refreshCaptcha')}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
            )}

            <div className="flex items-center justify-between">
              <label className="flex cursor-pointer items-center gap-2 text-sm text-white/80 select-none">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="h-4 w-4 rounded border-white/30 bg-surface/10 text-primary focus:ring-primary/30"
                />
                {t('login.rememberMe')}
              </label>
              <Link to="/password/forgot" className="text-sm text-white/70 hover:text-white">
                {t('login.forgotPassword')}
              </Link>
            </div>
            {(magicLinkEnabled || smsEnabled) && (
              <div className="flex items-center justify-center gap-4 text-xs">
                {magicLinkEnabled && (
                  <Link to="/login/magic-link" className="text-white/55 hover:text-white">
                    {t('login.magicLink.entry')}
                  </Link>
                )}
                {smsEnabled && (
                  <Link to="/login/sms" className="text-white/55 hover:text-white">
                    {t('login.sms.entry')}
                  </Link>
                )}
              </div>
            )}

            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
              >
                {error}
              </motion.div>
            )}

            <button
              type="submit"
              disabled={loading || !username.trim() || !password}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? t('login.submitting') : t('login.submit')}
            </button>
          </form>
          ) : (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-3 text-sm text-amber-200">
{t('login.passwordDisabledHint')}
            </div>
          )}

          {!showMfa && !idpFirst && (
            <ExternalIdpButtons
              idps={idps}
              hrefFor={(idp) => externalIdpApi.startURL(idp.code, undefined, tenantCode || undefined)}
              dividerLabel={t('login.socialDivider')}
            />
          )}

          {bootstrap.branding.login_footer_html ? (
            <div
              className="mt-8 text-center text-xs text-white/55"
              dangerouslySetInnerHTML={{ __html: bootstrap.branding.login_footer_html }}
            />
          ) : (
            <p className="mt-8 text-center text-xs text-white/55">
              {bootstrap.branding.product_name || 'MXID'} Identity Platform
            </p>
          )}
        </motion.div>
      </div>
    </div>
  )
}
