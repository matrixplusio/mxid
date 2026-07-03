import { useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import { authApi, useAuthStore, useBootstrap, useTheme } from '@mxid/shared'
import MainLayout from './components/layout/MainLayout'
import LoginPage from './pages/login'
import MagicLinkLoginPage from './pages/login/magic-link'
import SMSLoginPage from './pages/login/sms'
import AppsPage from './pages/apps'
import ConsentPage from './pages/consent'
import ProfilePage from './pages/profile'
import SecurityPage from './pages/security'
import AccessRequestsPage from './pages/access-requests'
import NoAccessPage from './pages/no-access'
import ForgotPasswordPage from './pages/password/forgot'
import ResetPasswordPage from './pages/password/reset'

function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, loading, setUser, clear } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Bootstrap: try the silent SSO bridge once (derive a portal session from
    // an existing SSO session, e.g. after switching back from console) before
    // falling back to the login form. skipAuthEvent keeps the probe's 401 from
    // racing the global mxid:unauthorized redirect.
    authApi.portalMe({ skipAuthEvent: true })
      .then(setUser)
      .catch(() =>
        authApi.portalSso()
          .then(() => authApi.portalMe({ skipAuthEvent: true }))
          .then(setUser)
          .catch(() => {
            clear()
            navigate('/login', { replace: true })
          }),
      )
  }, [setUser, clear, navigate])

  useEffect(() => {
    const handler = () => {
      clear()
      navigate('/login', { replace: true })
    }
    window.addEventListener('mxid:unauthorized', handler)
    return () => window.removeEventListener('mxid:unauthorized', handler)
  }, [clear, navigate])

  // Mandatory MFA enrollment: when the backend gate reports the user must bind
  // a factor before proceeding, send them to the security page where TOTP
  // enrollment lives.
  useEffect(() => {
    const onEnroll = () => navigate('/security', { replace: true })
    window.addEventListener('mxid:mfa-enroll-required', onEnroll)
    return () => window.removeEventListener('mxid:mfa-enroll-required', onEnroll)
  }, [navigate])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    )
  }

  if (!user) return null

  return <>{children}</>
}

function RedirectIfAuth({ children }: { children: React.ReactNode }) {
  const { user, loading, setUser, clear } = useAuthStore()
  const location = useLocation()

  useEffect(() => {
    authApi.portalMe().then(setUser).catch(() => clear())
  }, [setUser, clear])

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    )
  }

  if (user) {
    // SSO bounce: when the user lands on /login while already signed in
    // and the URL carries an in-flight protocol handshake (CAS / OIDC /
    // SAML), resume that handshake instead of dropping them on /apps. The
    // backend's protocol handler will issue the ticket / code and 302
    // back to the original service.
    const sp = new URLSearchParams(location.search)
    const protocol = sp.get('protocol')
    const appCode = sp.get('app_code')
    const service = sp.get('service')
    if (protocol === 'cas' && appCode && service) {
      const url = `/protocol/cas/${appCode}/login?service=${encodeURIComponent(service)}`
      window.location.replace(url)
      return null
    }
    if (protocol === 'saml' && appCode) {
      // Resume an SP-initiated SAML handshake. Backend returns the
      // signed SAML Response (auto-POST form) → browser submits to SP
      // ACS. request_id carries the original AuthnRequest ID so the
      // response's InResponseTo matches what the SP is waiting on.
      const requestID = sp.get('request_id') || ''
      const relayState = sp.get('relay_state') || ''
      const params = new URLSearchParams()
      if (requestID) params.set('request_id', requestID)
      if (relayState) params.set('relay_state', relayState)
      const qs = params.toString()
      const url = `/protocol/saml/${appCode}/resume${qs ? `?${qs}` : ''}`
      window.location.replace(url)
      return null
    }
    const from = (location.state as { from?: string })?.from || '/apps'
    return <Navigate to={from} replace />
  }

  return <>{children}</>
}

export default function App() {
  // Pull bootstrap (branding + login methods + i18n) on first render so
  // document.title / primary color / favicon reflect admin settings
  // before the login page paints.
  useBootstrap()
  // Sync the theme store to the class the FOUC script already applied.
  const initTheme = useTheme((s) => s.init)
  useEffect(() => {
    initTheme()
  }, [initTheme])
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <RedirectIfAuth>
            <LoginPage />
          </RedirectIfAuth>
        }
      />
      <Route
        path="/"
        element={
          <AuthGuard>
            <MainLayout />
          </AuthGuard>
        }
      >
        <Route index element={<Navigate to="/apps" replace />} />
        <Route path="apps" element={<AppsPage />} />
        <Route path="consent" element={<ConsentPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="security" element={<SecurityPage />} />
        <Route path="access-requests" element={<AccessRequestsPage />} />
      </Route>
      <Route
        path="/login/magic-link"
        element={
          <RedirectIfAuth>
            <MagicLinkLoginPage />
          </RedirectIfAuth>
        }
      />
      <Route
        path="/login/sms"
        element={
          <RedirectIfAuth>
            <SMSLoginPage />
          </RedirectIfAuth>
        }
      />
      <Route path="/password/forgot" element={<ForgotPasswordPage />} />
      <Route path="/password/reset" element={<ResetPasswordPage />} />
      <Route path="/no-access" element={<NoAccessPage />} />
      <Route path="*" element={<Navigate to="/apps" replace />} />
    </Routes>
  )
}
