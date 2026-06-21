import { useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore, authApi, useBootstrap } from '@mxid/shared'
import MainLayout from './components/layout/MainLayout'
import StepUpModal from './components/StepUpModal'
import LoginPage from './pages/login'
import DashboardPage from './pages/dashboard'
import UsersPage from './pages/users'
import UserDetailPage from './pages/users/detail'
import OrgsPage from './pages/orgs'
import GroupsPage from './pages/groups'
import AppsPage from './pages/apps'
import IDPsPage from './pages/idps'
import TenantsPage from './pages/tenants'
import PermissionsPage from './pages/permissions'
import AuditPage from './pages/audit'
import OffboardingPage from './pages/offboarding'
import DocsPage from './pages/docs'
import AccountPage from './pages/account'
import SettingsLayout from './pages/settings/SettingsLayout'
import MailSMTPPage from './pages/settings/MailSMTP'
import SecurityPage from './pages/settings/Security'
import SystemVersionPage from './pages/settings/SystemVersion'
import {
  BrandingPage,
  LoginMethodsPage,
  ProtocolDefaultsPage,
  SMSPage,
  AuditPolicyPage,
  OffboardingWebhookPage,
  MFAPolicyPage,
  ConditionalAccessPage,
  LocalizationPage,
  LicensePage,
  MailTemplatesPage,
  ExternalURLsPage,
} from './pages/settings/SimplePages'
import { Navigate as RRNavigate } from 'react-router-dom'

function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, loading, setUser, clear } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Bootstrap: if there's no console session yet, try the silent SSO bridge
    // once (derives a console session from an existing portal/SSO session)
    // before falling back to the login form. skipAuthEvent keeps the probe's
    // 401 from racing the global mxid:unauthorized redirect.
    authApi.me({ skipAuthEvent: true })
      .then(setUser)
      .catch(() =>
        authApi.sso()
          .then(() => authApi.me({ skipAuthEvent: true }))
          .then(setUser)
          .catch(() => {
            clear()
            navigate('/login', { replace: true })
          }),
      )
  }, [])

  useEffect(() => {
    const handler = () => {
      clear()
      navigate('/login', { replace: true })
    }
    window.addEventListener('mxid:unauthorized', handler)
    return () => window.removeEventListener('mxid:unauthorized', handler)
  }, [])

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

export default function App() {
  const location = useLocation()
  // Apply branding (title, primary color, custom CSS) before anything paints.
  useBootstrap()

  return (
    <Routes location={location} key={location.pathname}>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <AuthGuard>
            <MainLayout>
              <StepUpModal />
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/users/:id" element={<UserDetailPage />} />
                <Route path="/orgs" element={<OrgsPage />} />
                <Route path="/groups" element={<GroupsPage />} />
                <Route path="/apps" element={<AppsPage />} />
                <Route path="/idps" element={<IDPsPage />} />
                <Route path="/tenants" element={<TenantsPage />} />
                <Route path="/permissions" element={<PermissionsPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/offboarding" element={<OffboardingPage />} />
                <Route path="/docs" element={<DocsPage />} />
                <Route path="/account" element={<AccountPage />} />
                <Route path="/settings" element={<SettingsLayout />}>
                  <Route index element={<RRNavigate to="/settings/mail/smtp" replace />} />
                  <Route path="mail/smtp" element={<MailSMTPPage />} />
                  <Route path="mail/templates" element={<MailTemplatesPage />} />
                  <Route path="sms" element={<SMSPage />} />
                  <Route path="security" element={<SecurityPage />} />
                  <Route path="mfa" element={<MFAPolicyPage />} />
                  <Route path="conditional-access" element={<ConditionalAccessPage />} />
                  <Route path="login-methods" element={<LoginMethodsPage />} />
                  <Route path="protocol-defaults" element={<ProtocolDefaultsPage />} />
                  <Route path="branding" element={<BrandingPage />} />
                  <Route path="localization" element={<LocalizationPage />} />
                  <Route path="audit-policy" element={<AuditPolicyPage />} />
                  <Route path="offboarding-webhook" element={<OffboardingWebhookPage />} />
                  <Route path="license" element={<LicensePage />} />
                  <Route path="external-urls" element={<ExternalURLsPage />} />
                  <Route path="system-version" element={<SystemVersionPage />} />
                </Route>
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </MainLayout>
          </AuthGuard>
        }
      />
    </Routes>
  )
}

