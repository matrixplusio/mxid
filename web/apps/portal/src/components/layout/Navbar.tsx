import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { authApi, useAuthStore, cn, useTranslation, setLanguage, SUPPORTED_LANGS, useEdition } from '@mxid/shared'
import {
  LayoutGrid,
  UserCircle,
  ShieldCheck,
  KeyRound,
  LogOut,
  Menu,
  X,
  Settings,
} from 'lucide-react'
import { ThemeToggle } from '@mxid/shared/ui'
import logo from '../../assets/logo.png'

const buildNavItems = (t: (k: string) => string, hasConditionalAccess: boolean) => [
  { to: '/apps', label: t('nav.myApps'), icon: LayoutGrid },
  { to: '/profile', label: t('nav.profile'), icon: UserCircle },
  { to: '/security', label: t('nav.security'), icon: ShieldCheck },
  ...(hasConditionalAccess
    ? [{ to: '/access-requests', label: t('nav.accessRequests'), icon: KeyRound }]
    : []),
]

export default function Navbar() {
  const navigate = useNavigate()
  const { user, clear } = useAuthStore()
  const { t, i18n } = useTranslation()
  const edition = useEdition()
  const navItems = buildNavItems(t, edition.has('conditional_access'))
  const [mobileOpen, setMobileOpen] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)

  const handleLogout = async () => {
    if (loggingOut) return
    setLoggingOut(true)
    try {
      await authApi.portalLogout()
    } catch {
      // ignore
    } finally {
      clear()
      navigate('/login', { replace: true })
    }
  }

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-border bg-surface/80 backdrop-blur-md">
      <div className="mx-auto flex h-full max-w-6xl items-center justify-between px-4">
        {/* Logo */}
        <NavLink to="/apps" className="flex items-center">
          <img src={logo} alt="MXID" className="h-8 w-auto" />
        </NavLink>

        {/* Desktop Nav */}
        <div className="hidden items-center gap-1 md:flex">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted hover:bg-surface-muted hover:text-ink',
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </div>

        {/* User & Logout */}
        <div className="hidden items-center gap-3 md:flex">
          <div className="flex items-center gap-1 text-xs text-muted">
            {SUPPORTED_LANGS.map((l) => (
              <button
                key={l}
                onClick={() => setLanguage(l)}
                className={cn(
                  'rounded px-2 py-0.5 transition-colors',
                  i18n.language === l ? 'bg-primary/10 text-primary font-medium' : 'hover:bg-surface-muted',
                )}
              >
                {l === 'zh-CN' ? '中' : 'EN'}
              </button>
            ))}
          </div>
          <ThemeToggle />
          {user?.is_admin && (
            <a
              href="/admin/"
              className="flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-sm font-medium text-primary transition-colors hover:bg-primary/10"
              title={t('nav.switchToConsole')}
            >
              <Settings className="h-4 w-4" />
              {t('nav.switchToConsole')}
            </a>
          )}
          <span className="flex items-center gap-2 text-sm text-muted">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full bg-primary/15 text-xs font-medium uppercase text-primary">
              {user?.avatar ? (
                <img src={user.avatar} alt="" className="h-full w-full object-cover" />
              ) : (
                user?.display_name?.charAt(0) || user?.username?.charAt(0) || 'U'
              )}
            </span>
            {user?.display_name || user?.username}
          </span>
          <button
            onClick={handleLogout}
            disabled={loggingOut}
            className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium text-muted transition-colors hover:bg-danger/10 hover:text-danger disabled:opacity-50"
          >
            <LogOut className="h-4 w-4" />
            {t('nav.logout')}
          </button>
        </div>

        {/* Mobile menu button */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-lg p-2 text-muted hover:bg-surface-muted md:hidden"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile Nav */}
      {mobileOpen && (
        <div className="border-b border-border bg-surface px-4 pb-4 md:hidden">
          <div className="flex flex-col gap-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted hover:bg-surface-muted',
                  )
                }
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </NavLink>
            ))}
            {user?.is_admin && (
              <a
                href="/admin/"
                onClick={() => setMobileOpen(false)}
                className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-primary transition-colors hover:bg-primary/10"
              >
                <Settings className="h-4 w-4" />
                {t('nav.switchToConsole')}
              </a>
            )}
            <button
              onClick={handleLogout}
              disabled={loggingOut}
              className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-danger transition-colors hover:bg-danger/10 disabled:opacity-50"
            >
              <LogOut className="h-4 w-4" />
              {t('nav.logout')}
            </button>
          </div>
        </div>
      )}
    </nav>
  )
}
