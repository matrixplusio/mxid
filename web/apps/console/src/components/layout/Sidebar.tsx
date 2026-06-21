import { NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore, authApi, cn, setActiveTenantID, useTranslation, setLanguage, SUPPORTED_LANGS, useBootstrap } from '@mxid/shared'
import {
  LayoutDashboard,
  Users,
  Building2,
  UsersRound,
  AppWindow,
  Shield,
  ScrollText,
  UserX,
  LogOut,
  Plug,
  Building,
  BookOpen,
  Settings,
  ExternalLink,
} from 'lucide-react'
import logo from '../../assets/logo.png'
import TenantSwitcher from './TenantSwitcher'

// navItemsBuild resolves to live translated labels each render — keeps
// the sidebar in sync when the user picks a different language without
// a full reload.
const navItemsBuild = (t: (k: string) => string) => [
  { to: '/dashboard', icon: LayoutDashboard, label: t('nav.dashboard') },
  { to: '/tenants', icon: Building, label: t('nav.tenants') },
  { to: '/users', icon: Users, label: t('nav.users') },
  { to: '/orgs', icon: Building2, label: t('nav.orgs') },
  { to: '/groups', icon: UsersRound, label: t('nav.groups') },
  { to: '/apps', icon: AppWindow, label: t('nav.apps') },
  { to: '/idps', icon: Plug, label: t('nav.idps') },
  { to: '/permissions', icon: Shield, label: t('nav.permissions') },
  { to: '/audit', icon: ScrollText, label: t('nav.audit') },
  { to: '/offboarding', icon: UserX, label: t('nav.offboarding') },
  { to: '/settings', icon: Settings, label: t('nav.settings') },
  { to: '/docs', icon: BookOpen, label: t('nav.docs') },
]

export default function Sidebar() {
  const { branding } = useBootstrap()
  const { user, clear } = useAuthStore()
  const navigate = useNavigate()
  const { t, i18n } = useTranslation()
  const navItems = navItemsBuild(t)

  const handleLogout = async () => {
    try {
      await authApi.logout()
    } finally {
      clear()
      setActiveTenantID(null)
      navigate('/login', { replace: true })
    }
  }

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col bg-sidebar text-white">
      {/* Logo */}
      <div className="flex h-16 items-center justify-center border-b border-white/10">
        <img src={branding.logo_url || logo} alt={branding.product_name || 'MXID'} className="h-10 w-auto" />
      </div>

      {/* Tenant switcher — full-width row under the logo, only renders
          when the caller can list multiple tenants. */}
      <div className="border-b border-white/10 px-3 py-3">
        <TenantSwitcher />
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-sidebar-active text-white'
                  : 'text-gray-300 hover:bg-sidebar-hover hover:text-white'
              )
            }
          >
            <item.icon className="h-5 w-5 shrink-0" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Language switcher */}
      <div className="border-t border-white/10 px-3 py-2">
        <div className="flex items-center justify-between text-xs text-gray-400">
          <span>{t('nav.language')}</span>
          <div className="flex gap-1">
            {SUPPORTED_LANGS.map((l) => (
              <button
                key={l}
                onClick={() => setLanguage(l)}
                className={cn(
                  'rounded px-2 py-0.5 transition-colors',
                  i18n.language === l ? 'bg-primary/30 text-white' : 'hover:bg-sidebar-hover hover:text-white',
                )}
              >
                {l === 'zh-CN' ? '中' : 'EN'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Switch to portal — admin always sees this; portal is the end-user
          surface, same MXID session works there. */}
      <div className="border-t border-white/10 px-4 py-3">
        <a
          href="/"
          className="flex w-full items-center justify-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-xs font-medium text-gray-200 transition-colors hover:bg-sidebar-hover hover:text-white"
          title={t('nav.switchToPortal')}
        >
          <ExternalLink className="h-3.5 w-3.5" />
          {t('nav.switchToPortal')}
        </a>
      </div>

      {/* User info + logout */}
      <div className="border-t border-white/10 px-4 py-4">
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => navigate('/account')}
            className="group flex min-w-0 flex-1 items-center gap-3 rounded-lg p-1 text-left transition-colors hover:bg-sidebar-hover"
            title={t('nav.myAccountTitle')}
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/30 text-sm font-medium">
              {user?.display_name?.charAt(0) || user?.username?.charAt(0) || 'U'}
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-medium group-hover:text-white">{user?.display_name || user?.username}</p>
              <p className="truncate text-xs text-gray-400">{user?.username}</p>
            </div>
          </button>
          <button
            onClick={handleLogout}
            className="shrink-0 rounded-lg p-2 text-gray-400 transition-colors hover:bg-sidebar-hover hover:text-white"
            title={t('nav.logout')}
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}
