import { useEffect, useRef, useState } from 'react'
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
  Globe,
  ChevronDown,
} from 'lucide-react'
import { ThemeToggle } from '@mxid/shared/ui'
import logo from '../../assets/logo.png'

// Primary navigation: product surfaces only. Account/security/logout live under
// the avatar menu so the top bar stays uncluttered (Okta / Azure MyApps model).
const buildNavItems = (t: (k: string) => string, hasConditionalAccess: boolean) => [
  { to: '/apps', label: t('nav.myApps'), icon: LayoutGrid },
  ...(hasConditionalAccess
    ? [{ to: '/access-requests', label: t('nav.accessRequests'), icon: KeyRound }]
    : []),
]

// Account items relocated from the top bar into the avatar dropdown (and the
// mobile drawer). Shared so both render the same set.
const buildAccountItems = (t: (k: string) => string) => [
  { to: '/profile', label: t('nav.profile'), icon: UserCircle },
  { to: '/security', label: t('nav.security'), icon: ShieldCheck },
]

const LANG_LABEL: Record<string, string> = { 'zh-CN': '中文', 'en-US': 'English' }
const langShort = (l: string) => (l === 'zh-CN' ? '中' : 'EN')

export default function Navbar() {
  const navigate = useNavigate()
  const { user, clear } = useAuthStore()
  const { t, i18n } = useTranslation()
  const edition = useEdition()
  const navItems = buildNavItems(t, edition.has('conditional_access'))
  const accountItems = buildAccountItems(t)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  // Which desktop popover is open ('lang' | 'user' | null) — only one at a time.
  const [openMenu, setOpenMenu] = useState<'lang' | 'user' | null>(null)
  const clusterRef = useRef<HTMLDivElement>(null)

  // Close the open popover on an outside click or Escape.
  useEffect(() => {
    if (!openMenu) return
    const onDown = (e: MouseEvent) => {
      if (clusterRef.current && !clusterRef.current.contains(e.target as Node)) setOpenMenu(null)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpenMenu(null)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [openMenu])

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

  const avatarNode = (
    <span className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full bg-primary/15 text-xs font-medium uppercase text-primary">
      {user?.avatar ? (
        <img src={user.avatar} alt="" className="h-full w-full object-cover" />
      ) : (
        user?.display_name?.charAt(0) || user?.username?.charAt(0) || 'U'
      )}
    </span>
  )

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-border bg-surface/80 backdrop-blur-md">
      <div className="mx-auto flex h-full max-w-6xl items-center justify-between px-4">
        {/* Logo */}
        <NavLink to="/apps" className="flex items-center">
          <img src={logo} alt="MXID" className="h-8 w-auto" />
        </NavLink>

        {/* Desktop primary nav */}
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

        {/* Desktop utility cluster */}
        <div ref={clusterRef} className="hidden items-center gap-2 md:flex">
          {/* Language */}
          <div className="relative">
            <button
              onClick={() => setOpenMenu((m) => (m === 'lang' ? null : 'lang'))}
              className="flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-sm text-muted transition-colors hover:bg-surface-muted hover:text-ink"
              title={t('nav.language')}
              aria-haspopup="menu"
              aria-expanded={openMenu === 'lang'}
            >
              <Globe className="h-4 w-4" />
              <span className="text-xs font-medium">{langShort(i18n.language)}</span>
            </button>
            {openMenu === 'lang' && (
              <div
                role="menu"
                className="absolute right-0 mt-1.5 min-w-32 overflow-hidden rounded-lg border border-border bg-surface py-1 shadow-lg"
              >
                {SUPPORTED_LANGS.map((l) => (
                  <button
                    key={l}
                    role="menuitem"
                    onClick={() => {
                      setLanguage(l)
                      setOpenMenu(null)
                    }}
                    className={cn(
                      'flex w-full items-center justify-between gap-3 px-3 py-2 text-sm transition-colors',
                      i18n.language === l
                        ? 'bg-primary/10 font-medium text-primary'
                        : 'text-muted hover:bg-surface-muted hover:text-ink',
                    )}
                  >
                    {LANG_LABEL[l] ?? l}
                    <span className="text-xs text-faint">{langShort(l)}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <ThemeToggle />

          {/* Admin console — role gated */}
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

          {/* Avatar menu — profile / security / logout */}
          <div className="relative">
            <button
              onClick={() => setOpenMenu((m) => (m === 'user' ? null : 'user'))}
              className="flex items-center gap-2 rounded-lg py-1 pl-1 pr-2 text-sm text-ink transition-colors hover:bg-surface-muted"
              aria-haspopup="menu"
              aria-expanded={openMenu === 'user'}
            >
              {avatarNode}
              <span className="max-w-32 truncate">{user?.display_name || user?.username}</span>
              <ChevronDown
                className={cn('h-4 w-4 text-muted transition-transform', openMenu === 'user' && 'rotate-180')}
              />
            </button>
            {openMenu === 'user' && (
              <div
                role="menu"
                className="absolute right-0 mt-1.5 min-w-48 overflow-hidden rounded-lg border border-border bg-surface py-1 shadow-lg"
              >
                <div className="border-b border-border px-3 py-2">
                  <p className="truncate text-sm font-medium text-ink">{user?.display_name || user?.username}</p>
                  {user?.display_name && user?.username && (
                    <p className="truncate text-xs text-faint">@{user.username}</p>
                  )}
                </div>
                {accountItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    role="menuitem"
                    onClick={() => setOpenMenu(null)}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2.5 px-3 py-2 text-sm transition-colors',
                        isActive
                          ? 'bg-primary/10 font-medium text-primary'
                          : 'text-muted hover:bg-surface-muted hover:text-ink',
                      )
                    }
                  >
                    <item.icon className="h-4 w-4" />
                    {item.label}
                  </NavLink>
                ))}
                <div className="my-1 border-t border-border" />
                <button
                  role="menuitem"
                  onClick={handleLogout}
                  disabled={loggingOut}
                  className="flex w-full items-center gap-2.5 px-3 py-2 text-sm text-danger transition-colors hover:bg-danger/10 disabled:opacity-50"
                >
                  <LogOut className="h-4 w-4" />
                  {t('nav.logout')}
                </button>
              </div>
            )}
          </div>
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
            {[...navItems, ...accountItems].map((item) => (
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

            {/* Language + theme row */}
            <div className="mt-2 flex items-center gap-2 border-t border-border pt-3">
              <div className="flex items-center gap-1 text-xs text-muted">
                {SUPPORTED_LANGS.map((l) => (
                  <button
                    key={l}
                    onClick={() => setLanguage(l)}
                    className={cn(
                      'rounded px-2 py-1 transition-colors',
                      i18n.language === l ? 'bg-primary/10 font-medium text-primary' : 'hover:bg-surface-muted',
                    )}
                  >
                    {LANG_LABEL[l] ?? l}
                  </button>
                ))}
              </div>
              <ThemeToggle />
            </div>

            <button
              onClick={handleLogout}
              disabled={loggingOut}
              className="mt-1 flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-danger transition-colors hover:bg-danger/10 disabled:opacity-50"
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
