import { useLocation } from 'react-router-dom'
import { useTranslation } from '@mxid/shared'
import { ThemeToggle } from '@mxid/shared/ui'

// Maps the first path segment to its nav i18n key so the header echoes the
// sidebar's active item. Kept in sync with Sidebar's navItemsBuild.
const TITLE_KEY: Record<string, string> = {
  dashboard: 'nav.dashboard',
  tenants: 'nav.tenants',
  users: 'nav.users',
  orgs: 'nav.orgs',
  groups: 'nav.groups',
  apps: 'nav.apps',
  idps: 'nav.idps',
  permissions: 'nav.permissions',
  'access-approvals': 'nav.accessApprovals',
  audit: 'nav.audit',
  offboarding: 'nav.offboarding',
  settings: 'nav.settings',
  docs: 'nav.docs',
  account: 'nav.myAccountTitle',
}

export default function Header() {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const seg = pathname.split('/').filter(Boolean)[0] ?? 'dashboard'
  const titleKey = TITLE_KEY[seg]

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-border bg-surface px-6">
      <h2 className="text-base font-semibold text-ink">{titleKey ? t(titleKey) : ''}</h2>
      <div className="flex items-center gap-1">
        <ThemeToggle />
      </div>
    </header>
  )
}
