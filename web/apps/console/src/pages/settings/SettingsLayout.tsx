// SettingsLayout — two-column shell shared by every /settings/* page.
//
// Left rail: vertical nav grouped by category. Right pane: outlet for the
// active child route. Pages are intentionally fine-grained (one route per
// settings card) so each save flow stays simple.
import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import {
  Mail, MailOpen, ShieldCheck, Palette, LogIn,
  Settings2, MessageSquare, FileClock, Globe, Award, Link2, KeyRound, ShieldAlert, Info, Webhook,
} from 'lucide-react'
import { cn, useTranslation, systemApi } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

const buildNav = (t: (k: string) => string): Array<{
  group: string
  items: Array<{ to: string; icon: typeof Mail; label: string; hint?: string }>
}> => [
  {
    group: t('settings.sections.mailTemplates') + ' / ' + t('settings.sections.sms'),
    items: [
      { to: '/settings/mail/smtp', icon: Mail, label: t('settings.sections.mailSmtp'), hint: t('settings.sections.mailSmtpHint') },
      { to: '/settings/mail/templates', icon: MailOpen, label: t('settings.sections.mailTemplates') },
      { to: '/settings/sms', icon: MessageSquare, label: t('settings.sections.sms') },
    ],
  },
  {
    group: t('settings.sections.security'),
    items: [
      { to: '/settings/security', icon: ShieldCheck, label: t('settings.sections.security'), hint: t('settings.sections.securityHint') },
      { to: '/settings/mfa', icon: KeyRound, label: t('settings.sections.mfa'), hint: t('settings.sections.mfaHint') },
      { to: '/settings/conditional-access', icon: ShieldAlert, label: t('settings.sections.conditionalAccess'), hint: t('settings.sections.conditionalAccessHint') },
      { to: '/settings/login-methods', icon: LogIn, label: t('settings.sections.loginMethods') },
    ],
  },
  {
    group: t('settings.sections.protocolDefaults') + ' / ' + t('settings.sections.branding'),
    items: [
      { to: '/settings/protocol-defaults', icon: Settings2, label: t('settings.sections.protocolDefaults') },
      { to: '/settings/branding', icon: Palette, label: t('settings.sections.branding') },
      { to: '/settings/localization', icon: Globe, label: t('settings.sections.localization') },
      { to: '/settings/external-urls', icon: Link2, label: t('settings.sections.externalUrls'), hint: t('settings.sections.externalUrlsHint') },
    ],
  },
  {
    group: t('settings.sections.auditPolicy') + ' / ' + t('settings.sections.license'),
    items: [
      { to: '/settings/audit-policy', icon: FileClock, label: t('settings.sections.auditPolicy') },
      { to: '/settings/offboarding-webhook', icon: Webhook, label: t('settings.sections.offboardingWebhook') },
      { to: '/settings/license', icon: Award, label: t('settings.sections.license') },
    ],
  },
  {
    group: t('settings.sections.systemVersion'),
    items: [
      { to: '/settings/system-version', icon: Info, label: t('settings.sections.systemVersion'), hint: t('settings.sections.systemVersionHint') },
    ],
  },
]

export default function SettingsLayout() {
  const { t } = useTranslation()
  const NAV = buildNav(t)
  // Update badge: a dot on the system-version nav item when a newer release
  // exists. Best-effort — failures (non-super_admin 403, network) leave it off.
  const [updateAvailable, setUpdateAvailable] = useState(false)
  useEffect(() => {
    systemApi
      .versionStatus()
      .then((s) => setUpdateAvailable(!!s.update_available))
      .catch(() => {})
  }, [])
  return (
    <div className="space-y-6">
      <PageHeader
        title={t('settings.title')}
        description={t('settings.subtitle')}
      />

      <div className="grid grid-cols-12 gap-6">
        <aside className="col-span-12 md:col-span-3 xl:col-span-2">
          <nav className="space-y-4 rounded-xl border border-gray-200 bg-white p-3">
            {NAV.map((sec) => (
              <div key={sec.group}>
                <div className="mb-1 px-2 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                  {sec.group}
                </div>
                <div className="space-y-0.5">
                  {sec.items.map((it) => (
                    <NavLink
                      key={it.to}
                      to={it.to}
                      className={({ isActive }) =>
                        cn(
                          'flex items-start gap-2 rounded-lg px-2.5 py-2 text-sm transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary'
                            : 'text-gray-700 hover:bg-gray-50',
                        )
                      }
                    >
                      <it.icon className="mt-0.5 h-4 w-4 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate font-medium">{it.label}</span>
                          {it.to === '/settings/system-version' && updateAvailable && (
                            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                          )}
                        </div>
                        {it.hint && <div className="truncate text-[11px] text-gray-400">{it.hint}</div>}
                      </div>
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>
        </aside>

        <main className="col-span-12 md:col-span-9 xl:col-span-10">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
