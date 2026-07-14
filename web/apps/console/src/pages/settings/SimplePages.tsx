// SimplePages — straightforward form pages for settings categories whose
// shape doesn't need bespoke UI logic. Each page binds to a typed setting
// via settingsApi.get* / put*. New fields require updating only the
// rowsFor() function for that page.
//
// Why one file: keeps the routing tree clean and avoids 8 nearly-identical
// 100-line files. Bespoke pages (MailSMTP, Security, Branding) live in
// their own files; the rest share this generic form harness.
import { useEffect, useState, type ReactNode } from 'react'
import { Loader2, Save } from 'lucide-react'
import {
  settingsApi,
  useTranslation,
  useEdition,
  cn,
  type Branding,
  type LoginMethods,
  type ProtocolDefaults,
  type SMS,
  type AuditPolicy,
  type OffboardingWebhook,
  type MFAPolicy,
  type ConditionalAccess,
  type Localization,
  type License,
  type MailTemplates,
  type ExternalURLs,
} from '@mxid/shared'
import { Field, Input, Select, Textarea, Button } from '../../components/ui'
import { toast } from '../../components/ui/toast'

type Row =
  | { kind: 'text';   key: string; label: string; hint?: string; placeholder?: string }
  | { kind: 'number'; key: string; label: string; hint?: string }
  | { kind: 'bool';   key: string; label: string }
  | { kind: 'select'; key: string; label: string; options: Array<{ value: string; label: string }> }
  | { kind: 'multiline'; key: string; label: string; hint?: string; rows?: number }
  | { kind: 'list'; key: string; label: string; hint?: string }

// Generic nested-object accessors. Values are unknown at the call site
// (table-driven form schema), so unknown + casts at the leaves are the
// right shape — using any would silently let bad keys through.
type AnyRecord = Record<string, unknown>

function get(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((o, k) => {
    if (o == null || typeof o !== 'object') return undefined
    return (o as AnyRecord)[k]
  }, obj)
}
function set<T>(obj: T, path: string, value: unknown): T {
  const keys = path.split('.')
  const out: AnyRecord = { ...(obj as unknown as AnyRecord) }
  let cur: AnyRecord = out
  for (let i = 0; i < keys.length - 1; i++) {
    cur[keys[i]] = { ...((cur[keys[i]] as AnyRecord) ?? {}) }
    cur = cur[keys[i]] as AnyRecord
  }
  cur[keys[keys.length - 1]] = value
  return out as T
}

function GenericForm<T>({
  rows,
  load,
  save,
  title,
  desc,
  locked,
  banner,
  onSaved,
}: {
  rows: Row[]
  load: () => Promise<T>
  save: (v: T) => Promise<unknown>
  title: string
  desc?: string
  // locked disables all inputs + save (e.g. an EE feature in CE).
  locked?: boolean
  // banner renders above the form (edition badge, upsell note, etc.).
  banner?: ReactNode
  // onSaved fires after a successful save (e.g. reload edition state).
  onSaved?: () => void
}) {
  const { t } = useTranslation()
  const [v, setV] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    load()
      .then(setV)
      .catch(() => toast.error(t('common.failed')))
      .finally(() => setLoading(false))
  }, [])

  if (loading || v == null) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await save(v)
      toast.success(t('settings.savedToast', { title }))
      onSaved?.()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t("common.failed"), msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-border bg-surface p-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-ink">{title}</h2>
          {desc && <p className="mt-0.5 text-sm text-muted">{desc}</p>}
        </div>

        {banner && <div className="mb-4">{banner}</div>}

        <fieldset disabled={locked} className={cn('grid grid-cols-1 gap-4 md:grid-cols-2', locked && 'opacity-60')}>
          {rows.map((r) => {
            // Booleans render as a self-contained toggle row (label inside a
            // bordered box, checkbox on the right) so they sit flush with the
            // adjacent inputs instead of a stray checkbox under a redundant
            // label. self-end aligns the box bottom with the neighbouring
            // input box (which has a label above it).
            if (r.kind === 'bool') {
              return (
                <label
                  key={r.key}
                  className="flex cursor-pointer select-none items-center justify-between gap-3 self-end rounded-lg border border-border px-3.5 py-2.5 text-sm hover:bg-surface-muted"
                >
                  <span className="font-medium text-ink">{r.label}</span>
                  <input
                    type="checkbox"
                    checked={!!get(v, r.key)}
                    onChange={(e) => setV(set(v, r.key, e.target.checked))}
                    className="h-4 w-4 rounded border-border text-primary focus:ring-primary/20"
                  />
                </label>
              )
            }
            return (
            <Field key={r.key} label={r.label} hint={'hint' in r ? r.hint : undefined}>
              {r.kind === 'text' && (
                <Input
                  value={(get(v, r.key) as string | undefined) ?? ''}
                  onChange={(e) => setV(set(v, r.key, e.target.value))}
                  placeholder={r.placeholder}
                />
              )}
              {r.kind === 'number' && (
                <Input
                  type="number"
                  value={(get(v, r.key) as number | undefined) ?? 0}
                  onChange={(e) => setV(set(v, r.key, Number(e.target.value) || 0))}
                />
              )}
              {r.kind === 'select' && (
                <Select
                  value={(get(v, r.key) as string | undefined) ?? ''}
                  onChange={(e) => setV(set(v, r.key, e.target.value))}
                >
                  {r.options.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </Select>
              )}
              {r.kind === 'multiline' && (
                <Textarea
                  rows={r.rows ?? 4}
                  value={(get(v, r.key) as string | undefined) ?? ''}
                  onChange={(e) => setV(set(v, r.key, e.target.value))}
                />
              )}
              {r.kind === 'list' && (
                <Textarea
                  rows={3}
                  value={((get(v, r.key) as string[] | undefined) ?? []).join('\n')}
                  onChange={(e) => setV(set(v, r.key, e.target.value.split('\n').map((s) => s.trim()).filter(Boolean)))}
                  placeholder={t('settings.listPlaceholder')}
                />
              )}
            </Field>
            )
          })}
        </fieldset>

        <div className="mt-6 flex justify-end">
          <Button onClick={handleSave} loading={saving} disabled={locked} icon={<Save className="h-4 w-4" />}>
            {saving ? t('common.saving') : t('common.save')}
          </Button>
        </div>
      </section>
    </div>
  )
}

/* ──────────────── Per-category pages ──────────────── */

// EEUpsell is the banner shown when an EE-only feature is viewed in CE.
function EEUpsell() {
  const { t } = useTranslation()
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
      {t('settings.eeOnly')}
    </div>
  )
}

export function BrandingPage() {
  const { t } = useTranslation()
  const { has } = useEdition()
  const unlocked = has('branding')
  return (
    <GenericForm<Branding>
      title={t('settings.branding.title')}
      desc={t('settings.branding.desc')}
      locked={!unlocked}
      banner={!unlocked ? <EEUpsell /> : undefined}
      rows={[
        { kind: 'text', key: 'product_name', label: t('settings.branding.productName'), placeholder: 'MXID' },
        { kind: 'text', key: 'primary_color', label: t('settings.branding.primaryColor'), placeholder: '#2563eb' },
        { kind: 'text', key: 'logo_url', label: t('settings.branding.logoUrl'), placeholder: t('settings.branding.logoUrlPlaceholder') },
        { kind: 'text', key: 'login_page_title', label: t('settings.branding.loginPageTitle') },
        { kind: 'multiline', key: 'login_footer_html', label: t('settings.branding.loginFooterHtml'), hint: t('settings.branding.loginFooterHtmlHint') },
        { kind: 'multiline', key: 'custom_css', label: t('settings.branding.customCss'), hint: t('settings.branding.customCssHint'), rows: 6 },
      ]}
      load={() => settingsApi.getBranding()}
      save={(v) => settingsApi.putBranding(v)}
    />
  )
}

export function LoginMethodsPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<LoginMethods>
      title={t('settings.loginMethods.title')}
      desc={t('settings.loginMethods.desc')}
      rows={[
        { kind: 'bool', key: 'password', label: t('settings.loginMethods.password') },
        { kind: 'bool', key: 'sms_otp', label: t('settings.loginMethods.sms') },
        { kind: 'bool', key: 'email_magic_link', label: t('settings.loginMethods.magicLink') },
        { kind: 'bool', key: 'external_idp_first', label: t('settings.loginMethods.externalIdpFirst') },
      ]}
      load={() => settingsApi.getLoginMethods()}
      save={(v) => settingsApi.putLoginMethods(v)}
    />
  )
}

export function ProtocolDefaultsPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<ProtocolDefaults>
      title={t('settings.protocolDefaults.title')}
      desc={t('settings.protocolDefaults.desc')}
      rows={[
        { kind: 'number', key: 'oidc_access_token_ttl_seconds', label: t('settings.protocolDefaults.oidcAccessTtl') },
        { kind: 'number', key: 'oidc_refresh_token_ttl_seconds', label: t('settings.protocolDefaults.oidcRefreshTtl') },
        { kind: 'number', key: 'oidc_id_token_ttl_seconds', label: t('settings.protocolDefaults.oidcIdTtl') },
        { kind: 'number', key: 'saml_assertion_ttl_seconds', label: t('settings.protocolDefaults.samlAssertionTtl') },
        { kind: 'number', key: 'cas_ticket_ttl_seconds', label: t('settings.protocolDefaults.casTicketTtl') },
        {
          kind: 'select', key: 'default_subject_strategy', label: t('settings.protocolDefaults.defaultSubject'),
          options: [
            { value: 'username', label: t('settings.protocolDefaults.subjectUsername') },
            { value: 'username_suffixed', label: t('settings.protocolDefaults.subjectUsernameSuffixed') },
            { value: 'email', label: t('settings.protocolDefaults.subjectEmail') },
            { value: 'persistent_id', label: t('settings.protocolDefaults.subjectPersistent') },
            { value: 'pairwise', label: t('settings.protocolDefaults.subjectPairwise') },
          ],
        },
      ]}
      load={() => settingsApi.getProtocolDefaults()}
      save={(v) => settingsApi.putProtocolDefaults(v)}
    />
  )
}

export function SMSPage() {
  const { t } = useTranslation()
  const [secretSet, setSecretSet] = useState(false)
  return (
    <GenericForm<SMS>
      title={t('settings.sms.title')}
      desc={t('settings.sms.desc')}
      rows={[
        { kind: 'bool', key: 'enabled', label: t('settings.sms.enabled') },
        {
          kind: 'select', key: 'provider', label: t('settings.sms.provider'),
          options: [
            { value: '', label: t('settings.sms.providerSelect') },
            { value: 'aliyun', label: t('settings.sms.providerAliyun') },
            { value: 'tencent', label: t('settings.sms.providerTencent') },
            { value: 'twilio', label: t('settings.sms.providerTwilio') },
          ],
        },
        { kind: 'text', key: 'access_key', label: t('settings.sms.accessKey') },
        { kind: 'text', key: 'secret', label: t('settings.sms.secret'), hint: secretSet ? t('settings.sms.secretSet') : '' },
        { kind: 'text', key: 'sign_name', label: t('settings.sms.signName') },
        { kind: 'text', key: 'template', label: t('settings.sms.template') },
        { kind: 'text', key: 'region', label: t('settings.sms.region'), placeholder: 'cn-hangzhou' },
      ]}
      load={async () => {
        const r = await settingsApi.getSMS()
        setSecretSet(r.secret_set)
        return r.config
      }}
      save={(v) => settingsApi.putSMS(v)}
    />
  )
}

export function AuditPolicyPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<AuditPolicy>
      title={t('settings.auditPolicy.title')}
      desc={t('settings.auditPolicy.desc')}
      rows={[
        { kind: 'number', key: 'retention_days', label: t('settings.auditPolicy.retentionDays'), hint: t('settings.auditPolicy.retentionDaysHint') },
        { kind: 'text', key: 'alert_webhook_url', label: t('settings.auditPolicy.webhook'), placeholder: 'https://hook.example.com/...' },
        { kind: 'list', key: 'alert_on_event_types', label: t('settings.auditPolicy.alertEventTypes'), hint: t('settings.auditPolicy.alertEventTypesHint') },
        { kind: 'list', key: 'high_risk_recipients', label: t('settings.auditPolicy.highRiskRecipients'), hint: t('settings.auditPolicy.highRiskRecipientsHint') },
      ]}
      load={() => settingsApi.getAuditPolicy()}
      save={(v) => settingsApi.putAuditPolicy(v)}
    />
  )
}

export function OffboardingWebhookPage() {
  const { t } = useTranslation()
  const [secretSet, setSecretSet] = useState(false)
  return (
    <GenericForm<OffboardingWebhook>
      title={t('settings.offboardingWebhook.title')}
      desc={t('settings.offboardingWebhook.desc')}
      rows={[
        { kind: 'bool', key: 'enabled', label: t('settings.offboardingWebhook.enabled') },
        { kind: 'text', key: 'url', label: t('settings.offboardingWebhook.url'), placeholder: 'https://itsm.example.com/hooks/offboard' },
        { kind: 'text', key: 'secret', label: t('settings.offboardingWebhook.secret'), hint: secretSet ? t('settings.offboardingWebhook.secretSet') : t('settings.offboardingWebhook.secretHint') },
      ]}
      load={async () => {
        const r = await settingsApi.getOffboardingWebhook()
        setSecretSet(r.secret_set)
        return r.config
      }}
      save={(v) => settingsApi.putOffboardingWebhook(v)}
    />
  )
}

export function MFAPolicyPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<MFAPolicy>
      title={t('settings.mfa.title')}
      desc={t('settings.mfa.desc')}
      rows={[
        {
          kind: 'select', key: 'mode', label: t('settings.mfa.mode'),
          options: [
            { value: 'off', label: t('settings.mfa.modeOff') },
            { value: 'admin_only', label: t('settings.mfa.modeAdminOnly') },
            { value: 'all', label: t('settings.mfa.modeAll') },
          ],
        },
        { kind: 'number', key: 'step_up_window_seconds', label: t('settings.mfa.window'), hint: t('settings.mfa.windowHint') },
      ]}
      load={() => settingsApi.getMFA()}
      save={(v) => settingsApi.putMFA(v)}
    />
  )
}

export function ConditionalAccessPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<ConditionalAccess>
      title={t('settings.conditionalAccess.title')}
      desc={t('settings.conditionalAccess.desc')}
      rows={[
        { kind: 'bool', key: 'enabled', label: t('settings.conditionalAccess.enabled') },
        { kind: 'bool', key: 'on_new_country', label: t('settings.conditionalAccess.onNewCountry') },
        { kind: 'bool', key: 'on_impossible_travel', label: t('settings.conditionalAccess.onImpossibleTravel') },
        { kind: 'bool', key: 'on_new_device', label: t('settings.conditionalAccess.onNewDevice') },
        { kind: 'number', key: 'impossible_travel_window_minutes', label: t('settings.conditionalAccess.window'), hint: t('settings.conditionalAccess.windowHint') },
      ]}
      load={() => settingsApi.getConditionalAccess()}
      save={(v) => settingsApi.putConditionalAccess(v)}
    />
  )
}

export function LocalizationPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<Localization>
      title={t('settings.localizationPage.title')}
      desc={t('settings.localizationPage.desc')}
      rows={[
        {
          kind: 'select', key: 'default_language', label: t('settings.localizationPage.defaultLanguage'),
          options: [
            { value: 'zh-CN', label: t('settings.localizationPage.langZhCN') },
            { value: 'en-US', label: t('settings.localizationPage.langEnUS') },
          ],
        },
        {
          kind: 'select', key: 'default_timezone', label: t('settings.localizationPage.defaultTimezone'),
          options: [
            { value: 'Asia/Shanghai', label: t('settings.timezones.shanghai') },
            { value: 'UTC', label: t('settings.timezones.utc') },
            { value: 'America/Los_Angeles', label: t('settings.timezones.losAngeles') },
            { value: 'Europe/London', label: t('settings.timezones.london') },
          ],
        },
        { kind: 'text', key: 'date_format', label: t('settings.localizationPage.dateFormat'), placeholder: 'YYYY-MM-DD HH:mm:ss' },
      ]}
      load={() => settingsApi.getLocalization()}
      save={(v) => settingsApi.putLocalization(v)}
    />
  )
}

export function LicensePage() {
  const { t } = useTranslation()
  const { features, isEE, state } = useEdition()
  const [lic, setLic] = useState<License | null>(null)
  useEffect(() => { settingsApi.getLicense().then(setLic).catch(() => {}) }, [])

  // Read-only derived status — everything except the token itself is computed
  // from the verified license, never editable.
  const banner = (
    <div className="space-y-2">
      {(state === 'expired' || state === 'invalid' || state === 'mismatch') && (
        <div className={cn('rounded-lg border px-4 py-3 text-sm',
          state === 'invalid' ? 'border-amber-200 bg-amber-50 text-amber-800' : 'border-red-200 bg-red-50 text-red-700')}>
          {state === 'expired' ? t('settings.licensePage.expiredWarning')
            : state === 'mismatch' ? t('settings.licensePage.mismatchWarning')
            : t('settings.licensePage.invalidWarning')}
        </div>
      )}
      <div className="space-y-2 rounded-lg border border-border bg-surface-muted px-4 py-3 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-muted">{t('settings.licensePage.editionLabel')}:</span>
          <span className={cn('rounded px-2 py-0.5 text-xs font-semibold',
            isEE ? 'bg-primary/10 text-primary'
              : state === 'invalid' ? 'bg-amber-100 text-amber-800'
              : state === 'ce' ? 'bg-surface-muted text-muted'
              : 'bg-red-100 text-red-700')}>
            {isEE ? 'Enterprise'
              : state === 'expired' ? t('settings.licensePage.stateExpired')
              : state === 'mismatch' ? t('settings.licensePage.stateMismatch')
              : state === 'invalid' ? t('settings.licensePage.stateInvalid') : 'Community'}
          </span>
        </div>
        {isEE && (
          <>
            <div><span className="text-muted">{t('settings.licensePage.registeredTo')}:</span> {lic?.registered_to || '—'}</div>
            <div><span className="text-muted">{t('settings.licensePage.expiresAt')}:</span> {lic?.expires_at || t('settings.licensePage.perpetual')}</div>
            <div><span className="text-muted">{t('settings.licensePage.features')}:</span> {features.join(', ') || '—'}</div>
          </>
        )}
        {lic?.install_id && (
          <div className="border-t border-border pt-2">
            <span className="text-muted">{t('settings.licensePage.installId')}:</span>{' '}
            <code className="select-all rounded bg-surface-muted px-1.5 py-0.5 text-xs text-ink">{lic.install_id}</code>
            <div className="mt-0.5 text-[11px] text-faint">{t('settings.licensePage.installIdHint')}</div>
          </div>
        )}
      </div>
    </div>
  )

  return (
    <GenericForm<License>
      title={t('settings.licensePage.title')}
      desc={t('settings.licensePage.desc')}
      banner={banner}
      onSaved={() => window.location.reload()}
      rows={[
        { kind: 'multiline', key: 'key', label: t('settings.licensePage.key'),
          hint: lic?.key_set ? t('settings.licensePage.keyHintSet') : t('settings.licensePage.keyHint'), rows: 4 },
      ]}
      load={() => settingsApi.getLicense()}
      save={(v) => settingsApi.putLicense(v)}
    />
  )
}

export function ExternalURLsPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<ExternalURLs>
      title={t('settings.externalUrls.title')}
      desc={t('settings.externalUrls.desc')}
      rows={[
        { kind: 'text', key: 'issuer_url', label: t('settings.externalUrls.issuerUrl'), hint: t('settings.externalUrls.issuerHint'), placeholder: 'https://id.example.com' },
        { kind: 'text', key: 'portal_url', label: t('settings.externalUrls.portalUrl'), hint: t('settings.externalUrls.portalHint'), placeholder: 'https://id.example.com' },
        { kind: 'text', key: 'console_url', label: t('settings.externalUrls.consoleUrl'), hint: t('settings.externalUrls.consoleHint'), placeholder: 'https://admin.example.com' },
      ]}
      load={() => settingsApi.getExternalURLs()}
      save={(v) => settingsApi.putExternalURLs(v)}
    />
  )
}

export function MailTemplatesPage() {
  const { t } = useTranslation()
  return (
    <GenericForm<MailTemplates>
      title={t('settings.mailTemplates.title')}
      desc={t('settings.mailTemplates.desc')}
      rows={[
        { kind: 'text', key: 'email_verify.subject', label: t('settings.mailTemplates.emailVerifySubject') },
        { kind: 'multiline', key: 'email_verify.body', label: t('settings.mailTemplates.emailVerifyBody'), rows: 6 },
        { kind: 'text', key: 'password_reset.subject', label: t('settings.mailTemplates.passwordResetSubject') },
        { kind: 'multiline', key: 'password_reset.body', label: t('settings.mailTemplates.passwordResetBody'), rows: 6 },
        { kind: 'text', key: 'welcome.subject', label: t('settings.mailTemplates.welcomeSubject') },
        { kind: 'multiline', key: 'welcome.body', label: t('settings.mailTemplates.welcomeBody'), rows: 6 },
      ]}
      load={() => settingsApi.getMailTemplates()}
      save={(v) => settingsApi.putMailTemplates(v)}
    />
  )
}
