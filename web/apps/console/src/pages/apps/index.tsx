import { useEffect, useState, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, AppWindow, Loader2, Copy, X, Settings, Eye, EyeOff, LayoutGrid, Search } from 'lucide-react'
import { appApi, protocolLabel, statusLabel, statusColor, cn, AppIcon, useTranslation, AppStatus } from '@mxid/shared'
import type { App, PaginatedData, AppTemplate, AppTemplateListItem } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import AppGroupsTab from './AppGroupsTab'
import { useTabParam } from '../../hooks/useTabParam'
import { CodeField, pageMotion, Button, ConfirmDialog, Modal } from '../../components/ui'
import { IconPicker } from '../../components/icon-picker/IconPicker'
import { toast, extractMessage } from '../../components/ui/toast'
import AccessPolicyTab from './AccessPolicyTab'
import AppRolesTab from './AppRolesTab'
import ProvisioningTab from './ProvisioningTab'
import SharedCredentialPanel from './SharedCredentialPanel'

const APPS_VIEW_VALUES = ['apps', 'groups'] as const
const DETAIL_TAB_VALUES = ['basic', 'protocol', 'credentials', 'access', 'roles', 'provisioning'] as const

const protocolColors: Record<string, string> = {
  oidc: 'bg-blue-100 text-blue-700',
  saml: 'bg-purple-100 text-purple-700',
  cas: 'bg-teal-100 text-teal-700',
  form: 'bg-emerald-100 text-emerald-700',
}

// ---------------------------------------------------------------------------
// Protocol config field definitions
// ---------------------------------------------------------------------------

// coerce: how to convert the form's string value when sending it into
// protocol_config JSON, and how to flatten it back into a string when
// loading from the backend. Default ("string") keeps everything as-is.
type Coerce = 'string' | 'int' | 'bool' | 'string_array_csv' | 'json'

interface SelectOption {
  value: string
  label: string
}

interface ConfigField {
  key: string
  label: string
  type: 'text' | 'textarea' | 'select'
  placeholder?: string
  coerce?: Coerce
  // For `select` fields. The first option is used when the form value is empty.
  options?: SelectOption[]
  // Optional one-line hint rendered below the input. Use to explain
  // non-obvious fields (e.g. NameID format trade-offs) without forcing
  // operators to read docs.
  hint?: string
}

// encodeFieldValue turns a form string into the value the backend expects.
// Empty inputs return undefined so the caller can drop the key from the
// payload — leaves the backend default in place.
function encodeFieldValue(raw: string, coerce: Coerce | undefined): unknown {
  if (raw === '' || raw === undefined) return undefined
  switch (coerce) {
    case 'int':
      return Number.parseInt(raw, 10)
    case 'bool':
      return raw.toLowerCase() === 'true'
    case 'string_array_csv':
      return raw.split(',').map((s) => s.trim()).filter(Boolean)
    case 'json':
      try {
        return JSON.parse(raw)
      } catch {
        // Surface as-is so the backend returns a clearer error than
        // silently dropping the field.
        throw new Error(`Invalid JSON: ${raw}`)
      }
    default:
      return raw
  }
}

// decodeFieldValue flattens a backend value back into the text the form
// renders. Mirrors encodeFieldValue exactly.
function decodeFieldValue(v: unknown, coerce: Coerce | undefined): string {
  if (v === null || v === undefined) return ''
  switch (coerce) {
    case 'string_array_csv':
      return Array.isArray(v) ? v.join(',') : String(v)
    case 'json':
      return typeof v === 'string' ? v : JSON.stringify(v)
    case 'bool':
      return v === true ? 'true' : 'false'
    default:
      return typeof v === 'string' ? v : String(v)
  }
}

// buildProtocolConfigFields returns the per-protocol config descriptors with
// localized label/hint/option text. A factory (not a module const) so labels
// resolve through t() — call it inside a component with useMemo. Field keys,
// types, coerce, and placeholders (example values) are NOT translated: keys map
// to backend json tags, placeholders are illustrative samples.
function buildProtocolConfigFields(t: (k: string) => string): Record<string, ConfigField[]> {
  const p = (proto: string, key: string, leaf: string) => t(`apps.protocolFields.${proto}.${key}.${leaf}`)
  return {
    oidc: [
      // Fields below populate the protocol_config JSONB blob that the OIDC IdP
      // reads when handling /authorize and /token for THIS app. They do NOT
      // describe a remote OIDC provider — MXID is the provider.
      { key: 'scopes', label: p('oidc', 'scopes', 'label'), type: 'text', placeholder: 'openid profile email phone groups' },
      { key: 'grant_types', label: p('oidc', 'grant_types', 'label'), type: 'text', placeholder: 'authorization_code refresh_token' },
      { key: 'response_types', label: p('oidc', 'response_types', 'label'), type: 'text', placeholder: 'code' },
      { key: 'token_endpoint_auth_method', label: p('oidc', 'token_endpoint_auth_method', 'label'), type: 'text', placeholder: 'client_secret_basic | client_secret_post | none' },
      { key: 'pkce_required', label: p('oidc', 'pkce_required', 'label'), type: 'text', placeholder: 'false (true for SPA / native)' },
      { key: 'access_token_lifetime', label: p('oidc', 'access_token_lifetime', 'label'), type: 'text', placeholder: '3600' },
      { key: 'id_token_lifetime', label: p('oidc', 'id_token_lifetime', 'label'), type: 'text', placeholder: '3600' },
      { key: 'refresh_token_lifetime', label: p('oidc', 'refresh_token_lifetime', 'label'), type: 'text', placeholder: '2592000' },
      { key: 'id_token_signing_alg', label: p('oidc', 'id_token_signing_alg', 'label'), type: 'text', placeholder: 'RS256' },
      { key: 'subject_type', label: p('oidc', 'subject_type', 'label'), type: 'text', placeholder: 'public' },
    ],
    saml: [
      // Field keys match internal/protocol/saml/config.go SAMLConfig json tags
      // one-to-one. Don't rename without updating the backend struct.
      { key: 'sp_entity_id', label: p('saml', 'sp_entity_id', 'label'), type: 'text', placeholder: 'https://app.example.com/saml/metadata', hint: p('saml', 'sp_entity_id', 'hint') },
      { key: 'acs_url', label: p('saml', 'acs_url', 'label'), type: 'text', placeholder: 'https://app.example.com/saml/acs', hint: p('saml', 'acs_url', 'hint') },
      { key: 'slo_url', label: p('saml', 'slo_url', 'label'), type: 'text', placeholder: 'https://app.example.com/saml/sls', hint: p('saml', 'slo_url', 'hint') },
      {
        key: 'name_id_format',
        label: p('saml', 'name_id_format', 'label'),
        type: 'select',
        options: [
          { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', label: p('saml', 'name_id_format', 'opt.email') },
          { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', label: p('saml', 'name_id_format', 'opt.persistent') },
          { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified', label: p('saml', 'name_id_format', 'opt.unspecified') },
          { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', label: p('saml', 'name_id_format', 'opt.transient') },
        ],
        hint: p('saml', 'name_id_format', 'hint'),
      },
      { key: 'sp_cert', label: p('saml', 'sp_cert', 'label'), type: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----', hint: p('saml', 'sp_cert', 'hint') },
      {
        key: 'sign_assertions',
        label: p('saml', 'sign_assertions', 'label'),
        type: 'select',
        coerce: 'bool',
        options: [
          { value: 'true', label: p('saml', 'sign_assertions', 'opt.yes') },
          { value: 'false', label: p('saml', 'sign_assertions', 'opt.no') },
        ],
        hint: p('saml', 'sign_assertions', 'hint'),
      },
      {
        key: 'sign_response',
        label: p('saml', 'sign_response', 'label'),
        type: 'select',
        coerce: 'bool',
        options: [
          { value: 'true', label: p('saml', 'sign_response', 'opt.yes') },
          { value: 'false', label: p('saml', 'sign_response', 'opt.no') },
        ],
        hint: p('saml', 'sign_response', 'hint'),
      },
      {
        key: 'encrypt_assertion',
        label: p('saml', 'encrypt_assertion', 'label'),
        type: 'select',
        coerce: 'bool',
        options: [
          { value: 'false', label: p('saml', 'encrypt_assertion', 'opt.no') },
          { value: 'true', label: p('saml', 'encrypt_assertion', 'opt.yes') },
        ],
        hint: p('saml', 'encrypt_assertion', 'hint'),
      },
      { key: 'attribute_mapping', label: p('saml', 'attribute_mapping', 'label'), type: 'textarea', coerce: 'json', placeholder: '{"username":"uid","email":"mail","display_name":"displayName","phone":"telephoneNumber"}', hint: p('saml', 'attribute_mapping', 'hint') },
      { key: 'session_ttl', label: p('saml', 'session_ttl', 'label'), type: 'text', coerce: 'int', placeholder: '28800', hint: p('saml', 'session_ttl', 'hint') },
    ],
    cas: [
      { key: 'service_urls', label: p('cas', 'service_urls', 'label'), type: 'text', placeholder: 'http://app.example.com/cas/callback,https://other.example.com/', coerce: 'string_array_csv' },
      { key: 'ticket_ttl', label: p('cas', 'ticket_ttl', 'label'), type: 'text', placeholder: '30', coerce: 'int' },
      { key: 'attribute_mapping', label: p('cas', 'attribute_mapping', 'label'), type: 'textarea', placeholder: '{"username":"uid","email":"mail","display_name":"displayName","phone":"telephoneNumber"}', coerce: 'json' },
      { key: 'renew_enabled', label: p('cas', 'renew_enabled', 'label'), type: 'text', placeholder: 'false', coerce: 'bool' },
    ],
    // Form-fill (SWA) descriptor. credential_mode picks per-user vs shared vault;
    // the selectors + login_url tell the browser extension how to auto-submit the
    // target login form (capture mode fills these automatically later).
    form: [
      {
        key: 'credential_mode',
        label: p('form', 'credential_mode', 'label'),
        type: 'select',
        options: [
          { value: 'per_user', label: p('form', 'credential_mode', 'opt.perUser') },
          { value: 'shared', label: p('form', 'credential_mode', 'opt.shared') },
        ],
        hint: p('form', 'credential_mode', 'hint'),
      },
      { key: 'login_url', label: p('form', 'login_url', 'label'), type: 'text', placeholder: 'https://wiki.internal/login', hint: p('form', 'login_url', 'hint') },
      { key: 'username_selector', label: p('form', 'username_selector', 'label'), type: 'text', placeholder: '#username' },
      { key: 'password_selector', label: p('form', 'password_selector', 'label'), type: 'text', placeholder: '#password' },
      { key: 'submit_selector', label: p('form', 'submit_selector', 'label'), type: 'text', placeholder: 'button[type=submit]' },
      { key: 'next_selector', label: p('form', 'next_selector', 'label'), type: 'text', placeholder: 'button.next', hint: p('form', 'next_selector', 'hint') },
      { key: 'extra_fields', label: p('form', 'extra_fields', 'label'), type: 'textarea', coerce: 'json', placeholder: '[{"selector":"#tenant","value":"acme"}]', hint: p('form', 'extra_fields', 'hint') },
      { key: 'success_url_glob', label: p('form', 'success_url_glob', 'label'), type: 'text', placeholder: 'https://wiki.internal/dashboard*' },
    ],
  }
}

// ---------------------------------------------------------------------------
// Clipboard helper
// ---------------------------------------------------------------------------

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  })
}

// ---------------------------------------------------------------------------
// CopyField component
// ---------------------------------------------------------------------------

function CopyField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    copyToClipboard(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-ink">{label}</label>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={value}
          readOnly
          className="flex-1 rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted outline-none"
        />
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-muted"
        >
          <Copy className="h-3.5 w-3.5" />
          {copied ? t('common.copied') : t('common.copy')}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// SecretField component (with show/hide toggle)
// ---------------------------------------------------------------------------

function SecretField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation()
  const [visible, setVisible] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    copyToClipboard(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-ink">{label}</label>
      <div className="flex items-center gap-2">
        <input
          type={visible ? 'text' : 'password'}
          value={value}
          readOnly
          className="flex-1 rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted outline-none"
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          className="inline-flex items-center rounded-lg border border-border px-2.5 py-2 text-muted transition-colors hover:bg-surface-muted"
        >
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-muted"
        >
          <Copy className="h-3.5 w-3.5" />
          {copied ? t('common.copied') : t('common.copy')}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Detail drawer tabs
// ---------------------------------------------------------------------------

type DetailTab = 'basic' | 'protocol' | 'credentials' | 'access' | 'roles' | 'provisioning'

const DETAIL_TAB_KEYS: DetailTab[] = ['basic', 'protocol', 'credentials', 'access', 'roles', 'provisioning']

// ---------------------------------------------------------------------------
// Input class constant
// ---------------------------------------------------------------------------

const inputCls =
  'w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20'

// Environment presets offered in the app-detail select; admins may still type a
// custom value via the "custom" option. Keep in sync with the portal's ENV_ORDER.
const ENV_PRESETS = ['prod', 'uat', 'qa', 'staging', 'dev']

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

type AppsView = 'apps' | 'groups'

export default function AppsPage() {
  const { t } = useTranslation()
  // Per-protocol config field descriptors, localized. Rebuilt when the language
  // changes so labels/hints follow the active locale.
  const protocolConfigFields = useMemo(() => buildProtocolConfigFields(t), [t])
  // tab + nested-detail tab persisted to URL so refresh / share preserves UI state.
  const [view, setView] = useTabParam<AppsView>('view', 'apps', APPS_VIEW_VALUES)
  const [data, setData] = useState<PaginatedData<App>>({ items: [], total: 0, page: 1, page_size: 50 })
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)

  // List filters (backend supports search over name/code/description + protocol
  // + status via the /apps query params). searchInput is the raw field value;
  // it debounces into `search` so we don't fire a request per keystroke.
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [protocol, setProtocol] = useState('')
  const [status, setStatus] = useState('')
  useEffect(() => {
    const id = setTimeout(() => setSearch(searchInput.trim()), 300)
    return () => clearTimeout(id)
  }, [searchInput])
  // Any filter change resets to page 1 so results aren't hidden past the end.
  useEffect(() => {
    setPage(1)
  }, [search, protocol, status])

  // Create modal state
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({
    name: '',
    code: '',
    protocol: 'oidc',
    client_type: 'web_app',
    home_url: '',
    redirect_uris: '',
  })
  const [creating, setCreating] = useState(false)

  // Template picker state
  const [templates, setTemplates] = useState<AppTemplateListItem[]>([])
  // Custom env labels already used by the tenant's apps (from the DB), merged
  // with the static presets so a previously-typed env reappears in the dropdown.
  const [envOptions, setEnvOptions] = useState<string[]>([])
  const [activeTemplate, setActiveTemplate] = useState<AppTemplate | null>(null)
  const [tplFieldValues, setTplFieldValues] = useState<Record<string, string>>({})

  // One-time client_secret reveal modal (shown immediately after create / rotate).
  // The backend stores bcrypt hash only; if the user closes this modal they
  // cannot retrieve the plaintext — they must rotate.
  const [revealedSecret, setRevealedSecret] = useState<{ clientId: string; clientSecret: string } | null>(null)

  // Detail drawer state
  const [detailApp, setDetailApp] = useState<App | null>(null)
  const [delApp, setDelApp] = useState<App | null>(null)
  const [deletingApp, setDeletingApp] = useState(false)
  const [rotateApp, setRotateApp] = useState<App | null>(null)
  const [rotating, setRotating] = useState(false)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailTab, setDetailTab] = useTabParam<DetailTab>('detail_tab', 'basic', DETAIL_TAB_VALUES)

  // Edit basic info state
  const [editForm, setEditForm] = useState({
    name: '',
    description: '',
    icon: '',
    env: '',
    home_url: '',
    login_url: '',
    logout_url: '',
    redirect_uris: '',
  })
  // env is a preset select (prod/uat/qa/staging/dev) with a "custom" escape
  // hatch that reveals a free-text input — envCustom tracks which mode is shown.
  const [envCustom, setEnvCustom] = useState(false)
  const [saving, setSaving] = useState(false)

  // Protocol config state
  const [protocolConfig, setProtocolConfig] = useState<Record<string, string>>({})
  const [protocolConfigLoading, setProtocolConfigLoading] = useState(false)
  const [savingProtocol, setSavingProtocol] = useState(false)

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: 50 }
      if (search) params.search = search
      if (protocol) params.protocol = protocol
      if (status) params.status = Number(status)
      const result = await appApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [page, search, protocol, status])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Load template catalog when create modal opens
  useEffect(() => {
    if (!showCreate) return
    appApi.listTemplates().then(setTemplates).catch(() => setTemplates([]))
  }, [showCreate])

  // Distinct custom envs already in use — loaded on mount and refreshed after a
  // save so a newly-typed env is remembered for the next app.
  const loadEnvOptions = useCallback(() => {
    appApi.listEnvOptions().then(setEnvOptions).catch(() => setEnvOptions([]))
  }, [])
  useEffect(() => {
    loadEnvOptions()
  }, [loadEnvOptions])

  // Dropdown choices: presets first, then DB-known custom envs not already a
  // preset. A known custom env now selects directly instead of forcing the
  // "custom" escape hatch.
  const envChoices = useMemo(() => {
    const seen = new Set(ENV_PRESETS)
    const extra = envOptions.filter((e) => e && !seen.has(e))
    return [...ENV_PRESETS, ...extra]
  }, [envOptions])

  // -------------------------------------------------------------------------
  // Open detail drawer
  // -------------------------------------------------------------------------

  const openDetail = async (app: App) => {
    setDetailTab('basic')
    setDetailLoading(true)
    setDetailApp(app)

    // Pre-fill edit form with current data
    setEditForm({
      name: app.name || '',
      description: app.description || '',
      icon: app.icon || '',
      env: app.env || '',
      home_url: app.home_url || '',
      login_url: app.login_url || '',
      logout_url: app.logout_url || '',
      redirect_uris: (app.redirect_uris || []).join('\n'),
    })
    setEnvCustom(!!app.env && !envChoices.includes(app.env))

    try {
      const full = await appApi.getById(app.id)
      setDetailApp(full)
      setEditForm({
        name: full.name || '',
        description: full.description || '',
        icon: full.icon || '',
        env: full.env || '',
        home_url: full.home_url || '',
        login_url: full.login_url || '',
        logout_url: full.logout_url || '',
        redirect_uris: (full.redirect_uris || []).join('\n'),
      })
      setEnvCustom(!!full.env && !envChoices.includes(full.env))
    } catch {
      // keep the card-level data we already have
    } finally {
      setDetailLoading(false)
    }
  }

  const closeDetail = () => {
    setDetailApp(null)
    setProtocolConfig({})
  }

  // -------------------------------------------------------------------------
  // Load protocol config when switching to that tab
  // -------------------------------------------------------------------------

  const loadProtocolConfig = useCallback(async (appId: string, protocol: string) => {
    setProtocolConfigLoading(true)
    try {
      const cfg = await appApi.getProtocolConfig(appId)
      const fields = protocolConfigFields[protocol] || []
      const coerceByKey: Record<string, Coerce | undefined> = {}
      for (const f of fields) coerceByKey[f.key] = f.coerce
      // Seed select fields with their first option so the rendered value
      // matches the actual state (avoids the "shown but unsaved" gap where
      // a select displays "Yes" while protocolConfig[key] is undefined and
      // the field gets dropped from the save payload).
      const flat: Record<string, string> = {}
      for (const f of fields) {
        if (f.type === 'select' && f.options && f.options.length > 0) {
          flat[f.key] = f.options[0].value
        }
      }
      if (cfg) {
        for (const [k, v] of Object.entries(cfg)) {
          flat[k] = decodeFieldValue(v, coerceByKey[k])
        }
      }
      setProtocolConfig(flat)
    } catch {
      setProtocolConfig({})
    } finally {
      setProtocolConfigLoading(false)
    }
  }, [])

  useEffect(() => {
    if (detailTab === 'protocol' && detailApp) {
      loadProtocolConfig(detailApp.id, detailApp.protocol)
    }
  }, [detailTab, detailApp, loadProtocolConfig])

  // -------------------------------------------------------------------------
  // Save basic info
  // -------------------------------------------------------------------------

  const handleSaveBasic = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!detailApp) return
    setSaving(true)
    try {
      const uris = editForm.redirect_uris
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)
      const updated = await appApi.update(detailApp.id, {
        name: editForm.name,
        description: editForm.description || null,
        icon: editForm.icon || null,
        // send the string (empty clears): backend treats null as "unchanged",
        // "" as "clear the label", so never coalesce to null here.
        env: editForm.env.trim(),
        home_url: editForm.home_url || null,
        login_url: editForm.login_url || null,
        logout_url: editForm.logout_url || null,
        redirect_uris: uris,
      })
      setDetailApp(updated)
      loadData()
      loadEnvOptions() // a newly-typed env should be remembered for the next app
      toast.success(t('common.success'))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('common.failed'), msg)
    } finally {
      setSaving(false)
    }
  }

  // -------------------------------------------------------------------------
  // Save protocol config
  // -------------------------------------------------------------------------

  const handleSaveProtocol = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!detailApp) return
    setSavingProtocol(true)
    try {
      const payload: Record<string, unknown> = {}
      const fields = protocolConfigFields[detailApp.protocol] || []
      for (const f of fields) {
        const raw = protocolConfig[f.key]
        const v = encodeFieldValue(raw, f.coerce)
        if (v !== undefined) {
          payload[f.key] = v
        }
      }
      await appApi.updateProtocolConfig(detailApp.id, payload)
      toast.success(t('common.success'))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('common.failed'), msg)
    } finally {
      setSavingProtocol(false)
    }
  }

  // -------------------------------------------------------------------------
  // Toggle status / delete (existing features)
  // -------------------------------------------------------------------------

  const handleToggleStatus = async (app: App) => {
    const newStatus = app.status === AppStatus.Enabled ? AppStatus.Disabled : AppStatus.Enabled
    try {
      await appApi.updateStatus(app.id, newStatus)
      toast.success(newStatus === 1 ? t('apps.list.statusEnabled') : t('apps.list.statusDisabled'))
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    }
  }

  const confirmDeleteApp = async () => {
    const app = delApp
    if (!app) return
    setDeletingApp(true)
    try {
      await appApi.delete(app.id)
      toast.success(t('common.success'))
      setDelApp(null)
      if (detailApp?.id === app.id) closeDetail()
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setDeletingApp(false)
    }
  }

  // -------------------------------------------------------------------------
  // Template picker handlers
  // -------------------------------------------------------------------------

  const handlePickTemplate = useCallback(async (key: string) => {
    try {
      const tpl = await appApi.getTemplate(key)
      setActiveTemplate(tpl)
      setTplFieldValues({})
      setCreateForm((f) => ({
        ...f,
        protocol: tpl.protocol,
        client_type: tpl.client_type,
        // Picking a template sets the app name to the template name so the
        // name follows the chosen template (incl. when switching templates).
        // The user can still edit it afterwards.
        name: tpl.name,
      }))
    } catch {
      toast.error(t('apps.templates.loadFailed'))
    }
  }, [t])

  const handleClearTemplate = useCallback(() => {
    setActiveTemplate(null)
    setTplFieldValues({})
  }, [])

  // -------------------------------------------------------------------------
  // Create app
  // -------------------------------------------------------------------------

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createForm.name || !createForm.code) return
    setCreating(true)
    try {
      // Build protocol_config + top-level fields from the active template (if any).
      const tplProtocolConfig: Record<string, unknown> = activeTemplate?.defaults ? { ...activeTemplate.defaults } : {}
      let redirectURIs: string[] = createForm.redirect_uris.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
      let homeUrl = createForm.home_url

      if (activeTemplate?.key) {
        // Validate + fold template field values into their targets
        for (const fld of activeTemplate.fields ?? []) {
          const raw = (tplFieldValues[fld.key] ?? '').trim()
          if (!raw) continue
          if (fld.target === 'redirect_uris') {
            redirectURIs = raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
          } else if (fld.target === 'home_url') {
            homeUrl = raw
          } else if (fld.target.startsWith('protocol_config.')) {
            const k = fld.target.slice('protocol_config.'.length)
            tplProtocolConfig[k] = k.endsWith('_urls')
              ? raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
              : raw
          }
        }
      }

      // Determine the final protocol_config to send:
      // - When a template is active: use tplProtocolConfig (seeded from defaults + fields)
      // - When no template (blank/OIDC form): use the existing OIDC-default builder
      const protocolConfig: Record<string, unknown> | undefined = activeTemplate?.key
        ? (Object.keys(tplProtocolConfig).length > 0 ? tplProtocolConfig : undefined)
        : createForm.protocol === 'oidc'
          ? {
              redirect_uris: redirectURIs,
              scopes: ['openid', 'profile', 'email', 'groups'],
              grant_types:
                createForm.client_type === 'm2m'
                  ? ['client_credentials']
                  : ['authorization_code', 'refresh_token'],
              response_types: ['code'],
              token_endpoint_auth_method:
                createForm.client_type === 'spa' || createForm.client_type === 'native'
                  ? 'none'
                  : 'client_secret_basic',
              pkce_required:
                createForm.client_type === 'spa' || createForm.client_type === 'native',
              access_token_lifetime: 3600,
              id_token_lifetime: 3600,
              refresh_token_lifetime: 2592000,
              id_token_signing_alg: 'RS256',
              subject_type: 'public',
            }
          : undefined

      const created = await appApi.create({
        name: createForm.name,
        code: createForm.code,
        protocol: createForm.protocol,
        client_type: createForm.client_type,
        home_url: homeUrl || null,
        redirect_uris: redirectURIs,
        protocol_config: protocolConfig,
        ...(activeTemplate?.subject_strategy
          ? { subject_strategy: activeTemplate.subject_strategy }
          : {}),
      })

      setShowCreate(false)
      setCreateForm({
        name: '',
        code: '',
        protocol: 'oidc',
        client_type: 'web_app',
        home_url: '',
        redirect_uris: '',
      })
      setActiveTemplate(null)
      setTplFieldValues({})

      // Capture the one-time plaintext client_secret. Only confidential clients
      // (web_app / m2m) receive it; SPA / native have no secret to reveal.
      if (created?.client_secret) {
        setRevealedSecret({
          clientId: created.client_id || '',
          clientSecret: created.client_secret,
        })
      }
      loadData()
      toast.success(t('common.success'))
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setCreating(false)
    }
  }

  // -------------------------------------------------------------------------
  // Rotate client_secret
  // -------------------------------------------------------------------------

  const confirmRotateSecret = async () => {
    const app = rotateApp
    if (!app) return
    setRotating(true)
    try {
      const result = await appApi.regenerateSecret(app.id)
      setRevealedSecret({
        clientId: app.client_id || '',
        clientSecret: result.client_secret,
      })
      setRotateApp(null)
      toast.success(t('apps.detail.credentials.rotated'))
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setRotating(false)
    }
  }

  const totalPages = Math.ceil(data.total / data.page_size) || 1

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('apps.title')}
        description={view === 'apps' ? t('apps.subtitle') : t('apps.appGroups.subtitle')}
        actions={
          view === 'apps' ? (
            <Button onClick={() => setShowCreate(true)} icon={<Plus className="h-4 w-4" />}>
              {t('apps.createModal.title')}
            </Button>
          ) : null
        }
      />

      {/* View switcher */}
      <div className="mb-4 inline-flex rounded-lg border border-border bg-surface p-1">
        <button
          onClick={() => setView('apps')}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
            view === 'apps' ? 'bg-primary text-white' : 'text-muted hover:text-ink',
          )}
        >
          <AppWindow className="h-3.5 w-3.5" />
          {t('apps.list.appList')}
        </button>
        <button
          onClick={() => setView('groups')}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
            view === 'groups' ? 'bg-primary text-white' : 'text-muted hover:text-ink',
          )}
        >
          <LayoutGrid className="h-3.5 w-3.5" />
          {t('apps.list.appGroups')}
        </button>
      </div>

      {view === 'groups' ? (
        <AppGroupsTab />
      ) : (
      <>
      {/* Filters: search (name/code/description) + protocol + status */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1 sm:max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder={t('apps.filter.searchPlaceholder')}
            className="w-full rounded-lg border border-border bg-surface py-2 pl-9 pr-8 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => setSearchInput('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-muted"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary/20"
        >
          <option value="">{t('apps.filter.allProtocols')}</option>
          <option value="oidc">{protocolLabel('oidc')}</option>
          <option value="saml">{protocolLabel('saml')}</option>
          <option value="cas">{protocolLabel('cas')}</option>
          <option value="form">{protocolLabel('form')}</option>
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary/20"
        >
          <option value="">{t('apps.filter.allStatus')}</option>
          <option value={String(AppStatus.Enabled)}>{statusLabel(AppStatus.Enabled)}</option>
          <option value={String(AppStatus.Disabled)}>{statusLabel(AppStatus.Disabled)}</option>
        </select>
      </div>

      {/* Card grid */}
      {loading ? (
        <div className="py-20 text-center text-sm text-faint">{t('common.loading')}</div>
      ) : data.items.length === 0 ? (
        <div className="py-20 text-center text-sm text-faint">{t('apps.list.empty')}</div>
      ) : (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {data.items.map((app, i) => (
            <motion.div
              key={app.id}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04, duration: 0.25 }}
              className="group cursor-pointer rounded-xl border border-border bg-surface p-5 shadow-sm transition-shadow hover:shadow-md"
              onClick={() => openDetail(app)}
            >
              {/* App icon + name */}
              <div className="mb-4 flex items-start justify-between">
                <div className="flex items-center gap-3">
                  {app.icon ? (
                    <AppIcon value={app.icon} size={40} />
                  ) : (
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <AppWindow className="h-5 w-5" />
                    </div>
                  )}
                  <div className="min-w-0">
                    <h3 className="truncate text-sm font-semibold text-ink">{app.name}</h3>
                    <p className="truncate text-xs text-faint">{app.code}</p>
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    openDetail(app)
                  }}
                  className="rounded-lg p-1.5 text-faint opacity-0 transition-all group-hover:opacity-100 hover:bg-surface-muted hover:text-muted"
                  title={t('apps.list.detail')}
                >
                  <Settings className="h-4 w-4" />
                </button>
              </div>

              {/* Description */}
              <p className="mb-4 line-clamp-2 text-xs text-muted">
                {app.description || t('apps.list.noDescription')}
              </p>

              {/* Tags */}
              <div className="mb-4 flex items-center gap-2">
                <span
                  className={cn(
                    'inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium',
                    protocolColors[app.protocol] || 'bg-surface-muted text-ink'
                  )}
                >
                  {protocolLabel(app.protocol)}
                </span>
                <span
                  className={cn(
                    'inline-flex items-center text-xs font-medium',
                    statusColor(app.status)
                  )}
                >
                  {statusLabel(app.status)}
                </span>
                {app.env && (
                  <span className="inline-flex rounded-full bg-surface-muted px-2.5 py-0.5 text-xs font-medium uppercase text-muted">
                    {app.env}
                  </span>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 border-t border-border pt-3">
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    handleToggleStatus(app)
                  }}
                  className={cn(
                    'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                    app.status === AppStatus.Enabled
                      ? 'text-muted hover:bg-surface-muted'
                      : 'text-emerald-600 hover:bg-emerald-50'
                  )}
                >
                  {app.status === AppStatus.Enabled ? t('common.disable') : t('common.enable')}
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    setDelApp(app)
                  }}
                  className="rounded px-2.5 py-1 text-xs font-medium text-red-500 transition-colors hover:bg-red-50"
                >
                  {t('common.delete')}
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {data.total > 0 && (
        <div className="mt-6 flex items-center justify-between">
          <p className="text-sm text-muted">{t('apps.list.total', { total: data.total })}</p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="rounded-lg border border-border px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-surface-muted"
            >
              {t('apps.list.prevPage')}
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="rounded-lg border border-border px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-surface-muted"
            >
              {t('apps.list.nextPage')}
            </button>
          </div>
        </div>
      )}

      {/* Create Modal */}
      <Modal
        open={showCreate}
        title={t('apps.createModal.title')}
        onClose={() => { setShowCreate(false); setActiveTemplate(null); setTplFieldValues({}) }}
        size="xl"
      >
            <form onSubmit={handleCreate} className="space-y-4">
              {/* Template picker step */}
              {!activeTemplate ? (
                <div className="space-y-3">
                  <div className="text-sm font-medium text-ink">{t('apps.templates.pick')}</div>
                  <div className="grid grid-cols-3 gap-2 max-h-80 overflow-y-auto">
                    {templates.map((tpl) => (
                      <button
                        key={tpl.key}
                        type="button"
                        onClick={() => handlePickTemplate(tpl.key)}
                        className="flex items-center gap-3 rounded-lg border border-border px-3 py-2.5 text-left hover:border-blue-400 hover:bg-blue-50/30"
                      >
                        <AppIcon value={tpl.icon} fallbackName={tpl.name} size={32} />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium">{tpl.name}</div>
                          <div className="text-xs text-faint">{protocolLabel(tpl.protocol)}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTemplate({ key: '', name: '', category: '', protocol: createForm.protocol, client_type: createForm.client_type } as AppTemplate)}
                    className="text-sm text-blue-600"
                  >
                    {t('apps.templates.blank')}
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  {activeTemplate.key && (
                    <div className="flex items-center justify-between rounded-lg bg-blue-50 px-3 py-2">
                      <span className="text-sm font-medium text-blue-800">{activeTemplate.name}</span>
                      <button type="button" onClick={handleClearTemplate} className="text-xs text-blue-600">{t('apps.templates.change')}</button>
                    </div>
                  )}
                  {activeTemplate.doc_md && (
                    <pre className="whitespace-pre-wrap rounded-lg bg-surface-muted px-3 py-2 text-xs text-muted">{activeTemplate.doc_md}</pre>
                  )}
                  {(activeTemplate.fields ?? []).map((fld) => (
                    <div key={fld.key}>
                      <label className="mb-1 block text-sm font-medium text-ink">{fld.label}</label>
                      {fld.type === 'textarea' ? (
                        <textarea className={inputCls} placeholder={fld.placeholder} value={tplFieldValues[fld.key] ?? ''}
                          onChange={(e) => setTplFieldValues((v) => ({ ...v, [fld.key]: e.target.value }))} />
                      ) : (
                        <input className={inputCls} placeholder={fld.placeholder} value={tplFieldValues[fld.key] ?? ''}
                          onChange={(e) => setTplFieldValues((v) => ({ ...v, [fld.key]: e.target.value }))} />
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Name + Code always visible */}
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('apps.createModal.nameLabel')}</label>
                <input
                  type="text"
                  value={createForm.name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))}
                  className={inputCls}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('apps.createModal.codeLabel')}</label>
                <CodeField
                  value={createForm.code}
                  onChange={(v) => setCreateForm((f) => ({ ...f, code: v }))}
                  nameForSlug={createForm.name}
                  prefix="app"
                  placeholder="jira / harbor / jumpserver ..."
                />
                <p className="mt-1 text-xs text-faint">
                  {t('apps.createModal.codeHint', { example: `/protocol/saml/${createForm.code || 'jira'}/metadata` })}
                </p>
              </div>

              {/* Manual Protocol/ClientType/home_url/redirect_uris — hidden when a real template is active */}
              {!activeTemplate?.key && (
                <>
                  <div>
                    <label className="mb-1 block text-sm font-medium text-ink">{t('apps.createModal.protocolLabel')}</label>
                    <select
                      value={createForm.protocol}
                      onChange={(e) => setCreateForm((f) => ({ ...f, protocol: e.target.value }))}
                      className={inputCls}
                    >
                      <option value="oidc">OIDC</option>
                      <option value="saml">SAML 2.0</option>
                      <option value="cas">CAS 3.0</option>
                      <option value="form">{t('apps.createModal.protocols.form')}</option>
                    </select>
                  </div>

                  {createForm.protocol === 'oidc' && (
                    <>
                      <div>
                        <label className="mb-1 block text-sm font-medium text-ink">
                          {t('apps.createModal.clientTypeLabel')}
                        </label>
                        <select
                          value={createForm.client_type}
                          onChange={(e) => setCreateForm((f) => ({ ...f, client_type: e.target.value }))}
                          className={inputCls}
                        >
                          <option value="web_app">{t('apps.createModal.clientTypes.webApp')}</option>
                          <option value="spa">{t('apps.createModal.clientTypes.spa')}</option>
                          <option value="native">{t('apps.createModal.clientTypes.native')}</option>
                          <option value="m2m">{t('apps.createModal.clientTypes.m2m')}</option>
                        </select>
                      </div>

                      <div>
                        <label className="mb-1 block text-sm font-medium text-ink">
                          {t('apps.createModal.homeUrlLabel')}
                        </label>
                        <input
                          type="text"
                          value={createForm.home_url}
                          onChange={(e) => setCreateForm((f) => ({ ...f, home_url: e.target.value }))}
                          className={inputCls}
                          placeholder="https://app.example.com"
                        />
                      </div>

                      <div>
                        <label className="mb-1 block text-sm font-medium text-ink">
                          {t('apps.createModal.redirectUrisLabel')} {createForm.client_type !== 'm2m' && '*'}
                        </label>
                        <textarea
                          value={createForm.redirect_uris}
                          onChange={(e) =>
                            setCreateForm((f) => ({ ...f, redirect_uris: e.target.value }))
                          }
                          rows={3}
                          className={inputCls}
                          placeholder={'http://localhost:8090/callback\nhttps://app.example.com/auth/callback'}
                          required={createForm.client_type !== 'm2m'}
                        />
                      </div>
                    </>
                  )}
                </>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => { setShowCreate(false); setActiveTemplate(null); setTplFieldValues({}) }}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={creating}>
                  {t('apps.createModal.submit')}
                </Button>
              </div>
            </form>
      </Modal>

      </>
      )}

      {/* Detail Drawer */}
      <AnimatePresence>
        {detailApp && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40"
              onClick={closeDetail}
            />
            {/* Drawer */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="fixed inset-y-0 right-0 z-50 flex w-full max-w-4xl flex-col bg-surface shadow-2xl"
            >
              {/* Header */}
              <div className="flex items-center justify-between border-b border-border px-6 py-4">
                <div className="flex items-center gap-3">
                  {detailApp.icon ? (
                    <AppIcon value={detailApp.icon} size={40} />
                  ) : (
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <AppWindow className="h-5 w-5" />
                    </div>
                  )}
                  <div>
                    <h2 className="text-lg font-semibold text-ink">{detailApp.name}</h2>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-faint">{detailApp.code}</span>
                      <span
                        className={cn(
                          'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
                          protocolColors[detailApp.protocol] || 'bg-surface-muted text-ink'
                        )}
                      >
                        {protocolLabel(detailApp.protocol)}
                      </span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={closeDetail}
                  className="rounded-lg p-2 text-faint transition-colors hover:bg-surface-muted hover:text-muted"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Tabs */}
              <div className="flex border-b border-border px-6">
                {DETAIL_TAB_KEYS.map((tabKey) => (
                  <button
                    key={tabKey}
                    onClick={() => setDetailTab(tabKey)}
                    className={cn(
                      'relative px-4 py-3 text-sm font-medium transition-colors',
                      detailTab === tabKey
                        ? 'text-primary'
                        : 'text-muted hover:text-ink'
                    )}
                  >
                    {t(`apps.detail.tabs.${tabKey}`)}
                    {detailTab === tabKey && (
                      <motion.div
                        layoutId="detail-tab-indicator"
                        className="absolute inset-x-0 bottom-0 h-0.5 bg-primary"
                      />
                    )}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-y-auto px-6 py-6">
                {detailLoading ? (
                  <div className="flex items-center justify-center py-20">
                    <Loader2 className="h-6 w-6 animate-spin text-faint" />
                  </div>
                ) : (
                  <>
                    {/* ---- Basic Info tab ---- */}
                    {detailTab === 'basic' && (
                      <form onSubmit={handleSaveBasic} className="space-y-5">
                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.nameLabel')}
                          </label>
                          <input
                            type="text"
                            value={editForm.name}
                            onChange={(e) =>
                              setEditForm((f) => ({ ...f, name: e.target.value }))
                            }
                            className={inputCls}
                            required
                          />
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.descLabel')}
                          </label>
                          <textarea
                            value={editForm.description}
                            onChange={(e) =>
                              setEditForm((f) => ({ ...f, description: e.target.value }))
                            }
                            rows={3}
                            className={inputCls}
                          />
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.iconLabel')}
                          </label>
                          <IconPicker
                            value={editForm.icon}
                            onChange={(v) => setEditForm((f) => ({ ...f, icon: v }))}
                          />
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.envLabel')}
                          </label>
                          <select
                            value={envCustom ? '__custom' : editForm.env}
                            onChange={(e) => {
                              const v = e.target.value
                              if (v === '__custom') {
                                setEnvCustom(true)
                              } else {
                                setEnvCustom(false)
                                setEditForm((f) => ({ ...f, env: v }))
                              }
                            }}
                            className={inputCls}
                          >
                            <option value="">{t('apps.detail.basic.envNone')}</option>
                            {envChoices.map((e) => (
                              <option key={e} value={e}>
                                {e}
                              </option>
                            ))}
                            <option value="__custom">{t('apps.detail.basic.envCustom')}</option>
                          </select>
                          {envCustom && (
                            <input
                              type="text"
                              value={editForm.env}
                              onChange={(e) =>
                                setEditForm((f) => ({ ...f, env: e.target.value }))
                              }
                              className={`${inputCls} mt-2`}
                              placeholder="canary / dr ..."
                            />
                          )}
                          <p className="mt-1 text-xs text-muted">
                            {t('apps.detail.basic.envHint')}
                          </p>
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.homeUrlLabel')}
                          </label>
                          <input
                            type="text"
                            value={editForm.home_url}
                            onChange={(e) =>
                              setEditForm((f) => ({ ...f, home_url: e.target.value }))
                            }
                            className={inputCls}
                            placeholder="https://app.example.com"
                          />
                          <p className="mt-1 text-xs text-muted">
                            {t('apps.detail.basic.homeUrlHint')}
                          </p>
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.loginUrlLabel')}
                          </label>
                          <input
                            type="text"
                            value={editForm.login_url}
                            onChange={(e) =>
                              setEditForm((f) => ({ ...f, login_url: e.target.value }))
                            }
                            className={inputCls}
                            placeholder="https://app.example.com/login"
                          />
                        </div>

                        <div>
                          <label className="mb-1 block text-sm font-medium text-ink">
                            {t('apps.detail.basic.logoutUrlLabel')}
                          </label>
                          <input
                            type="text"
                            value={editForm.logout_url}
                            onChange={(e) =>
                              setEditForm((f) => ({ ...f, logout_url: e.target.value }))
                            }
                            className={inputCls}
                            placeholder="https://app.example.com/logout"
                          />
                        </div>

                        {/* Redirect URIs are an OIDC concept (redirect_uri spec). SAML
                            uses ACS URL configured under 协议配置; CAS uses the service
                            URL allow-list there. Hide for non-OIDC apps to keep the
                            basic tab protocol-clean. */}
                        {detailApp.protocol === 'oidc' && (
                          <div>
                            <label className="mb-1 block text-sm font-medium text-ink">
                              {t('apps.detail.basic.redirectUrisLabel')}
                            </label>
                            <textarea
                              value={editForm.redirect_uris}
                              onChange={(e) =>
                                setEditForm((f) => ({ ...f, redirect_uris: e.target.value }))
                              }
                              rows={3}
                              className={inputCls}
                              placeholder={'https://app.example.com/callback\nhttps://app.example.com/auth/callback'}
                            />
                          </div>
                        )}

                        <div className="flex justify-end pt-2">
                          <Button type="submit" loading={saving}>
                            {t('common.save')}
                          </Button>
                        </div>
                      </form>
                    )}

                    {/* ---- Protocol Config tab ---- */}
                    {detailTab === 'protocol' && (
                      <>
                        {protocolConfigLoading ? (
                          <div className="flex items-center justify-center py-20">
                            <Loader2 className="h-6 w-6 animate-spin text-faint" />
                          </div>
                        ) : (
                          <form onSubmit={handleSaveProtocol} className="space-y-5">
                            <div className="mb-4 rounded-lg bg-surface-muted px-4 py-3">
                              <p className="text-sm text-muted">
                                {t('apps.detail.protocol.protocolType')}
                                <span
                                  className={cn(
                                    'ml-1 inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium',
                                    protocolColors[detailApp.protocol] || 'bg-surface-muted text-ink'
                                  )}
                                >
                                  {protocolLabel(detailApp.protocol)}
                                </span>
                              </p>
                            </div>

                            {/* SAML SP metadata one-shot import. Hidden for other protocols. */}
                            {detailApp.protocol === 'saml' && (
                              <SamlMetadataImport
                                appId={detailApp.id}
                                onImported={(cfg) => {
                                  // Refresh form from backend echo so the
                                  // operator sees what was parsed without a
                                  // re-fetch.
                                  const flat: Record<string, string> = {}
                                  const fields = protocolConfigFields['saml'] || []
                                  const coerceByKey: Record<string, Coerce | undefined> = {}
                                  for (const f of fields) coerceByKey[f.key] = f.coerce
                                  for (const f of fields) {
                                    if (f.type === 'select' && f.options && f.options.length > 0) {
                                      flat[f.key] = f.options[0].value
                                    }
                                  }
                                  for (const [k, v] of Object.entries(cfg)) {
                                    flat[k] = decodeFieldValue(v, coerceByKey[k])
                                  }
                                  setProtocolConfig(flat)
                                }}
                              />
                            )}

                            {(protocolConfigFields[detailApp.protocol] || []).map((field) => (
                              <div key={field.key}>
                                <label className="mb-1 block text-sm font-medium text-ink">
                                  {field.label}
                                </label>
                                {field.type === 'textarea' ? (
                                  <textarea
                                    value={protocolConfig[field.key] || ''}
                                    onChange={(e) =>
                                      setProtocolConfig((c) => ({
                                        ...c,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                    rows={5}
                                    className={inputCls}
                                    placeholder={field.placeholder}
                                  />
                                ) : field.type === 'select' ? (
                                  <select
                                    value={
                                      protocolConfig[field.key] !== undefined && protocolConfig[field.key] !== ''
                                        ? protocolConfig[field.key]
                                        : field.options?.[0]?.value || ''
                                    }
                                    onChange={(e) =>
                                      setProtocolConfig((c) => ({
                                        ...c,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                    className={inputCls}
                                  >
                                    {(field.options || []).map((opt) => (
                                      <option key={opt.value} value={opt.value}>
                                        {opt.label}
                                      </option>
                                    ))}
                                  </select>
                                ) : (
                                  <input
                                    type="text"
                                    value={protocolConfig[field.key] || ''}
                                    onChange={(e) =>
                                      setProtocolConfig((c) => ({
                                        ...c,
                                        [field.key]: e.target.value,
                                      }))
                                    }
                                    className={inputCls}
                                    placeholder={field.placeholder}
                                  />
                                )}
                                {field.hint && (
                                  <p className="mt-1 text-xs text-muted">{field.hint}</p>
                                )}
                              </div>
                            ))}

                            {(protocolConfigFields[detailApp.protocol] || []).length === 0 && (
                              <p className="py-10 text-center text-sm text-faint">
                                {t('apps.detail.protocol.emptyConfig')}
                              </p>
                            )}

                            {(protocolConfigFields[detailApp.protocol] || []).length > 0 && (
                              <div className="flex justify-end pt-2">
                                <Button type="submit" loading={savingProtocol}>
                                  {t('apps.detail.protocol.saveConfig')}
                                </Button>
                              </div>
                            )}
                          </form>
                        )}

                        {/* Form-fill shared service account (credential_mode=shared).
                            Lives outside protocol_config (step-up-gated secret), so
                            it's its own panel below the descriptor form. */}
                        {detailApp.protocol === 'form' && (
                          <SharedCredentialPanel
                            appId={String(detailApp.id)}
                            mode={(protocolConfig['credential_mode'] as string) || 'per_user'}
                          />
                        )}
                      </>
                    )}

                    {/* ---- Credentials tab ---- */}
                    {/*
                      Protocol-specific credential rendering. Showing OIDC
                      client_id / client_secret / discovery / JWKS on a SAML or
                      CAS app is misleading — SPs there don't use those.
                      Industry-standard (Okta / Keycloak / Auth0) split:
                        OIDC → client creds + discovery + JWKS
                        SAML → IdP entity + metadata XML + SSO/SLO + signing cert
                        CAS  → CAS server URL + validate URL
                    */}
                    {detailTab === 'credentials' && (
                      <CredentialsTab app={detailApp} onRotateSecret={() => setRotateApp(detailApp)} />
                    )}

                    {/* ---- Access policy tab ---- */}
                    {detailTab === 'access' && detailApp && (
                      <AccessPolicyTab owner="app" ownerId={String(detailApp.id)} />
                    )}

                    {/* ---- App roles tab ---- */}
                    {detailTab === 'roles' && detailApp && (
                      <AppRolesTab owner="app" ownerId={String(detailApp.id)} />
                    )}

                    {detailTab === 'provisioning' && detailApp && (
                      <ProvisioningTab appId={String(detailApp.id)} />
                    )}
                  </>
                )}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* One-time Client Secret reveal — shown immediately after create / rotate */}
      <AnimatePresence>
        {revealedSecret && (
          <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 px-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg rounded-xl bg-surface p-6 shadow-2xl"
            >
              <h3 className="mb-2 text-lg font-semibold text-ink">{t('apps.secretReveal.title')}</h3>
              <p className="mb-4 text-sm text-muted">
                {t('apps.secretReveal.desc')}
              </p>

              <div className="space-y-4">
                <CopyField label={t('apps.detail.credentials.clientId')} value={revealedSecret.clientId} />
                <SecretField label={t('apps.detail.credentials.clientSecret')} value={revealedSecret.clientSecret} />
              </div>

              <div className="mt-6 flex justify-end">
                <Button type="button" onClick={() => setRevealedSecret(null)}>
                  {t('apps.secretReveal.acknowledge')}
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <ConfirmDialog
        open={!!delApp}
        title={t('apps.list.confirmDelete', { name: delApp?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingApp}
        onConfirm={confirmDeleteApp}
        onCancel={() => setDelApp(null)}
      />
      <ConfirmDialog
        open={!!rotateApp}
        title={t('apps.detail.credentials.confirmRotate', { name: rotateApp?.name ?? '' })}
        loading={rotating}
        onConfirm={confirmRotateSecret}
        onCancel={() => setRotateApp(null)}
      />
    </motion.div>
  )
}

// ---------------------------------------------------------------------------
// CredentialsTab — protocol-aware "what the SP needs from us" panel.
// Mirrors the Keycloak "Keys / Credentials / Installation" layout.
// ---------------------------------------------------------------------------

function CredentialsTab({
  app,
  onRotateSecret,
}: {
  app: App
  onRotateSecret: () => void
}) {
  const { t } = useTranslation()
  const origin = typeof window !== 'undefined' ? window.location.origin : ''

  if (app.protocol === 'oidc') {
    return (
      <div className="space-y-6">
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
          <p className="text-sm text-amber-700">{t('apps.detail.credentials.warning')}</p>
        </div>
        <CopyField label={t('apps.detail.credentials.clientId')} value={app.client_id || '—'} />
        <div>
          <label className="mb-1 block text-sm font-medium text-ink">{t('apps.detail.credentials.clientSecret')}</label>
          <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted">
            <span className="flex-1 font-mono">{t('apps.detail.credentials.masked')}</span>
            {(app.client_type === 'web_app' || app.client_type === 'm2m') && (
              <button
                type="button"
                onClick={onRotateSecret}
                className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:bg-surface-muted"
              >
                {t('apps.detail.credentials.rotate')}
              </button>
            )}
          </div>
          {(app.client_type === 'spa' || app.client_type === 'native') && (
            <p className="mt-1 text-xs text-faint">
              {t('apps.detail.credentials.publicClientHint', { clientType: app.client_type })}
            </p>
          )}
        </div>
        <CopyField label={t('apps.detail.credentials.discovery')} value={`${origin}/protocol/oidc/.well-known/openid-configuration`} />
        <CopyField label={t('apps.detail.credentials.jwks')} value={`${origin}/protocol/oidc/jwks`} />
      </div>
    )
  }

  if (app.protocol === 'saml') {
    const metadataURL = `${origin}/protocol/saml/${app.code}/metadata`
    const ssoURL = `${origin}/protocol/saml/${app.code}/sso`
    const sloURL = `${origin}/protocol/saml/${app.code}/slo`
    return (
      <div className="space-y-6">
        <CopyField label={t('apps.detail.credentials.saml.entityID')} value={origin} />
        <div>
          <label className="mb-1 block text-sm font-medium text-ink">
            {t('apps.detail.credentials.saml.metadataURL')}
          </label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={metadataURL}
              className="flex-1 rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted"
            />
            <button
              type="button"
              onClick={() => copyToClipboard(metadataURL)}
              className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-muted"
            >
              <Copy className="h-3.5 w-3.5" />
              {t('common.copy')}
            </button>
            <a
              href={metadataURL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-muted"
            >
              {t('apps.detail.credentials.saml.openMetadata')}
            </a>
            <a
              href={metadataURL}
              download={`${app.code}-idp-metadata.xml`}
              className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-muted"
            >
              {t('apps.detail.credentials.saml.downloadMetadata')}
            </a>
          </div>
          <p className="mt-1 text-xs text-muted">
            {t('apps.detail.credentials.saml.metadataHint')}
          </p>
        </div>
        <CopyField label={t('apps.detail.credentials.saml.ssoURL')} value={ssoURL} />
        <CopyField label={t('apps.detail.credentials.saml.sloURL')} value={sloURL} />
        <SAMLCertView appId={app.id} />
      </div>
    )
  }

  if (app.protocol === 'cas') {
    const baseURL = `${origin}/protocol/cas/${app.code}`
    return (
      <div className="space-y-6">
        <CopyField label={t('apps.detail.credentials.cas.serverURL')} value={baseURL} />
        <CopyField label={t('apps.detail.credentials.cas.loginURL')} value={`${baseURL}/login`} />
        <CopyField label={t('apps.detail.credentials.cas.logoutURL')} value={`${baseURL}/logout`} />
        <CopyField label={t('apps.detail.credentials.cas.validateURL')} value={`${baseURL}/serviceValidate`} />
        <CopyField label={t('apps.detail.credentials.cas.p3ValidateURL')} value={`${baseURL}/p3/serviceValidate`} />
        <p className="text-xs text-muted">{t('apps.detail.credentials.cas.hint')}</p>
      </div>
    )
  }

  return (
    <p className="py-10 text-center text-sm text-faint">
      {t('apps.detail.credentials.noneForProtocol')}
    </p>
  )
}

// SAMLCertView fetches and displays the active signing cert PEM. Two
// affordances: copy base64 (for fields that want the raw blob) and
// download .pem (for fields that want a file).
function SAMLCertView({ appId }: { appId: string }) {
  const { t } = useTranslation()
  const [pem, setPem] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')
    appApi
      .listCerts(appId)
      .then((certs) => {
        if (cancelled) return
        const active = certs[0]
        setPem(active?.public_key || '')
      })
      .catch((e: unknown) => {
        if (cancelled) return
        const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
        setError(msg || String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [appId])

  const rawBase64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')

  const downloadPEM = () => {
    const blob = new Blob([pem], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mxid-idp-signing.pem`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-ink">
        {t('apps.detail.credentials.saml.signingCert')}
      </label>
      {loading && <p className="text-xs text-faint">{t('common.loading')}</p>}
      {error && <p className="text-xs text-red-500">{error}</p>}
      {!loading && !error && pem && (
        <>
          <textarea
            readOnly
            value={pem}
            rows={5}
            className="w-full rounded-lg border border-border bg-surface-muted px-3 py-2 font-mono text-xs text-ink"
          />
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => copyToClipboard(pem)}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-muted hover:bg-surface-muted"
            >
              <Copy className="h-3.5 w-3.5" />
              {t('apps.detail.credentials.saml.copyPEM')}
            </button>
            <button
              type="button"
              onClick={() => copyToClipboard(rawBase64)}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-muted hover:bg-surface-muted"
            >
              <Copy className="h-3.5 w-3.5" />
              {t('apps.detail.credentials.saml.copyBase64')}
            </button>
            <button
              type="button"
              onClick={downloadPEM}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-muted hover:bg-surface-muted"
            >
              {t('apps.detail.credentials.saml.downloadPEM')}
            </button>
          </div>
          <p className="mt-1 text-xs text-muted">
            {t('apps.detail.credentials.saml.signingCertHint')}
          </p>
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// SamlMetadataImport — one-shot SP metadata XML importer (paste / file /
// URL). Keycloak / Auth0 / Okta all ship this exact UX so operators don't
// have to copy 4 fields by hand. Backend parses + patches protocol_config,
// echoes the result so the form refreshes without a separate GET.
// ---------------------------------------------------------------------------

function SamlMetadataImport({
  appId,
  onImported,
}: {
  appId: string
  onImported: (cfg: Record<string, unknown>) => void
}) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<'paste' | 'file' | 'url'>('paste')
  const [xmlText, setXmlText] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (xml: string) => {
    setBusy(true)
    try {
      const cfg = await appApi.importSAMLMetadata(appId, xml)
      onImported(cfg)
      toast.success(t('apps.detail.protocol.samlImport.success'))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('apps.detail.protocol.samlImport.failed'), msg)
    } finally {
      setBusy(false)
    }
  }

  const onPaste = async () => {
    if (!xmlText.trim()) return
    await submit(xmlText)
  }

  const onFile = async (file: File) => {
    if (file.size > 256 * 1024) {
      toast.error(t('apps.detail.protocol.samlImport.failed'), '>256KB')
      return
    }
    const txt = await file.text()
    await submit(txt)
  }

  const onUrl = async () => {
    const u = urlInput.trim()
    if (!u) return
    try {
      const resp = await fetch(u, { credentials: 'omit' })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const txt = await resp.text()
      await submit(txt)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      toast.error(t('apps.detail.protocol.samlImport.failed'), msg)
    }
  }

  return (
    <div className="rounded-lg border border-dashed border-blue-200 bg-blue-50/40 p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-ink">
          {t('apps.detail.protocol.samlImport.title')}
        </p>
        <div className="inline-flex rounded-md border border-border bg-surface text-xs">
          {(['paste', 'file', 'url'] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={cn(
                'px-3 py-1.5 transition',
                mode === m ? 'bg-primary text-white' : 'text-muted hover:bg-surface-muted',
              )}
            >
              {t(`apps.detail.protocol.samlImport.mode.${m}`)}
            </button>
          ))}
        </div>
      </div>

      <p className="mb-3 text-xs text-muted">
        {t('apps.detail.protocol.samlImport.hint')}
      </p>

      {mode === 'paste' && (
        <div className="space-y-2">
          <textarea
            value={xmlText}
            onChange={(e) => setXmlText(e.target.value)}
            rows={4}
            placeholder="<EntityDescriptor entityID=&quot;...&quot;>...</EntityDescriptor>"
            className={inputCls}
          />
          <div className="flex justify-end">
            <Button type="button" size="md" onClick={onPaste} loading={busy} disabled={busy || !xmlText.trim()}>
              {t('apps.detail.protocol.samlImport.parseAndFill')}
            </Button>
          </div>
        </div>
      )}

      {mode === 'file' && (
        <div className="flex items-center gap-2">
          <input
            type="file"
            accept=".xml,application/xml,text/xml"
            disabled={busy}
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) onFile(f)
            }}
            className="text-xs"
          />
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin text-faint" />}
        </div>
      )}

      {mode === 'url' && (
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="https://sp.example.com/saml/metadata"
            className={inputCls}
          />
          <Button type="button" size="md" className="shrink-0" onClick={onUrl} loading={busy} disabled={busy || !urlInput.trim()}>
            {t('apps.detail.protocol.samlImport.fetchAndFill')}
          </Button>
        </div>
      )}
    </div>
  )
}
