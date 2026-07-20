import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import i18n from 'i18next'

export * from './app-icon'
export * from './app-icon-library'
export { AppIcon } from './AppIcon'
export * from './user-agent'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// upgradeToHTTPS redirects an http:// page load to https:// before the app
// mounts. Reaching MXID over http makes the browser send `Origin: http://…`,
// which never matches the https-only CSRF allow-list → state-changing POSTs
// (login included) get a 403. Skipped for local dev (localhost) and bare-IP
// hosts, which typically have no TLS cert and would otherwise dead-loop.
export function upgradeToHTTPS(): void {
  if (typeof window === 'undefined') return
  const { protocol, hostname, href } = window.location
  if (protocol !== 'http:') return
  const isLocal =
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname.endsWith('.localhost')
  const isBareIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
  if (isLocal || isBareIPv4) return
  window.location.replace(href.replace(/^http:/, 'https:'))
}

// Module-scoped runtime overrides applied by useBootstrap once the
// admin's Localization setting loads. No setting → fall back to the
// browser locale + Asia/Shanghai. Never default-import: bootstrap may
// race the first formatDate() call, in which case the legacy fallback
// renders for one frame and the next render picks up the override.
let runtimeTimezone = ''
let runtimeDateFormat = ''
let runtimeLanguage = ''

export function setRuntimeLocalization(opts: { timezone?: string; dateFormat?: string; language?: string }) {
  if (opts.timezone !== undefined) runtimeTimezone = opts.timezone
  if (opts.dateFormat !== undefined) runtimeDateFormat = opts.dateFormat
  if (opts.language !== undefined) runtimeLanguage = opts.language
}

// formatDate renders an ISO/RFC date string for the UI. Honors the
// admin-configured timezone and (optionally) a strftime-like date_format
// pattern: YYYY/MM/DD/HH/mm/ss tokens are replaced; everything else flows
// through verbatim. Empty date_format → toLocaleString with the runtime
// timezone + language.
export function formatDate(date: string | null): string {
  if (!date) return '-'
  const d = new Date(date)
  const tz = runtimeTimezone || 'Asia/Shanghai'
  const lang = runtimeLanguage || (typeof navigator !== 'undefined' ? navigator.language : 'zh-CN')
  if (runtimeDateFormat) {
    return applyDateFormat(d, tz, runtimeDateFormat)
  }
  return d.toLocaleString(lang, { timeZone: tz })
}

function applyDateFormat(d: Date, tz: string, pattern: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).formatToParts(d).reduce<Record<string, string>>((acc, p) => {
    if (p.type !== 'literal') acc[p.type] = p.value
    return acc
  }, {})
  return pattern
    .replace(/YYYY/g, parts.year ?? '')
    .replace(/MM/g, parts.month ?? '')
    .replace(/DD/g, parts.day ?? '')
    .replace(/HH/g, parts.hour === '24' ? '00' : (parts.hour ?? ''))
    .replace(/mm/g, parts.minute ?? '')
    .replace(/ss/g, parts.second ?? '')
}

export function statusLabel(status: number): string {
  const key = {
    1: 'users.statusActive',
    2: 'users.statusLocked',
    3: 'users.statusDisabled',
    4: 'users.statusPending',
  }[status]
  return key ? i18n.t(key) : i18n.t('common.unknown')
}

export function statusColor(status: number): string {
  const map: Record<number, string> = {
    1: 'text-green-600',
    2: 'text-red-600',
    3: 'text-gray-400',
    4: 'text-yellow-600',
  }
  return map[status] || 'text-gray-500'
}

export function protocolLabel(protocol: string): string {
  const map: Record<string, string> = {
    oidc: 'OIDC',
    saml: 'SAML 2.0',
    cas: 'CAS 3.0',
    form: 'Form-fill',
  }
  return map[protocol] || protocol.toUpperCase()
}
