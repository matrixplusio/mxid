import { UAParser } from 'ua-parser-js'
import i18next from 'i18next'

// Cache parsed results — UA strings rarely vary within one session list,
// and ua-parser-js is non-trivial CPU-wise on cold parse.
const CACHE = new Map<string, ParsedUserAgent>()

export interface ParsedUserAgent {
  /** "Chrome 149 · macOS 15.2" — for one-line cards */
  short: string
  browser: string
  browserVersion: string
  os: string
  osVersion: string
  /** Best guess: "desktop" / "mobile" / "tablet" / "bot" / "unknown" */
  kind: 'desktop' | 'mobile' | 'tablet' | 'bot' | 'unknown'
}

/**
 * parseUserAgent turns a raw User-Agent string into something humans want
 * to read. Returns a stable "unknown" object for empty/garbage inputs so
 * callers don't need null checks.
 */
export function parseUserAgent(ua: string): ParsedUserAgent {
  const key = ua ?? ''
  const hit = CACHE.get(key)
  if (hit) return hit

  if (!ua) {
    const empty: ParsedUserAgent = {
      short: i18next.t('common.userAgent.unknownDevice'),
      browser: '',
      browserVersion: '',
      os: '',
      osVersion: '',
      kind: 'unknown',
    }
    CACHE.set(key, empty)
    return empty
  }

  const parser = new UAParser(ua)
  const browser = parser.getBrowser()
  const os = parser.getOS()
  const device = parser.getDevice()

  let kind: ParsedUserAgent['kind'] = 'desktop'
  if (device.type === 'mobile') kind = 'mobile'
  else if (device.type === 'tablet') kind = 'tablet'
  else if (/bot|crawler|spider/i.test(ua)) kind = 'bot'
  else if (!browser.name && !os.name) kind = 'unknown'

  const browserName = browser.name ?? i18next.t('common.userAgent.unknownBrowser')
  const browserVersion = (browser.version ?? '').split('.')[0] || ''
  const osName = os.name ?? i18next.t('common.userAgent.unknownOS')
  const osVersion = os.version ?? ''

  const short = [
    [browserName, browserVersion].filter(Boolean).join(' '),
    [osName, osVersion].filter(Boolean).join(' '),
  ]
    .filter(Boolean)
    .join(' · ')

  const out: ParsedUserAgent = {
    short: short || ua.slice(0, 32),
    browser: browserName,
    browserVersion,
    os: osName,
    osVersion,
    kind,
  }
  CACHE.set(key, out)
  return out
}
