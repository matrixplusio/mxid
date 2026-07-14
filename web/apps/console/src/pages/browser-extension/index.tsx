// Browser Extension — admin page for rolling out the "MXID Login" browser
// extension (form-fill SSO). Pure front-end: it makes no new backend call, and
// substitutes this deployment's origin (window.location.origin) into the managed
// config so the copy-paste enterprise policy snippets are correct for whatever
// domain the admin actually runs MXID on.
//
// Why an in-console page: the extension can't be installed by a user downloading
// a .crx (Chrome blocks non-store CRX). The real path is an admin force-installing
// it via managed-browser policy — so the audience is here, in the console.

import { useState, type ReactNode } from 'react'
import { Check, Copy, Download, ExternalLink } from 'lucide-react'
import { useTranslation } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

// Stable identity + hosted artifacts. The extension id is pinned by the
// manifest "key", so a self-hosted CRX keeps the same id MXID allow-lists.
const EXT_ID = 'bfdbncnhgjdbaeipacekokclgbkhlpic'
const RELEASE_BASE = 'https://github.com/imkerbos/mxid-extension/releases'
const CRX_URL = `${RELEASE_BASE}/latest/download/mxid-login.crx`
const UPDATE_URL = `${RELEASE_BASE}/latest/download/update.xml`
const FORCELIST = `${EXT_ID};${UPDATE_URL}`

function CodeBlock({ code, lang }: { code: string; lang?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="group relative overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
      {lang && (
        <div className="border-b border-gray-800 px-3 py-1 text-[10px] uppercase tracking-wider text-faint">
          {lang}
        </div>
      )}
      <button
        onClick={copy}
        className="absolute right-2 top-2 hidden items-center gap-1 rounded-md bg-gray-700 px-2 py-1 text-xs text-white opacity-0 transition-opacity hover:bg-gray-600 group-hover:flex group-hover:opacity-100"
        title={t('docs.copyTitle')}
      >
        {copied ? (
          <>
            <Check className="h-3 w-3" /> {t('docs.copied')}
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" /> {t('docs.copy')}
          </>
        )}
      </button>
      <pre className="overflow-x-auto p-3 text-[12.5px] leading-relaxed text-gray-100">
        <code>{code.trimEnd()}</code>
      </pre>
    </div>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 sm:grid-cols-[180px_1fr] sm:items-start sm:gap-4">
      <dt className="text-sm font-medium text-muted">{label}</dt>
      <dd className="min-w-0 break-all text-sm text-ink">{children}</dd>
    </div>
  )
}

export default function BrowserExtensionPage() {
  const { t } = useTranslation()
  const origin = window.location.origin

  const linuxJson = `{
  "ExtensionInstallForcelist": [
    "${FORCELIST}"
  ],
  "3rdparty": {
    "extensions": {
      "${EXT_ID}": {
        "mxidBaseUrl": "${origin}"
      }
    }
  }
}`

  const windowsReg = `reg add "HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist" ^
  /v 1 /t REG_SZ /d "${FORCELIST}"

reg add "HKLM\\Software\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${EXT_ID}\\policy" ^
  /v mxidBaseUrl /t REG_SZ /d "${origin}"`

  const macosPlist = `<key>ExtensionInstallForcelist</key>
<array>
  <string>${FORCELIST}</string>
</array>
<!-- push the MXID URL to the extension (managed config) via its own key: -->
<key>com.google.Chrome.extensions.${EXT_ID}</key>
<dict>
  <key>mxidBaseUrl</key>
  <string>${origin}</string>
</dict>`

  return (
    <div className="space-y-6">
      <PageHeader title={t('browserExtension.title')} description={t('browserExtension.subtitle')} />

      {/* Overview */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <p className="text-sm leading-relaxed text-muted">{t('browserExtension.overview')}</p>
        <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
          {t('browserExtension.manualBlocked')}
        </div>
      </div>

      {/* Details */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <h2 className="mb-4 text-sm font-semibold text-ink">{t('browserExtension.detailsTitle')}</h2>
        <dl className="space-y-3">
          <Row label={t('browserExtension.extId')}>
            <code className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-xs">{EXT_ID}</code>
          </Row>
          <Row label={t('browserExtension.updateUrl')}>
            <code className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-xs">{UPDATE_URL}</code>
          </Row>
          <Row label={t('browserExtension.mxidUrl')}>
            <code className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-xs">{origin}</code>
            <span className="ml-2 text-xs text-faint">{t('browserExtension.mxidUrlHint')}</span>
          </Row>
          <Row label={t('browserExtension.download')}>
            <div className="flex flex-wrap gap-3">
              <a
                href={CRX_URL}
                className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
              >
                <Download className="h-4 w-4" /> mxid-login.crx
              </a>
              <a
                href={RELEASE_BASE}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
              >
                <ExternalLink className="h-4 w-4" /> {t('browserExtension.allReleases')}
              </a>
            </div>
          </Row>
        </dl>
      </div>

      {/* Enterprise install */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <h2 className="text-sm font-semibold text-ink">{t('browserExtension.installTitle')}</h2>
        <p className="mt-1 text-sm text-muted">{t('browserExtension.installIntro')}</p>

        {/* Google Admin */}
        <div className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-ink">{t('browserExtension.googleAdmin')}</h3>
          <ol className="ml-5 list-decimal space-y-1 text-sm text-muted">
            <li>{t('browserExtension.ga1')}</li>
            <li>{t('browserExtension.ga2')}</li>
            <li>
              {t('browserExtension.ga3')}
              <div className="mt-1.5">
                <CodeBlock code={`Extension ID:     ${EXT_ID}\nInstallation URL: ${UPDATE_URL}`} />
              </div>
            </li>
            <li>{t('browserExtension.ga4')}</li>
            <li>{t('browserExtension.ga5', { origin })}</li>
          </ol>
        </div>

        {/* Linux */}
        <div className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-ink">{t('browserExtension.linux')}</h3>
          <p className="mb-2 text-xs text-faint">/etc/opt/chrome/policies/managed/mxid-login.json</p>
          <CodeBlock code={linuxJson} lang="json" />
        </div>

        {/* Windows */}
        <div className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-ink">{t('browserExtension.windows')}</h3>
          <CodeBlock code={windowsReg} lang="cmd" />
        </div>

        {/* macOS */}
        <div className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-ink">{t('browserExtension.macos')}</h3>
          <CodeBlock code={macosPlist} lang="xml" />
        </div>
      </div>
    </div>
  )
}
