// Console "我的账户" page — admin self-service surface mirrors the
// portal /security but with admin-flavored tweaks:
//
//   - red banner urging TOTP enrollment when missing (admins are high-value)
//   - the user's current session is badged + un-kickable
//   - change-password warns that ALL other sessions (portal too) are killed
//
// Backend reuses the portal security handler under the console namespace
// (cmd/server/main.go calls portal.RegisterSecurityRoutes on the console
// group); change-password kills sessions in BOTH namespaces server-side.

import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { motion } from 'framer-motion'
import QRCode from 'qrcode'
import {
  consoleSecurityApi,
  useAuthStore,
  formatDate,
  cn,
  parseUserAgent,
  useTranslation,
  type LoginHistoryRow,
  type ConsoleUserInfo,
  type APITokenRow,
} from '@mxid/shared'
import { Button, ConfirmDialog, AvatarUpload, avatarTexts, Modal } from '../../components/ui'
import { toast } from '@mxid/shared/ui/toast'
import type { MFAInfo, SessionInfo } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  ListChecks,
  Loader2,
  Mail,
  Monitor,
  Plus,
  RefreshCw,
  Shield,
  Smartphone,
  Terminal,
  Trash2,
  User as UserIcon,
} from 'lucide-react'

export default function AccountPage() {
  // ProfileSection fetches full user via /profile now; useAuthStore was
  // only kept for username fallback before that section grew.
  useAuthStore()
  const { t } = useTranslation()
  const [mfaList, setMfaList] = useState<MFAInfo[]>([])
  const [mfaLoading, setMfaLoading] = useState(true)

  const refreshMFA = useCallback(() => {
    setMfaLoading(true)
    consoleSecurityApi
      .listMFA()
      .then(setMfaList)
      .catch(() => setMfaList([]))
      .finally(() => setMfaLoading(false))
  }, [])

  useEffect(() => {
    refreshMFA()
  }, [refreshMFA])

  const totpActive = !!mfaList.find((m) => m.type === 'totp' && m.verified)

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <PageHeader title={t('account.title')} description={t('account.subtitle')} />

      {!mfaLoading && !totpActive && (
        <div className="mb-5 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="flex-1">
            <p className="font-medium">{t('account.mfaBanner')}</p>
            <p className="mt-0.5 text-xs text-red-600/90">
              {t('account.mfaBannerDesc')}
            </p>
          </div>
        </div>
      )}

      <div className="space-y-6">
        <ProfileSection />
        <ChangePasswordSection totpActive={totpActive} />
        <MFASection
          mfaList={mfaList}
          loading={mfaLoading}
          refresh={refreshMFA}
          totpActive={totpActive}
        />
        <APITokensSection />
        <SessionsSection />
        <LoginHistorySection />
      </div>
    </motion.div>
  )
}

/* ─────────────── Profile (avatar + display name + email) ─────────────── */
function ProfileSection() {
  const { t } = useTranslation()
  const { user, setUser } = useAuthStore()
  const [profile, setProfile] = useState<ConsoleUserInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [saving, setSaving] = useState(false)
  const [sending, setSending] = useState(false)
  const [devLink, setDevLink] = useState('')
  const [uploading, setUploading] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    consoleSecurityApi
      .getProfile()
      .then((p) => {
        setProfile(p.user)
        setDisplayName(p.user.display_name)
        setEmail(p.user.email)
      })
      .catch(() => setProfile(null))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleSave = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await consoleSecurityApi.updateProfile({ display_name: displayName, email })
      toast.success(t('account.saved'))
      setEditing(false)
      setDevLink('')
      load()
    } catch (e) {
      toast.error(t('account.saveFailed'), e instanceof Error ? e.message : '')
    } finally {
      setSaving(false)
    }
  }

  const handleSendVerify = async () => {
    setSending(true)
    try {
      const r = await consoleSecurityApi.sendEmailVerification()
      if (r.smtp) {
        toast.success(t('account.verifySent'), t('account.verifySentHint'))
        setDevLink('')
      } else {
        toast.success(t('account.verifyDevMode'), t('account.verifyDevModeHint'))
        setDevLink(r.dev_link)
      }
    } catch (e) {
      toast.error(t('account.verifyFailed'), e instanceof Error ? e.message : '')
    } finally {
      setSending(false)
    }
  }

  // Persist the cropped avatar (square PNG data URL from AvatarUpload).
  const saveAvatar = async (dataURL: string) => {
    setUploading(true)
    try {
      await consoleSecurityApi.updateAvatar(dataURL)
      // Reflect the new avatar in the sidebar immediately (store drives it).
      if (user) setUser({ ...user, avatar: dataURL })
      toast.success(t('account.avatarUpdated'))
      load()
    } catch (e) {
      toast.error(t('account.fields.uploadFailed'), e instanceof Error ? e.message : '')
    } finally {
      setUploading(false)
    }
  }

  return (
    <SectionCard
      icon={UserIcon}
      title={t('account.profileSection')}
      action={
        !editing && !loading ? (
          <button
            onClick={() => setEditing(true)}
            className="rounded-lg border border-border px-3 py-1.5 text-xs hover:bg-surface-muted"
          >
            {t('common.edit')}
          </button>
        ) : null
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('common.loading')}
        </div>
      ) : (
        <div className="flex flex-col gap-4 sm:flex-row">
          <div className="flex flex-col items-center gap-2">
            <AvatarUpload
              value={profile?.avatar}
              onChange={saveAvatar}
              disabled={uploading}
              texts={avatarTexts(t)}
              fallback={<span className="text-2xl font-medium">{profile?.display_name?.charAt(0) || profile?.username?.charAt(0) || 'U'}</span>}
            />
            <p className="text-[10px] text-faint">{t('account.fields.avatarHint')}</p>
          </div>

          {editing ? (
            <form onSubmit={handleSave} className="flex-1 space-y-3">
              <Field label={t('account.fields.displayName')}>
                <input
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
              </Field>
              <Field label={t('account.fields.email')}>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
                <p className="mt-1 text-xs text-faint">{t('account.emailModified')}</p>
              </Field>
              <div className="flex gap-2">
                <Button type="submit" loading={saving}>
                  {saving ? t('common.saving') : t('common.save')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setEditing(false)
                    if (profile) {
                      setDisplayName(profile.display_name)
                      setEmail(profile.email)
                    }
                  }}
                >
                  {t('common.cancel')}
                </Button>
              </div>
            </form>
          ) : (
            <div className="flex-1 space-y-2">
              <Row label={t('account.fields.username')} value={profile?.username ?? '-'} />
              <Row label={t('account.fields.displayName')} value={profile?.display_name || '-'} />
              <div>
                <p className="text-xs text-muted">{t('account.fields.email')}</p>
                <div className="flex items-center gap-2">
                  <p className="text-sm text-ink">{profile?.email || <span className="text-faint">{t('account.fields.emailUnset')}</span>}</p>
                  {profile?.email && (
                    <span
                      className={cn(
                        'rounded-full px-2 py-0.5 text-[10px] font-medium',
                        profile.email_verified
                          ? 'bg-emerald-50 text-emerald-600'
                          : 'bg-amber-50 text-amber-700',
                      )}
                    >
                      {profile.email_verified ? t('account.fields.verified') : t('account.fields.unverified')}
                    </span>
                  )}
                  {profile?.email && !profile.email_verified && (
                    <button
                      onClick={handleSendVerify}
                      disabled={sending}
                      className="ml-auto flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs hover:bg-surface-muted disabled:opacity-50"
                    >
                      {sending && <Loader2 className="h-3 w-3 animate-spin" />}
                      <Mail className="h-3 w-3" /> {t('account.fields.sendVerify')}
                    </button>
                  )}
                </div>
                {devLink && (
                  <div className="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    <p className="font-medium">{t('account.devEmailLinkTitle')}</p>
                    <a href={devLink} className="break-all text-amber-900 underline" target="_blank" rel="noreferrer noopener">
                      {devLink}
                    </a>
                  </div>
                )}
              </div>
              <Row label={t('account.fields.lastLogin')} value={profile?.last_login_at ? formatDate(profile.last_login_at) : '-'} />
            </div>
          )}
        </div>
      )}
    </SectionCard>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1 text-xs text-muted">{label}</p>
      {children}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted">{label}</p>
      <p className="text-sm text-ink">{value}</p>
    </div>
  )
}

/* ─────────────── Change Password ─────────────── */
function ChangePasswordSection({ totpActive }: { totpActive: boolean }) {
  const { t } = useTranslation()
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showOld, setShowOld] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [okMsg, setOkMsg] = useState('')

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setOkMsg('')
    if (newPwd !== confirmPwd) {
      setError(t('account.pwd.mismatch'))
      return
    }
    if (newPwd.length < 8) {
      setError(t('account.pwd.tooShort'))
      return
    }
    if (totpActive && totpCode.length !== 6) {
      setError(t('account.pwd.needMfa'))
      return
    }
    setSaving(true)
    try {
      await consoleSecurityApi.changePassword(oldPwd, newPwd, totpActive ? totpCode : undefined)
      setOkMsg(t('account.pwd.changed'))
      setOldPwd('')
      setNewPwd('')
      setConfirmPwd('')
      setTotpCode('')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('account.pwd.changeFailed')
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <SectionCard icon={KeyRound} title={t('account.passwordSection')}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <PasswordField
          label={t('account.pwd.old')}
          value={oldPwd}
          onChange={setOldPwd}
          show={showOld}
          onToggle={() => setShowOld(!showOld)}
          autoComplete="current-password"
        />
        <PasswordField
          label={t('account.pwd.new')}
          value={newPwd}
          onChange={setNewPwd}
          show={showNew}
          onToggle={() => setShowNew(!showNew)}
          autoComplete="new-password"
          hint={t('account.pwd.lenHint')}
        />
        <PasswordField
          label={t('account.pwd.confirm')}
          value={confirmPwd}
          onChange={setConfirmPwd}
          show={showNew}
          onToggle={() => setShowNew(!showNew)}
          autoComplete="new-password"
        />
        {totpActive && (
          <div>
            <label className="mb-1.5 block text-sm font-medium text-ink">
              {t('account.pwd.mfaCode')}
              <span className="ml-2 text-xs text-faint">{t('account.pwd.mfaCodeHint')}</span>
            </label>
            <input
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="••••••"
              className="w-full rounded-lg border border-border px-3 py-2 text-center text-lg font-mono tracking-widest outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
          </div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">
            <AlertCircle className="h-4 w-4" />
            {error}
          </div>
        )}
        {okMsg && (
          <div className="flex items-center gap-2 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
            <CheckCircle className="h-4 w-4" />
            {okMsg}
          </div>
        )}
        <div>
          <Button type="submit" loading={saving} disabled={saving || !oldPwd || !newPwd || !confirmPwd}>
            {saving ? t('account.pwd.submitting') : t('account.pwd.submit')}
          </Button>
          <p className="mt-2 text-xs text-muted">
            {t('account.pwd.footnote')}
          </p>
        </div>
      </form>
    </SectionCard>
  )
}

function PasswordField({
  label,
  value,
  onChange,
  show,
  onToggle,
  autoComplete,
  hint,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  show: boolean
  onToggle: () => void
  autoComplete: string
  hint?: string
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-ink">
        {label}
        {hint && <span className="ml-2 text-xs text-faint">{hint}</span>}
      </label>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          className="w-full rounded-lg border border-border px-3 py-2 pr-10 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
        />
        <button
          type="button"
          onClick={onToggle}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-muted"
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </div>
  )
}

/* ─────────────── MFA ─────────────── */
function MFASection({
  mfaList,
  loading,
  refresh,
  totpActive,
}: {
  mfaList: MFAInfo[]
  loading: boolean
  refresh: () => void
  totpActive: boolean
}) {
  const { t } = useTranslation()
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [backupRemaining, setBackupRemaining] = useState<number | null>(null)
  const [newBackupCodes, setNewBackupCodes] = useState<string[] | null>(null)
  const [regenerating, setRegenerating] = useState(false)

  useEffect(() => {
    if (!totpActive) {
      setBackupRemaining(null)
      return
    }
    consoleSecurityApi.countBackupCodes().then(setBackupRemaining).catch(() => setBackupRemaining(null))
  }, [totpActive, mfaList])

  const [showRegen, setShowRegen] = useState(false)
  const [showDisable, setShowDisable] = useState(false)

  const handleRegenerate = async () => {
    setShowRegen(false)
    let totpCode: string | undefined
    if (totpActive) {
      const code = window.prompt(t('account.mfa.backupNeedTotp')) ?? ''
      if (!/^\d{6}$/.test(code)) {
        toast.error(t('account.mfa.backupNeedDigits'))
        return
      }
      totpCode = code
    }
    setRegenerating(true)
    try {
      const codes = await consoleSecurityApi.regenerateBackupCodes(totpCode)
      setNewBackupCodes(codes)
      const n = await consoleSecurityApi.countBackupCodes().catch(() => codes.length)
      setBackupRemaining(n)
      toast.success(t('account.mfa.backupGenerated'), t('account.mfa.backupGenerateHint'))
    } catch (e) {
      toast.error(t('account.mfa.backupGenerateFailed'), e instanceof Error ? e.message : '')
    } finally {
      setRegenerating(false)
    }
  }

  const handleDisable = async () => {
    setShowDisable(false)
    try {
      await consoleSecurityApi.deleteTOTP()
      toast.success(t('account.mfa.disabled'))
      refresh()
    } catch (err) {
      toast.error(t('account.mfa.disableFailed'), err instanceof Error ? err.message : '')
    }
  }

  return (
    <SectionCard
      icon={Shield}
      title={t('account.mfaSection')}
      action={
        !totpActive ? (
          <button
            onClick={() => setEnrollOpen(true)}
            className="rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover"
          >
            {t('account.mfa.enableTotp')}
          </button>
        ) : null
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('common.loading')}
        </div>
      ) : mfaList.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border bg-surface-muted/50 px-4 py-6 text-sm text-muted">
          {t('account.mfa.noFactor')}
        </div>
      ) : (
        <div className="space-y-3">
          {mfaList.map((mfa) => (
            <div
              key={mfa.type}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Smartphone className="h-5 w-5 text-primary" />
                <div>
                  <p className="text-sm font-medium text-ink">
                    {mfa.type === 'totp' ? t('account.mfa.type.totp') : mfa.type.toUpperCase()}
                  </p>
                  <p className="text-xs text-muted">
                    {mfa.is_default ? t('account.mfa.defaultMethod') : t('account.mfa.backupMethod')}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    'rounded-full px-2.5 py-0.5 text-xs font-medium',
                    mfa.verified ? 'bg-emerald-50 text-emerald-600' : 'bg-amber-50 text-amber-600',
                  )}
                >
                  {mfa.verified ? t('account.fields.verified') : t('account.fields.unverified')}
                </span>
                {mfa.type === 'totp' && mfa.verified && (
                  <button
                    onClick={() => setShowDisable(true)}
                    className="flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-red-600 transition-colors hover:bg-red-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> {t('account.mfa.disable')}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {/* Backup codes — only relevant when TOTP is active */}
      {totpActive && (
        <div className="mt-4 rounded-lg border border-border bg-surface-muted/60 px-4 py-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-ink">{t('account.mfa.backupTitle')}</p>
              <p className="mt-0.5 text-xs text-muted">
                {t('account.mfa.backupHint')}{' '}
                <span
                  className={cn(
                    'font-semibold',
                    backupRemaining !== null && backupRemaining <= 3 ? 'text-red-600' : 'text-ink',
                  )}
                >
                  {backupRemaining === null ? '…' : backupRemaining}
                </span>
                。
              </p>
            </div>
            <button
              onClick={() => setShowRegen(true)}
              disabled={regenerating}
              className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-medium hover:bg-surface-muted disabled:opacity-50"
            >
              {regenerating ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
              {backupRemaining && backupRemaining > 0 ? t('account.mfa.backupRegen') : t('account.mfa.backupGen')}
            </button>
          </div>
        </div>
      )}

      {newBackupCodes && (
        <BackupCodesModal codes={newBackupCodes} onClose={() => setNewBackupCodes(null)} />
      )}

      {enrollOpen && (
        <EnrollTOTPModal
          onClose={() => setEnrollOpen(false)}
          onSuccess={() => {
            setEnrollOpen(false)
            refresh()
          }}
        />
      )}

      <ConfirmDialog
        open={showRegen}
        title={t('account.mfa.backupRegenConfirm')}
        loading={regenerating}
        onConfirm={handleRegenerate}
        onCancel={() => setShowRegen(false)}
      />
      <ConfirmDialog
        open={showDisable}
        title={t('account.mfa.disableConfirm')}
        onConfirm={handleDisable}
        onCancel={() => setShowDisable(false)}
      />
    </SectionCard>
  )
}

/* ─────────────── Backup codes (one-shot plaintext) ─────────────── */
function BackupCodesModal({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const { t } = useTranslation()
  const blob = useMemo(() => {
    const text =
      '# MXID Backup Recovery Codes\n' +
      t('account.mfa.backupFileOneShot') + '\n' +
      t('account.mfa.backupFileGenAt', { at: new Date().toLocaleString() }) + '\n\n' +
      codes.join('\n') +
      '\n'
    return URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  }, [codes])

  const copy = () => {
    navigator.clipboard
      .writeText(codes.join('\n'))
      .then(() => toast.success(t('account.mfa.backupCopiedAll')))
      .catch(() => toast.error(t('account.mfa.copyFail')))
  }

  return (
    <Modal open title={t('account.mfa.backupSaveTitle')} onClose={onClose}>
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <p>
            <strong>{t('account.mfa.backupSaveWarnTitle')}</strong>{t('account.mfa.backupSaveWarnBody')}
          </p>
        </div>
        <ul className="mb-3 grid grid-cols-2 gap-2">
          {codes.map((c) => (
            <li key={c} className="rounded-lg border border-border bg-surface-muted px-3 py-2 text-center font-mono text-sm text-ink">
              {c}
            </li>
          ))}
        </ul>
        <div className="flex gap-2">
          <a
            download="mxid-backup-codes.txt"
            href={blob}
            className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-center text-xs font-medium text-ink hover:bg-surface-muted"
          >
            {t('account.mfa.backupDownload')}
          </a>
          <button
            onClick={copy}
            className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-ink hover:bg-surface-muted"
          >
            {t('account.mfa.backupCopyAll')}
          </button>
          <button onClick={onClose} className="flex-1 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary-hover">
            {t('account.mfa.backupConfirmSaved')}
          </button>
        </div>
    </Modal>
  )
}

function EnrollTOTPModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const { t } = useTranslation()
  const [secret, setSecret] = useState('')
  const [qrDataURL, setQrDataURL] = useState('')
  const [qrUrl, setQrUrl] = useState('')
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    consoleSecurityApi
      .setupTOTP()
      .then(async ({ secret, qr_url }) => {
        if (!alive) return
        setSecret(secret)
        setQrUrl(qr_url)
        try {
          const png = await QRCode.toDataURL(qr_url, { width: 220, margin: 1 })
          if (alive) setQrDataURL(png)
        } catch {
          /* render failure → fall back to manual entry */
        }
      })
      .catch((e: Error) => alive && setErr(e.message || t('common.failed')))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (code.length !== 6) return
    setVerifying(true)
    try {
      await consoleSecurityApi.verifyTOTP(code)
      toast.success(t('account.mfa.enabled'), t('account.mfa.enabledHint'))
      onSuccess()
    } catch (e) {
      toast.error(t('login.invalidCaptcha'), e instanceof Error ? e.message : '')
    } finally {
      setVerifying(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard
      .writeText(secret)
      .then(() => toast.success(t('account.mfa.copySuccess'), t('account.mfa.copyHint')))
      .catch(() => toast.error(t('account.mfa.copyFail')))
  }

  return (
    <Modal open title={t('account.mfa.enrollTitle')} onClose={onClose}>
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        ) : err ? (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{err}</p>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-muted">
              {t('account.mfa.enrollHint')}
            </p>
            <div className="flex justify-center rounded-xl border border-border bg-surface-muted p-3">
              {qrDataURL ? (
                <img src={qrDataURL} alt="TOTP QR" className="h-44 w-44" />
              ) : (
                <a
                  href={qrUrl}
                  className="break-all text-xs text-primary underline"
                  target="_blank"
                  rel="noreferrer noopener"
                >
                  {qrUrl}
                </a>
              )}
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted">{t('account.mfa.secretLabel')}</label>
              <div className="flex items-center gap-2">
                <input
                  readOnly
                  value={secret}
                  className="flex-1 rounded-lg border border-border bg-surface-muted px-3 py-2 font-mono text-xs text-ink"
                />
                <button
                  type="button"
                  onClick={copySecret}
                  className="rounded-lg border border-border px-3 py-2 text-xs hover:bg-surface-muted"
                  title={t('account.mfa.copyTitle')}
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted">{t('account.mfa.verifyCode')}</label>
              <input
                autoFocus
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full rounded-lg border border-border px-3 py-2 text-center text-lg font-mono tracking-widest text-ink outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                placeholder="••••••"
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="secondary" onClick={onClose}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" loading={verifying} disabled={code.length !== 6 || verifying}>
                {t('account.mfa.submit')}
              </Button>
            </div>
          </form>
        )}
    </Modal>
  )
}

/* ─────────────── Sessions ─────────────── */
function SessionsSection() {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revoking, setRevoking] = useState<string | null>(null)
  const [currentSID, setCurrentSID] = useState<string>('')
  const [delSid, setDelSid] = useState<string | null>(null)

  const fetchAll = useCallback(() => {
    setLoading(true)
    consoleSecurityApi
      .listSessions()
      .then((list) => {
        setSessions(list)
        setError('')
        // The "current" session is the one with the most recent last_active
        // — every list call comes through auth middleware which Touched it
        // right before this handler executed.
        if (list.length > 0) {
          const latest = [...list].sort(
            (a, b) => new Date(b.last_active_at).getTime() - new Date(a.last_active_at).getTime(),
          )[0]
          setCurrentSID(latest.id)
        }
      })
      .catch((e: Error) => setError(e.message || t('account.sessions.loadError')))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchAll()
  }, [fetchAll])

  const confirmRevoke = async () => {
    const sid = delSid
    if (!sid || sid === currentSID) return
    setRevoking(sid)
    try {
      await consoleSecurityApi.deleteSession(sid)
      setDelSid(null)
      toast.success(t('account.sessions.kicked'))
      fetchAll()
    } catch (e) {
      toast.error(t('account.sessions.kickFailed'), e instanceof Error ? e.message : '')
    } finally {
      setRevoking(null)
    }
  }

  return (
    <SectionCard icon={Monitor} title={t('account.sessionsSection')} description={t('account.sessionsHint')}>
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : sessions.length === 0 ? (
        <p className="py-4 text-sm text-muted">{t('account.sessions.empty')}</p>
      ) : (
        <div className="space-y-3">
          {[...sessions]
            .sort((a, b) => new Date(b.last_active_at).getTime() - new Date(a.last_active_at).getTime())
            .map((s) => {
              const isCurrent = s.id === currentSID
              const ua = parseUserAgent(s.user_agent)
              return (
                <div
                  key={s.id}
                  className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <Monitor className="h-5 w-5 shrink-0 text-faint" />
                    <div className="min-w-0">
                      <p className="flex items-center gap-2 truncate text-sm font-medium text-ink">
                        {ua.short}
                        {isCurrent && (
                          <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-medium text-blue-600">
                            {t('account.sessions.currentBadge')}
                          </span>
                        )}
                      </p>
                      <p className="truncate text-xs text-muted">
                        {t('account.sessions.ipLabel')}: {s.ip || t('account.sessions.unknown')} · {t('account.sessions.lastActiveLabel')}: {formatDate(s.last_active_at)}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setDelSid(s.id)}
                    disabled={isCurrent || revoking === s.id}
                    title={isCurrent ? t('account.sessions.cantKickSelf') : t('account.sessions.kickTitle')}
                    className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
                  >
                    {revoking === s.id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="h-3.5 w-3.5" />
                    )}
                    {t('account.sessions.kick')}
                  </button>
                </div>
              )
            })}
        </div>
      )}

      <ConfirmDialog
        open={!!delSid}
        title={t('account.sessions.kickConfirm')}
        loading={revoking === delSid}
        onConfirm={confirmRevoke}
        onCancel={() => setDelSid(null)}
      />
    </SectionCard>
  )
}

/* ─────────────── Login history ─────────────── */
function LoginHistorySection() {
  const { t } = useTranslation()
  const [rows, setRows] = useState<LoginHistoryRow[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    consoleSecurityApi
      .listLoginHistory(50)
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false))
  }, [])

  return (
    <SectionCard
      icon={ListChecks}
      title={t('account.historySection')}
      description={t('account.historyHint')}
    >
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('common.loading')}
        </div>
      ) : rows.length === 0 ? (
        <p className="py-4 text-sm text-muted">{t('account.history.empty')}</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="min-w-full text-xs">
            <thead className="bg-surface-muted text-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">{t('account.history.time')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.history.event')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.history.ip')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.history.device')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.history.detail')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((r, i) => {
                const ua = parseUserAgent(r.user_agent)
                const evLabel: Record<string, string> = {
                  'login.success': t('account.history.events.success'),
                  'login.failed': t('account.history.events.failed'),
                  logout: t('account.history.events.logout'),
                }
                return (
                  <tr key={i} className={cn(!r.success && 'bg-red-50/40')}>
                    <td className="whitespace-nowrap px-3 py-2 text-ink">{formatDate(r.created_at)}</td>
                    <td className="px-3 py-2">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-medium',
                          r.event_type === 'login.success' && 'bg-emerald-50 text-emerald-700',
                          r.event_type === 'login.failed' && 'bg-red-50 text-red-700',
                          r.event_type === 'logout' && 'bg-surface-muted text-muted',
                        )}
                      >
                        {evLabel[r.event_type] ?? r.event_type}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-ink">{r.ip || '-'}</td>
                    <td className="px-3 py-2 text-ink">{ua.short}</td>
                    <td className="px-3 py-2 text-muted">{r.reason || '-'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  )
}

/* ─────────────── API Tokens ─────────────── */
function APITokensSection() {
  const { t } = useTranslation()
  const [tokens, setTokens] = useState<APITokenRow[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [newPlaintext, setNewPlaintext] = useState<{ name: string; token: string } | null>(null)
  const [delTok, setDelTok] = useState<APITokenRow | null>(null)
  const [revokingTok, setRevokingTok] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    consoleSecurityApi
      .listAPITokens()
      .then(setTokens)
      .catch(() => setTokens([]))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleCreate = async (name: string, scopes: string[], days: number) => {
    setCreating(true)
    try {
      const tok = await consoleSecurityApi.createAPIToken({ name, scopes, expires_in_days: days })
      if (tok.plaintext) setNewPlaintext({ name: tok.name, token: tok.plaintext })
      setCreateOpen(false)
      load()
    } catch (e) {
      toast.error(t('account.apiTokens.createFailed'), e instanceof Error ? e.message : '')
    } finally {
      setCreating(false)
    }
  }

  const confirmRevoke = async () => {
    const tok = delTok
    if (!tok) return
    setRevokingTok(true)
    try {
      await consoleSecurityApi.revokeAPIToken(tok.id)
      setDelTok(null)
      toast.success(t('account.apiTokens.revokeOk'))
      load()
    } catch (e) {
      toast.error(t('account.apiTokens.revokeFailed'), e instanceof Error ? e.message : '')
    } finally {
      setRevokingTok(false)
    }
  }

  return (
    <SectionCard
      icon={Terminal}
      title={t('account.apiTokenSection')}
      description={t('account.apiTokenHint')}
      action={
        <button
          onClick={() => setCreateOpen(true)}
          className="inline-flex items-center gap-1 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover"
        >
          <Plus className="h-3 w-3" /> {t('account.apiTokens.newToken')}
        </button>
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('common.loading')}
        </div>
      ) : tokens.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border bg-surface-muted/50 px-4 py-6 text-center text-sm text-muted">
          {t('account.apiTokens.empty')}
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="min-w-full text-xs">
            <thead className="bg-surface-muted text-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.name')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.prefix')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.scopes')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.expires')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.lastUsed')}</th>
                <th className="px-3 py-2 text-left font-medium">{t('account.apiTokens.cols.status')}</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {tokens.map((tok) => (
                <tr key={tok.id} className={cn(tok.revoked_at && 'text-faint')}>
                  <td className="px-3 py-2 font-medium">{tok.name}</td>
                  <td className="px-3 py-2 font-mono text-ink">mxidpat_{tok.prefix}…</td>
                  <td className="px-3 py-2">
                    {tok.scopes.length === 0 ? (
                      <span className="text-faint">{t('account.apiTokens.noScope')}</span>
                    ) : (
                      <span className="break-all">{tok.scopes.join(', ')}</span>
                    )}
                  </td>
                  <td className="px-3 py-2">{tok.expires_at ? formatDate(tok.expires_at) : t('account.apiTokens.forever')}</td>
                  <td className="px-3 py-2">{tok.last_used_at ? formatDate(tok.last_used_at) : '-'}</td>
                  <td className="px-3 py-2">
                    {tok.revoked_at ? (
                      <span className="rounded-full bg-surface-muted px-2 py-0.5 text-muted">{t('common.revoked')}</span>
                    ) : tok.expires_at && new Date(tok.expires_at) < new Date() ? (
                      <span className="rounded-full bg-amber-50 px-2 py-0.5 text-amber-700">{t('common.expired')}</span>
                    ) : (
                      <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-emerald-700">{t('common.valid')}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {!tok.revoked_at && (
                      <button
                        onClick={() => setDelTok(tok)}
                        className="rounded-lg px-2 py-1 text-red-600 hover:bg-red-50"
                        title={t('account.apiTokens.cols.status')}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <CreateAPITokenModal
          onClose={() => setCreateOpen(false)}
          onSubmit={handleCreate}
          submitting={creating}
        />
      )}

      {newPlaintext && (
        <NewTokenModal
          name={newPlaintext.name}
          token={newPlaintext.token}
          onClose={() => setNewPlaintext(null)}
        />
      )}

      <ConfirmDialog
        open={!!delTok}
        title={t('account.apiTokens.revokeConfirm', { name: delTok?.name ?? '' })}
        loading={revokingTok}
        onConfirm={confirmRevoke}
        onCancel={() => setDelTok(null)}
      />
    </SectionCard>
  )
}

function CreateAPITokenModal({
  onClose,
  onSubmit,
  submitting,
}: {
  onClose: () => void
  onSubmit: (name: string, scopes: string[], days: number) => void
  submitting: boolean
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [scopesText, setScopesText] = useState('*')
  const [days, setDays] = useState(90)

  const handle = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    const scopes = scopesText
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    onSubmit(name.trim(), scopes, days)
  }

  return (
    <Modal open title={t('account.apiTokens.newToken')} onClose={onClose}>
        <form onSubmit={handle} className="space-y-3">
          <Field label={t('account.apiTokens.formName')}>
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('account.apiTokens.formNamePlaceholder')}
              className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
          </Field>
          <Field label={t('account.apiTokens.formScopes')}>
            <input
              value={scopesText}
              onChange={(e) => setScopesText(e.target.value)}
              placeholder={t('account.apiTokens.formScopesPlaceholder')}
              className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <p className="mt-1 text-xs text-faint">{t('account.apiTokens.formScopesHint')}</p>
          </Field>
          <Field label={t('account.apiTokens.formExpires')}>
            <input
              type="number"
              min={0}
              max={730}
              value={days}
              onChange={(e) => setDays(Number(e.target.value) || 0)}
              className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <p className="mt-1 text-xs text-faint">{t('account.apiTokens.formExpiresHint')}</p>
          </Field>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="secondary" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={submitting} disabled={submitting || !name.trim()}>
              {t('common.create')}
            </Button>
          </div>
        </form>
    </Modal>
  )
}

function NewTokenModal({ name, token, onClose }: { name: string; token: string; onClose: () => void }) {
  const { t } = useTranslation()
  const copy = () => {
    navigator.clipboard
      .writeText(token)
      .then(() => toast.success(t('account.mfa.copySuccess')))
      .catch(() => toast.error(t('account.mfa.copyFail')))
  }
  return (
    <Modal open title={t('account.apiTokens.created')} onClose={onClose}>
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <p>
            <strong>{t('account.apiTokens.createWarnTitle')}</strong>{t('account.apiTokens.createWarnBody')}
          </p>
        </div>
        <p className="mb-2 text-xs text-muted">{name}</p>
        <div className="mb-3 break-all rounded-lg border border-border bg-surface-muted px-3 py-2 font-mono text-xs text-ink">
          {token}
        </div>
        <div className="flex gap-2">
          <button
            onClick={copy}
            className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-ink hover:bg-surface-muted"
          >
            <Copy className="mr-1 inline h-3 w-3" /> {t('common.copy')}
          </button>
          <button
            onClick={onClose}
            className="flex-1 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary-hover"
          >
            {t('account.apiTokens.saved')}
          </button>
        </div>
    </Modal>
  )
}

/* ─────────────── Section Card ─────────────── */
function SectionCard({
  icon: Icon,
  title,
  description,
  action,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  description?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-border bg-surface p-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Icon className="h-5 w-5 text-primary" />
          <h2 className="text-base font-semibold text-ink">{title}</h2>
          {description && <span className="text-xs text-faint">· {description}</span>}
        </div>
        {action}
      </div>
      {children}
    </div>
  )
}
