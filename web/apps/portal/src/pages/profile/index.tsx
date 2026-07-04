import { useEffect, useState, type FormEvent } from 'react'
import { motion } from 'framer-motion'
import { portalApi, useAuthStore, formatDate, useTranslation } from '@mxid/shared'
import { Button, AvatarUpload, avatarTexts } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import { UserCircle, Save, Loader2, AlertCircle, CheckCircle } from 'lucide-react'

interface ProfileData {
  id: string
  username: string
  email: string
  email_verified: boolean
  phone: string
  display_name: string
  avatar: string
  status: number
  last_login_at: string | null
}

export default function ProfilePage() {
  const { t } = useTranslation()
  const { user, setUser } = useAuthStore()

  const [profile, setProfile] = useState<ProfileData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [displayName, setDisplayName] = useState('')
  const [phone, setPhone] = useState('')
  const [email, setEmail] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  const [sendingVerify, setSendingVerify] = useState(false)
  const [devLink, setDevLink] = useState<string | null>(null)

  const [uploading, setUploading] = useState(false)

  // Persist the cropped avatar (a square PNG data URL from AvatarUpload). The
  // avatar column stores the data URL inline.
  const saveAvatar = async (dataURL: string) => {
    setUploading(true)
    try {
      await portalApi.updateAvatar(dataURL)
      setProfile((p) => (p ? { ...p, avatar: dataURL } : p))
      // Reflect the new avatar in the nav bar immediately (store drives Navbar).
      if (user) setUser({ ...user, avatar: dataURL })
      toast.success(t('account.avatarUpdated'))
    } catch (err: unknown) {
      toast.error(t('account.fields.uploadFailed'), extractMessage(err))
    } finally {
      setUploading(false)
    }
  }

  // Pick up the click-back from /profile/email/verify?token=... — backend
  // redirects here with ?email_verified=1 on success. Show a banner and
  // refresh the profile so the badge flips to verified.
  const [verifiedBanner, setVerifiedBanner] = useState(false)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('email_verified') === '1') {
      setVerifiedBanner(true)
      // Clean the URL so a reload doesn't keep showing the banner.
      const url = new URL(window.location.href)
      url.searchParams.delete('email_verified')
      window.history.replaceState({}, '', url.toString())
    }
  }, [])

  const handleSendVerify = async () => {
    if (sendingVerify) return
    setSendingVerify(true)
    setSaveMsg(null)
    setDevLink(null)
    try {
      const resp = await portalApi.sendEmailVerification()
      setSaveMsg({ type: 'ok', text: `${t('account.verifySent')}: ${resp.email}` })
      setDevLink(resp.dev_link)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('account.verifyFailed')
      setSaveMsg({ type: 'err', text: msg })
    } finally {
      setSendingVerify(false)
    }
  }

  useEffect(() => {
    portalApi
      .getProfile()
      .then((data) => {
        const u = data.user
        setProfile(u)
        setDisplayName(u.display_name || '')
        setPhone(u.phone || '')
        setEmail(u.email || '')
      })
      .catch((err: Error) => setError(err.message || t('common.failed')))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async (e: FormEvent) => {
    e.preventDefault()
    if (saving) return
    setSaving(true)
    setSaveMsg(null)
    try {
      await portalApi.updateProfile({
        display_name: displayName.trim(),
        phone: phone.trim(),
        email: email.trim(),
      })
      setSaveMsg({ type: 'ok', text: t('account.saved') })
      // Update auth store display name
      setUser({
        ...useAuthStore.getState().user!,
        display_name: displayName.trim(),
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('account.saveFailed')
      setSaveMsg({ type: 'err', text: msg })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (error || !profile) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-32 text-muted">
        <AlertCircle className="h-10 w-10 text-red-400" />
        <p className="text-sm">{error || t('common.failed')}</p>
      </div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-ink">{t('portal.profile.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('portal.profile.basic')}</p>
      </div>

      {verifiedBanner && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          <CheckCircle className="h-4 w-4" />
          {t('common.success')}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left - User card */}
        <div className="rounded-xl border border-border bg-surface p-6">
          <div className="flex flex-col items-center text-center">
            <AvatarUpload
              value={profile.avatar}
              onChange={saveAvatar}
              disabled={uploading}
              texts={avatarTexts(t)}
              fallback={<UserCircle className="h-10 w-10 text-primary" />}
            />
            <h2 className="mt-4 text-lg font-semibold text-ink">
              {profile.display_name || profile.username}
            </h2>
            <p className="text-sm text-muted">@{profile.username}</p>

            <div className="mt-6 w-full space-y-3 text-left">
              <InfoRow label={t('account.fields.email')} value={profile.email || '-'} />
              <InfoRow label={t('users.columns.phone')} value={profile.phone || '-'} />
              <InfoRow label={t('account.fields.lastLogin')} value={formatDate(profile.last_login_at)} />
            </div>
          </div>
        </div>

        {/* Right - Edit form */}
        <div className="rounded-xl border border-border bg-surface p-6 lg:col-span-2">
          <h3 className="mb-4 text-base font-semibold text-ink">
{t('common.edit')}
          </h3>
          <form onSubmit={handleSave} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-ink">
{t('users.columns.username')}
              </label>
              <input
                type="text"
                value={profile.username}
                disabled
                className="w-full rounded-lg border border-border bg-surface-muted px-3 py-2.5 text-sm text-muted"
              />
            </div>
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <label className="block text-sm font-medium text-ink">{t('account.fields.email')}</label>
                {email && (
                  <span
                    className={
                      profile.email_verified
                        ? 'rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-700'
                        : 'rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-700'
                    }
                  >
                    {profile.email_verified ? t('account.fields.verified') : t('account.fields.unverified')}
                  </span>
                )}
              </div>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
              />
              <div className="mt-2 flex items-center justify-between gap-2">
                <p className="text-xs text-faint">
                  {t('account.emailModified')}
                </p>
                {!profile.email_verified && email && (
                  <button
                    type="button"
                    onClick={handleSendVerify}
                    disabled={sendingVerify}
                    className="shrink-0 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-100 disabled:opacity-50"
                  >
                    {sendingVerify ? t('common.loading') : t('account.fields.sendVerify')}
                  </button>
                )}
              </div>
              {devLink && (
                <div className="mt-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                  <div className="mb-1 font-medium">{t('account.devEmailLinkTitle')}</div>
                  <a
                    href={devLink}
                    target="_blank"
                    rel="noreferrer"
                    className="break-all font-mono text-amber-900 underline hover:text-amber-700"
                  >
                    {devLink}
                  </a>
                </div>
              )}
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-ink">
{t('account.fields.displayName')}
              </label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder={t('account.fields.displayName')}
                className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-ink">
{t('users.columns.phone')}
              </label>
              <input
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                placeholder={t('users.columns.phone')}
                className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
              />
            </div>

            {/* Save message */}
            {saveMsg && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                  saveMsg.type === 'ok'
                    ? 'bg-emerald-50 text-emerald-600'
                    : 'bg-red-50 text-red-600'
                }`}
              >
                {saveMsg.type === 'ok' ? (
                  <CheckCircle className="h-4 w-4" />
                ) : (
                  <AlertCircle className="h-4 w-4" />
                )}
                {saveMsg.text}
              </motion.div>
            )}

            <Button type="submit" loading={saving} icon={<Save className="h-4 w-4" />}>
              {saving ? t('common.saving') : t('common.save')}
            </Button>
          </form>
        </div>
      </div>
    </motion.div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-border pb-2 last:border-0">
      <span className="text-xs text-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  )
}
