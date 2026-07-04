import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ArrowLeft,
  KeyRound,
  Loader2,
  Lock,
  LockOpen,
  LogOut,
  Mail,
  Phone,
  ShieldCheck,
  Trash2,
  Unlink,
  User as UserIcon,
  UserX,
} from 'lucide-react'
import {
  userApi,
  groupApi,
  formatDate,
  statusColor,
  statusLabel,
  cn,
  useTranslation,
  UserStatus,
} from '@mxid/shared'
import type {
  User,
  UserDetail,
  UserMFA,
  UserIdentity,
  UserLoginRecord,
  UserSession,
  EffectiveRole,
  Group,
  PaginatedData,
} from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { useTabParam } from '../../hooks/useTabParam'
import { Field, pageMotion, Button, ConfirmDialog } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

type Tab = 'basic' | 'detail' | 'groups' | 'roles' | 'identities' | 'mfa' | 'sessions' | 'history'

const TAB_VALUES = ['basic', 'detail', 'groups', 'roles', 'identities', 'mfa', 'sessions', 'history'] as const

const TAB_KEYS: { key: Tab; i18nKey: string }[] = [
  { key: 'basic', i18nKey: 'users.detail.tabs.basic' },
  { key: 'detail', i18nKey: 'users.detail.tabs.detail' },
  { key: 'groups', i18nKey: 'users.detail.tabs.groups' },
  { key: 'roles', i18nKey: 'users.detail.tabs.roles' },
  { key: 'identities', i18nKey: 'users.detail.tabs.identities' },
  { key: 'mfa', i18nKey: 'users.detail.tabs.mfa' },
  { key: 'sessions', i18nKey: 'users.detail.tabs.sessions' },
  { key: 'history', i18nKey: 'users.detail.tabs.history' },
]

const STATUS_VALUES = [
  { value: 1, i18nKey: 'users.detail.status.active' },
  { value: 2, i18nKey: 'users.detail.status.locked' },
  { value: 3, i18nKey: 'users.detail.status.disabled' },
  { value: 4, i18nKey: 'users.detail.status.pending' },
]

const GENDER_VALUES = [
  { value: 0, i18nKey: 'users.detail.gender.unset' },
  { value: 1, i18nKey: 'users.detail.gender.male' },
  { value: 2, i18nKey: 'users.detail.gender.female' },
]

export default function UserDetailPage() {
  // Keep id as string — snowflake int64 IDs exceed JS Number safe range;
  // Number(id) would round the trailing few digits and make every API
  // call 404 against the real DB row.
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const userID = id ?? ''

  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useTabParam<Tab>('tab', 'basic', TAB_VALUES)

  const loadUser = useCallback(async () => {
    if (!userID) return
    setLoading(true)
    try {
      const u = await userApi.getById(userID)
      setUser(u)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [userID])

  useEffect(() => {
    if (userID) loadUser()
  }, [userID, loadUser])

  if (!userID || !/^\d+$/.test(userID)) {
    return <div className="p-8 text-sm text-gray-500">{t('users.detail.invalidUserId')}</div>
  }

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('users.detail.title')}
        description={user ? `${user.display_name || user.username}` : t('users.detail.loading')}
        actions={
          <button
            onClick={() => navigate('/users')}
            className="inline-flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50"
          >
            <ArrowLeft className="h-4 w-4" />
            {t('users.detail.backToList')}
          </button>
        }
      />

      {/* User header card */}
      <div className="mb-4 rounded-xl border border-gray-100 bg-white p-6 shadow-sm">
        {loading || !user ? (
          <div className="flex h-24 items-center justify-center text-sm text-gray-400">
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            {t('users.detail.loading')}
          </div>
        ) : (
          <div className="flex items-start gap-4">
            {user.avatar ? (
              <img src={user.avatar} alt={user.username} className="h-16 w-16 rounded-full object-cover" />
            ) : (
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-primary/10 text-2xl font-semibold text-primary">
                {(user.display_name || user.username).charAt(0).toUpperCase()}
              </div>
            )}
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-3">
                <h2 className="text-lg font-semibold text-gray-900">
                  {user.display_name || user.username}
                </h2>
                <span className={cn('rounded-full px-2 py-0.5 text-xs font-medium', statusColor(user.status))}>
                  {statusLabel(user.status)}
                </span>
                {user.must_change_pwd && (
                  <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
                    {t('users.detail.mustResetPassword')}
                  </span>
                )}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-4 text-sm text-gray-500">
                <span className="inline-flex items-center gap-1">
                  <UserIcon className="h-3.5 w-3.5" />
                  {user.username}
                </span>
                {user.email && (
                  <span className="inline-flex items-center gap-1">
                    <Mail className="h-3.5 w-3.5" />
                    {user.email}
                  </span>
                )}
                {user.phone && (
                  <span className="inline-flex items-center gap-1">
                    <Phone className="h-3.5 w-3.5" />
                    {user.phone}
                  </span>
                )}
              </div>
              <p className="mt-2 text-xs text-gray-400">
                {t('users.detail.createdAt', { date: formatDate(user.created_at) })}
                {user.last_login_at && t('users.detail.lastLoginAt', { date: formatDate(user.last_login_at) })}
                {user.last_login_ip && t('users.detail.lastLoginIp', { ip: user.last_login_ip })}
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <ResetPasswordButton userID={userID} onDone={loadUser} />
              {user.status === UserStatus.Locked ? (
                <UnlockButton userID={userID} onDone={loadUser} />
              ) : (
                <LockButton userID={userID} onDone={loadUser} />
              )}
              {user.status !== 3 && (
                <OffboardButton userID={userID} username={user.username} onDone={loadUser} />
              )}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <nav className="flex border-b border-gray-100">
          {TAB_KEYS.map((item) => (
            <button
              key={item.key}
              onClick={() => setTab(item.key)}
              className={cn(
                'border-b-2 px-4 py-3 text-sm font-medium transition-colors',
                tab === item.key
                  ? 'border-primary text-primary'
                  : 'border-transparent text-gray-500 hover:text-gray-700',
              )}
            >
              {t(item.i18nKey)}
            </button>
          ))}
        </nav>

        <div className="p-6">
          {tab === 'basic' && user && <BasicTab user={user} onSaved={loadUser} />}
          {tab === 'detail' && user && <DetailTab userID={userID} />}
          {tab === 'groups' && user && <GroupsTab userID={userID} />}
          {tab === 'roles' && user && <RolesTab userID={userID} />}
          {tab === 'identities' && user && <IdentitiesTab userID={userID} />}
          {tab === 'mfa' && user && <MFATab userID={userID} />}
          {tab === 'sessions' && user && <SessionsTab userID={userID} />}
          {tab === 'history' && user && <HistoryTab userID={userID} />}
        </div>
      </div>
    </motion.div>
  )
}

/* ─────────────────────────── Reset password ─────────────────────────── */

function ResetPasswordButton({ userID, onDone }: { userID: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [pwd, setPwd] = useState('')
  const [mustChange, setMustChange] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  const submit = async () => {
    if (!pwd || pwd.length < 6) return
    setSubmitting(true)
    try {
      await userApi.resetPassword(userID, pwd, mustChange)
      setOpen(false)
      setPwd('')
      onDone()
      toast.success(t('users.detail.resetPwd.success'))
    } catch (e) {
      toast.error(t('users.detail.resetPwd.failed'), extractMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-sm font-medium text-amber-700 hover:bg-amber-100"
      >
        <KeyRound className="h-4 w-4" />
        {t('users.detail.resetPwd.button')}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
            <h3 className="mb-4 text-lg font-semibold">{t('users.detail.resetPwd.title')}</h3>
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.detail.resetPwd.newPassword')}</label>
                <input
                  type="password"
                  value={pwd}
                  onChange={(e) => setPwd(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  placeholder={t('users.detail.resetPwd.placeholder')}
                />
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={mustChange}
                  onChange={(e) => setMustChange(e.target.checked)}
                  className="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                />
                {t('users.detail.resetPwd.forceChange')}
              </label>
              <div className="flex justify-end gap-3 pt-2">
                <Button variant="secondary" onClick={() => setOpen(false)}>
                  {t('users.detail.common.cancel')}
                </Button>
                <Button onClick={submit} loading={submitting} disabled={submitting || pwd.length < 6}>
                  {t('users.detail.resetPwd.submit')}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/* ─────────────────────────── Basic tab ──────────────────────────────── */

function BasicTab({ user, onSaved }: { user: User; onSaved: () => void }) {
  const { t } = useTranslation()
  const [form, setForm] = useState({
    display_name: user.display_name || '',
    email: user.email || '',
    phone: user.phone || '',
    avatar: user.avatar || '',
    status: user.status,
  })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setForm({
      display_name: user.display_name || '',
      email: user.email || '',
      phone: user.phone || '',
      avatar: user.avatar || '',
      status: user.status,
    })
  }, [user])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await userApi.update(user.id, {
        display_name: form.display_name || undefined,
        email: form.email || undefined,
        phone: form.phone || undefined,
        avatar: form.avatar || undefined,
        status: form.status,
      })
      onSaved()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={save} className="max-w-2xl space-y-4">
      <Field label={t('users.detail.basicForm.displayName')} hint={t('users.detail.basicForm.displayNameHint')}>
        <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.basicForm.email')} hint={t('users.detail.basicForm.emailHint')}>
        <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.basicForm.phone')} hint={t('users.detail.basicForm.phoneHint')}>
        <input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.basicForm.avatar')} hint={t('users.detail.basicForm.avatarHint')}>
        <input value={form.avatar} onChange={(e) => setForm({ ...form, avatar: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.basicForm.status')} hint={<><strong>{t('users.detail.status.active')}</strong>{t('users.detail.basicForm.statusHintActiveDesc')}<strong>{t('users.detail.status.locked')}</strong>{t('users.detail.basicForm.statusHintLockedDesc')}<strong>{t('users.detail.status.disabled')}</strong>{t('users.detail.basicForm.statusHintDisabledDesc')}<strong>{t('users.detail.status.pending')}</strong>{t('users.detail.basicForm.statusHintPendingDesc')}</>}>
        <select value={form.status} onChange={(e) => setForm({ ...form, status: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20">
          {STATUS_VALUES.map((s) => (
            <option key={s.value} value={s.value}>{t(s.i18nKey)}</option>
          ))}
        </select>
      </Field>
      <div className="pt-2">
        <Button type="submit" loading={saving}>
          {t('users.detail.common.save')}
        </Button>
      </div>
    </form>
  )
}

/* ─────────────────────────── Detail tab ─────────────────────────────── */

function DetailTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [detail, setDetail] = useState<UserDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState({
    gender: 0,
    birthday: '',
    address: '',
    employee_no: '',
    job_title: '',
    department: '',
  })

  useEffect(() => {
    let alive = true
    setLoading(true)
    userApi
      .getDetail(userID)
      .then((d) => {
        if (!alive) return
        setDetail(d)
        setForm({
          gender: d?.gender ?? 0,
          birthday: d?.birthday ?? '',
          address: d?.address ?? '',
          employee_no: d?.employee_no ?? '',
          job_title: d?.job_title ?? '',
          department: d?.department ?? '',
        })
      })
      .catch(() => {})
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [userID])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await userApi.updateDetail(userID, {
        gender: form.gender,
        birthday: form.birthday,
        address: form.address,
        employee_no: form.employee_no,
        job_title: form.job_title,
        department: form.department,
      })
      setDetail(updated)
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  }

  return (
    <form onSubmit={save} className="max-w-2xl space-y-4">
      <Field label={t('users.detail.profile.gender')} hint={t('users.detail.profile.genderHint')}>
        <select value={form.gender} onChange={(e) => setForm({ ...form, gender: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20">
          {GENDER_VALUES.map((g) => (
            <option key={g.value} value={g.value}>{t(g.i18nKey)}</option>
          ))}
        </select>
      </Field>
      <Field label={t('users.detail.profile.birthday')} hint={t('users.detail.profile.birthdayHint')}>
        <input type="date" value={form.birthday} onChange={(e) => setForm({ ...form, birthday: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.profile.department')} hint={t('users.detail.profile.departmentHint')}>
        <input value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" placeholder={t('users.detail.profile.departmentPlaceholder')} />
      </Field>
      <Field label={t('users.detail.profile.jobTitle')} hint={t('users.detail.profile.jobTitleHint')}>
        <input value={form.job_title} onChange={(e) => setForm({ ...form, job_title: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" placeholder={t('users.detail.profile.jobTitlePlaceholder')} />
      </Field>
      <Field label={t('users.detail.profile.employeeNo')} hint={t('users.detail.profile.employeeNoHint')}>
        <input value={form.employee_no} onChange={(e) => setForm({ ...form, employee_no: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <Field label={t('users.detail.profile.address')} hint={t('users.detail.profile.addressHint')}>
        <textarea value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} rows={2} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
      </Field>
      <div className="pt-2">
        <Button type="submit" loading={saving}>
          {t('users.detail.common.save')}
        </Button>
      </div>
      {detail && (
        <p className="text-xs text-gray-400">{t('users.detail.profile.lastUpdated', { date: formatDate(detail.birthday ? new Date().toISOString() : new Date().toISOString()) })}</p>
      )}
    </form>
  )
}

/* ─────────────────────────── Groups tab ─────────────────────────────── */

function GroupsTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<Group[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    groupApi
      .listByUser(userID)
      .then((items) => alive && setGroups(items ?? []))
      .catch(() => {})
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [userID])

  if (loading) {
    return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  }
  if (groups.length === 0) {
    return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.groupsTab.empty')}</div>
  }
  return (
    <div className="space-y-2">
      {groups.map((g) => (
        <div key={g.id} className="flex items-center justify-between rounded-lg border border-gray-100 px-4 py-3 hover:bg-gray-50">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-900">{g.name}</span>
              <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">{g.code}</code>
            </div>
            {g.description && <p className="mt-0.5 text-xs text-gray-500">{g.description}</p>}
          </div>
          <span className="text-xs text-gray-400">{t('users.detail.groupsTab.memberCount', { count: g.member_count })}</span>
        </div>
      ))}
    </div>
  )
}

/* ─────────────────────────── Identities tab ─────────────────────────── */

function IdentitiesTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [items, setItems] = useState<UserIdentity[]>([])
  const [loading, setLoading] = useState(true)
  const [removingID, setRemovingID] = useState<string | null>(null)
  const [delIdentity, setDelIdentity] = useState<UserIdentity | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await userApi.listIdentities(userID)
      setItems(list ?? [])
    } finally {
      setLoading(false)
    }
  }, [userID])

  useEffect(() => {
    load()
  }, [load])

  const confirmUnbind = async () => {
    const it = delIdentity
    if (!it) return
    setDelIdentity(null)
    setRemovingID(it.id)
    try {
      await userApi.unbindIdentity(userID, it.id)
      toast.success(t('common.deleteSuccess'))
      await load()
    } catch (e) {
      toast.error(t('common.deleteFailed'), extractMessage(e))
    } finally {
      setRemovingID(null)
    }
  }

  if (loading) {
    return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  }
  if (items.length === 0) {
    return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.identitiesTab.empty')}</div>
  }
  return (
    <div className="space-y-2">
      {items.map((it) => (
        <div key={it.id} className="flex items-center justify-between rounded-lg border border-gray-100 px-4 py-3 hover:bg-gray-50">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-900">{it.provider_type}</span>
              <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">{it.provider_id}</code>
            </div>
            <p className="mt-0.5 text-xs text-gray-500">
              {it.external_name ? `${it.external_name} · ` : ''}{it.external_id}
            </p>
            <p className="mt-0.5 text-xs text-gray-400">{t('users.detail.identitiesTab.boundAt', { date: formatDate(it.created_at) })}</p>
          </div>
          <button
            onClick={() => setDelIdentity(it)}
            disabled={removingID === it.id}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-gray-400 hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
          >
            {removingID === it.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unlink className="h-3.5 w-3.5" />}
            {t('users.detail.identitiesTab.unbind')}
          </button>
        </div>
      ))}

      <ConfirmDialog
        open={!!delIdentity}
        title={t('users.detail.identitiesTab.confirmUnbind', { provider: delIdentity?.provider_type ?? '' })}
        loading={removingID === delIdentity?.id}
        onConfirm={confirmUnbind}
        onCancel={() => setDelIdentity(null)}
      />
    </div>
  )
}

/* ─────────────────────────── MFA tab ────────────────────────────────── */

function MFATab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [items, setItems] = useState<UserMFA[]>([])
  const [loading, setLoading] = useState(true)
  const [removing, setRemoving] = useState<string | null>(null)
  const [delMfa, setDelMfa] = useState<UserMFA | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await userApi.listMFA(userID)
      setItems(list ?? [])
    } finally {
      setLoading(false)
    }
  }, [userID])

  useEffect(() => {
    load()
  }, [load])

  const confirmRemove = async () => {
    const m = delMfa
    if (!m) return
    setDelMfa(null)
    setRemoving(m.type)
    try {
      await userApi.deleteMFA(userID, m.type)
      toast.success(t('common.deleteSuccess'))
      await load()
    } catch (e) {
      toast.error(t('common.deleteFailed'), extractMessage(e))
    } finally {
      setRemoving(null)
    }
  }

  if (loading) {
    return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  }
  if (items.length === 0) {
    return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.mfaTab.empty')}</div>
  }
  return (
    <div className="space-y-2">
      {items.map((m) => (
        <div key={m.type} className="flex items-center justify-between rounded-lg border border-gray-100 px-4 py-3 hover:bg-gray-50">
          <div className="flex items-center gap-3">
            <ShieldCheck className={cn('h-5 w-5', m.verified ? 'text-emerald-500' : 'text-gray-300')} />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-900">{m.type.toUpperCase()}</span>
                {m.is_default && <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">{t('users.detail.mfaTab.default')}</span>}
                {!m.verified && <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-700">{t('users.detail.mfaTab.unverified')}</span>}
              </div>
              <p className="mt-0.5 text-xs text-gray-400">
                {t('users.detail.mfaTab.enrolledAt', { date: formatDate(m.created_at) })}
              </p>
            </div>
          </div>
          <button
            onClick={() => setDelMfa(m)}
            disabled={removing === m.type}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-gray-400 hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
          >
            {removing === m.type ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
            {t('users.detail.mfaTab.forceRemove')}
          </button>
        </div>
      ))}

      <ConfirmDialog
        open={!!delMfa}
        title={t('users.detail.mfaTab.confirmRemove', { type: delMfa?.type.toUpperCase() ?? '' })}
        loading={removing === delMfa?.type}
        onConfirm={confirmRemove}
        onCancel={() => setDelMfa(null)}
      />
    </div>
  )
}

/* ─────────────────────────── Lock / Unlock ──────────────────────────── */

function LockButton({ userID, onDone }: { userID: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    if (!reason.trim()) return
    setBusy(true)
    try {
      await userApi.lock(userID, reason.trim())
      setOpen(false)
      setReason('')
      onDone()
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100"
      >
        <Lock className="h-4 w-4" />
        {t('users.detail.lock.button')}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
            <h3 className="mb-4 text-lg font-semibold">{t('users.detail.lock.title')}</h3>
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.detail.lock.reason')}</label>
                <textarea
                  rows={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={t('users.detail.lock.reasonPlaceholder')}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button onClick={() => setOpen(false)} className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50">{t('users.detail.common.cancel')}</button>
                <button
                  onClick={submit}
                  disabled={busy || !reason.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-60"
                >
                  {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                  {t('users.detail.lock.submit')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function UnlockButton({ userID, onDone }: { userID: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const doUnlock = async () => {
    setConfirming(false)
    setBusy(true)
    try {
      await userApi.unlock(userID)
      onDone()
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <button
        onClick={() => setConfirming(true)}
        disabled={busy}
        className="inline-flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-sm font-medium text-emerald-700 hover:bg-emerald-100 disabled:opacity-60"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <LockOpen className="h-4 w-4" />}
        {t('users.detail.unlock.button')}
      </button>
      <ConfirmDialog
        open={confirming}
        title={t('users.detail.unlock.confirm')}
        danger={false}
        loading={busy}
        onConfirm={doUnlock}
        onCancel={() => setConfirming(false)}
      />
    </>
  )
}

/* ─────────────────────────── Offboard ───────────────────────────────── */

function OffboardButton({ userID, username, onDone }: { userID: string; username: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await userApi.offboard(userID)
      setOpen(false)
      toast.success(t('users.detail.offboard.success'))
      onDone()
    } catch (e) {
      toast.error(t('users.detail.offboard.failed'), extractMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg border border-red-300 bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700"
      >
        <UserX className="h-4 w-4" />
        {t('users.detail.offboard.button')}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
            <h3 className="mb-2 text-lg font-semibold">{t('users.detail.offboard.title')}</h3>
            <p className="mb-4 text-sm text-gray-600">{t('users.detail.offboard.confirm', { username })}</p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setOpen(false)} className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50">{t('users.detail.common.cancel')}</button>
              <button
                onClick={submit}
                disabled={busy}
                className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-60"
              >
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('users.detail.offboard.submit')}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/* ─────────────────────────── Roles tab ──────────────────────────────── */

function RolesTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [items, setItems] = useState<EffectiveRole[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let alive = true
    userApi
      .listEffectiveRoles(userID)
      .then((list) => alive && setItems(list ?? []))
      .catch(() => {})
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [userID])
  if (loading) return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  if (items.length === 0) return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.rolesTab.empty')}</div>
  return (
    <div className="space-y-2">
      {items.map((it, i) => (
        <div key={`${it.role.id}-${it.source}-${it.source_id}-${i}`} className="flex items-center justify-between rounded-lg border border-gray-100 px-4 py-3 hover:bg-gray-50">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-900">{it.role.name}</span>
              <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">{it.role.code}</code>
            </div>
            {it.role.description && <p className="mt-0.5 text-xs text-gray-500">{it.role.description}</p>}
          </div>
          <span
            className={cn(
              'rounded-full px-2 py-0.5 text-xs font-medium',
              it.source === 'direct'
                ? 'bg-primary/10 text-primary'
                : it.source === 'org'
                  ? 'bg-purple-100 text-purple-700'
                  : 'bg-amber-100 text-amber-700',
            )}
          >
            {it.source === 'direct'
              ? t('users.detail.rolesTab.direct')
              : it.source === 'org'
                ? t('users.detail.rolesTab.fromOrg', { id: it.source_id })
                : t('users.detail.rolesTab.fromGroup', { id: it.source_id })}
          </span>
        </div>
      ))}
    </div>
  )
}

/* ─────────────────────────── Sessions tab ───────────────────────────── */

function SessionsTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [items, setItems] = useState<UserSession[]>([])
  const [loading, setLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [revokingAll, setRevokingAll] = useState(false)
  const [delSession, setDelSession] = useState<UserSession | null>(null)
  const [showRevokeAll, setShowRevokeAll] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await userApi.listSessions(userID)
      setItems(list ?? [])
    } finally {
      setLoading(false)
    }
  }, [userID])

  useEffect(() => {
    load()
  }, [load])

  const confirmRevokeOne = async () => {
    const s = delSession
    if (!s) return
    setDelSession(null)
    setRevoking(s.id)
    try {
      await userApi.revokeSession(userID, s.namespace, s.id)
      await load()
    } finally {
      setRevoking(null)
    }
  }

  const confirmRevokeAll = async () => {
    setShowRevokeAll(false)
    setRevokingAll(true)
    try {
      await userApi.revokeAllSessions(userID)
      await load()
    } finally {
      setRevokingAll(false)
    }
  }

  if (loading) return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  if (items.length === 0) return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.sessionsTab.empty')}</div>
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button
          onClick={() => setShowRevokeAll(true)}
          disabled={revokingAll}
          className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100 disabled:opacity-60"
        >
          {revokingAll ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <LogOut className="h-3.5 w-3.5" />}
          {t('users.detail.sessionsTab.revokeAll')}
        </button>
      </div>
      {items.map((s) => (
        <div key={s.id} className="rounded-lg border border-gray-100 px-4 py-3 hover:bg-gray-50">
          <div className="flex items-start justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600">{s.namespace.split(':').pop()}</code>
                <span className="text-sm text-gray-700">{s.ip}</span>
                {s.mfa_verified && <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-700">{t('users.detail.sessionsTab.mfaVerified')}</span>}
              </div>
              <p className="mt-1 truncate text-xs text-gray-500">{s.user_agent}</p>
              <p className="mt-0.5 text-xs text-gray-400">
                {t('users.detail.sessionsTab.meta', { loginAt: formatDate(s.created_at), lastActiveAt: formatDate(s.last_active_at), expiresAt: formatDate(s.expires_at) })}
              </p>
            </div>
            <button
              onClick={() => setDelSession(s)}
              disabled={revoking === s.id}
              className="ml-3 inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-gray-400 hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
            >
              {revoking === s.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <LogOut className="h-3.5 w-3.5" />}
              {t('users.detail.sessionsTab.revoke')}
            </button>
          </div>
        </div>
      ))}

      <ConfirmDialog
        open={!!delSession}
        title={t('users.detail.sessionsTab.confirmRevokeOne', { namespace: delSession?.namespace ?? '' })}
        loading={revoking === delSession?.id}
        onConfirm={confirmRevokeOne}
        onCancel={() => setDelSession(null)}
      />
      <ConfirmDialog
        open={showRevokeAll}
        title={t('users.detail.sessionsTab.confirmRevokeAll')}
        loading={revokingAll}
        onConfirm={confirmRevokeAll}
        onCancel={() => setShowRevokeAll(false)}
      />
    </div>
  )
}

/* ─────────────────────────── History tab ────────────────────────────── */

function HistoryTab({ userID }: { userID: string }) {
  const { t } = useTranslation()
  const [data, setData] = useState<PaginatedData<UserLoginRecord>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)

  useEffect(() => {
    let alive = true
    // setLoading inside the same async chain avoids the cascading
    // re-render the eslint rule flags when setState is called
    // synchronously in the effect body.
    userApi
      .listLoginHistory(userID, { page, page_size: 20 })
      .then((res) => {
        if (!alive) return
        setData(res)
        setLoading(false)
      })
      .catch(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [userID, page])

  const totalPages = Math.ceil(data.total / data.page_size) || 1

  if (loading) return <div className="py-8 text-center text-sm text-gray-400"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
  if (data.items.length === 0) return <div className="py-8 text-center text-sm text-gray-400">{t('users.detail.historyTab.empty')}</div>

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
              <th className="px-3 py-2">{t('users.detail.historyTab.colTime')}</th>
              <th className="px-3 py-2">{t('users.detail.historyTab.colResult')}</th>
              <th className="px-3 py-2">{t('users.detail.historyTab.colStage')}</th>
              <th className="px-3 py-2">{t('users.detail.historyTab.colType')}</th>
              <th className="px-3 py-2">{t('users.detail.historyTab.colIp')}</th>
              <th className="px-3 py-2">{t('users.detail.historyTab.colReason')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {data.items.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-gray-500">{formatDate(r.created_at)}</td>
                <td className="px-3 py-2">
                  <span className={cn('rounded-full px-2 py-0.5 text-xs font-medium', r.success ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700')}>
                    {r.success ? t('users.detail.historyTab.success') : t('users.detail.historyTab.failed')}
                  </span>
                </td>
                <td className="px-3 py-2 text-xs text-gray-600">{r.stage}</td>
                <td className="px-3 py-2 text-xs text-gray-600">{r.auth_type}</td>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-gray-500">{r.ip || '-'}</td>
                <td className="px-3 py-2 text-xs text-gray-500">{r.reason || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-gray-100 pt-3">
          <p className="text-sm text-gray-500">{t('users.detail.historyTab.pagingSummary', { total: data.total, page, pages: totalPages })}</p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
            >
              {t('users.detail.historyTab.prevPage')}
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
            >
              {t('users.detail.historyTab.nextPage')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
