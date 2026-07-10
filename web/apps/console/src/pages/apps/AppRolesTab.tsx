// AppRolesTab — central UI for per-app role catalog + role bindings.
//
// Two stacked sections:
//   1. Roles (Role catalog)    — define Admin / Editor / Viewer / custom
//   2. Bindings                — bind user/group/org/system-role → role
//
// Backend automatically emits `app_roles: ["admin"]` claim at /token
// time based on these bindings. SP reads claim verbatim — no JMESPath.
import { useCallback, useEffect, useState } from 'react'
import { Plus, Trash2, Loader2, Crown, Shield, User, UsersRound, Building2, Edit2, Star } from 'lucide-react'
import { appRoleApi, groupApi, userApi, orgApi, permissionApi, useTranslation, AccessPolicySubjectType } from '@mxid/shared'
import type {
  AppRole, AppRoleBinding, AppRoleSubjectType, AppRoleOwner,
  Group, User as UserT, OrgNode, Role,
} from '@mxid/shared'
import { Field, Input, Select, Button, Textarea, ConfirmDialog } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

export default function AppRolesTab({
  owner = 'app',
  ownerId,
}: {
  owner?: AppRoleOwner
  ownerId: string
}) {
  const { t } = useTranslation()
  const [roles, setRoles] = useState<AppRole[]>([])
  const [bindings, setBindings] = useState<AppRoleBinding[]>([])
  const [loading, setLoading] = useState(true)
  const [showRoleForm, setShowRoleForm] = useState(false)
  const [editingRole, setEditingRole] = useState<AppRole | null>(null)
  const [showBindForm, setShowBindForm] = useState(false)
  const [delRole, setDelRole] = useState<AppRole | null>(null)
  const [deletingRole, setDeletingRole] = useState(false)
  const [delBinding, setDelBinding] = useState<AppRoleBinding | null>(null)
  const [deletingBinding, setDeletingBinding] = useState(false)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const [r, b] = await Promise.all([
        appRoleApi.listRoles(owner, ownerId),
        appRoleApi.listBindings(owner, ownerId),
      ])
      setRoles(r)
      setBindings(b)
    } catch {
      toast.error(t('apps.roles.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [owner, ownerId, t])

  useEffect(() => {
    reload()
  }, [reload])

  const confirmDeleteRole = async () => {
    const r = delRole
    if (!r) return
    setDeletingRole(true)
    try {
      await appRoleApi.deleteRole(owner, ownerId, r.id)
      setDelRole(null)
      toast.success(t("common.success"))
      reload()
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setDeletingRole(false)
    }
  }

  const confirmDeleteBinding = async () => {
    const b = delBinding
    if (!b) return
    setDeletingBinding(true)
    try {
      await appRoleApi.deleteBinding(owner, ownerId, b.id)
      setDelBinding(null)
      toast.success(t("common.success"))
      reload()
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setDeletingBinding(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold text-ink">{t('apps.roles.title')}</h3>
        <p className="mt-0.5 text-sm text-muted">
          {t('apps.roles.hint')}{' '}
          {t('apps.roles.tokenHint', { claim: 'app_roles' })}
        </p>
      </div>

      {/* ─── Roles section ─── */}
      <section className="space-y-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-ink">{t('apps.roles.catalog', { count: roles.length })}</h4>
          <Button variant="primary" size="sm" onClick={() => { setEditingRole(null); setShowRoleForm(true) }}>
            <Plus className="h-4 w-4" /> {t('apps.roles.createRole')}
          </Button>
        </div>
        {loading ? (
          <Loader2 className="mx-auto my-6 h-5 w-5 animate-spin text-faint" />
        ) : roles.length === 0 ? (
          <p className="rounded-lg border border-dashed border-border py-6 text-center text-sm text-faint">
            {t('apps.roles.emptyCatalog')}
          </p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {roles.map((r) => (
              <div
                key={r.id}
                className="group relative flex items-start gap-3 overflow-hidden rounded-xl border border-border bg-surface px-4 py-3 transition-colors hover:border-primary/40 hover:shadow-sm"
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Shield className="h-4 w-4 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate text-sm font-semibold text-ink">{r.name}</span>
                    {r.is_default && (
                      <span title={t('apps.roles.defaultRoleTitle')} className="shrink-0">
                        <Star className="h-3.5 w-3.5 fill-amber-400 text-amber-400" />
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 truncate font-mono text-xs text-faint">{r.code}</div>
                  {r.description && (
                    <p className="mt-1 line-clamp-2 text-xs text-muted">{r.description}</p>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                  <button onClick={() => { setEditingRole(r); setShowRoleForm(true) }} className="rounded p-1 text-faint hover:bg-surface-muted hover:text-ink" title={t('common.edit')}>
                    <Edit2 className="h-3.5 w-3.5" />
                  </button>
                  <button onClick={() => setDelRole(r)} className="rounded p-1 text-faint hover:bg-red-50 hover:text-red-500" title={t('common.delete')}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ─── Bindings section ─── */}
      <section className="space-y-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-ink">{t('apps.roles.bindings', { count: bindings.length })}</h4>
          <Button variant="primary" size="sm" onClick={() => setShowBindForm(true)} disabled={roles.length === 0}>
            <Plus className="h-4 w-4" /> {t('apps.roles.createBinding')}
          </Button>
        </div>
        {roles.length === 0 ? (
          <p className="py-4 text-center text-xs text-faint">{t('apps.roles.pleaseCreateRoleFirst')}</p>
        ) : bindings.length === 0 ? (
          <p className="rounded-lg border border-dashed border-border py-6 text-center text-sm text-faint">
            {t('apps.roles.emptyBindings')}
          </p>
        ) : (
          <div className="space-y-2">
            {bindings.map((b) => (
              <BindingRow key={b.id} binding={b} onDelete={setDelBinding} />
            ))}
          </div>
        )}
      </section>

      {showRoleForm && (
        <RoleForm
          owner={owner}
          ownerId={ownerId}
          editing={editingRole}
          onClose={() => { setShowRoleForm(false); setEditingRole(null) }}
          onSaved={() => { setShowRoleForm(false); setEditingRole(null); reload() }}
        />
      )}
      {showBindForm && (
        <BindingForm
          owner={owner}
          ownerId={ownerId}
          roles={roles}
          onClose={() => setShowBindForm(false)}
          onSaved={() => { setShowBindForm(false); reload() }}
        />
      )}

      <ConfirmDialog
        open={!!delRole}
        title={t('apps.roles.confirmDeleteRole', { name: delRole?.name ?? '', code: delRole?.code ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingRole}
        onConfirm={confirmDeleteRole}
        onCancel={() => setDelRole(null)}
      />
      <ConfirmDialog
        open={!!delBinding}
        title={t('apps.roles.confirmDeleteBinding')}
        loading={deletingBinding}
        onConfirm={confirmDeleteBinding}
        onCancel={() => setDelBinding(null)}
      />
    </div>
  )
}

/* ─── Binding row ─── */

const SUBJECT_ICON: Record<AppRoleSubjectType, typeof User> = {
  user: User, group: UsersRound, org: Building2, role: Crown,
}

function BindingRow({ binding, onDelete }: { binding: AppRoleBinding; onDelete: (b: AppRoleBinding) => void }) {
  const { t } = useTranslation()
  const Icon = SUBJECT_ICON[binding.subject_type]
  const subjectSame = binding.subject_name === binding.subject_code
  const subjectLabel = t(`apps.roles.subjectLabels.${binding.subject_type}`)
  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-surface px-4 py-3 transition-colors hover:border-primary/30">
      {/* Subject */}
      <div className="flex min-w-0 flex-1 items-center gap-2.5">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-muted">
          <Icon className="h-4 w-4 text-muted" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-ink">
            {binding.subject_name || t('apps.roles.unknownSubject')}
          </div>
          <div className="flex items-center gap-1.5 truncate text-xs text-faint">
            <span>{subjectLabel}</span>
            {!subjectSame && binding.subject_code && (
              <>
                <span>·</span>
                <span className="font-mono">{binding.subject_code}</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Arrow */}
      <span className="shrink-0 text-faint">→</span>

      {/* Role */}
      <div className="flex min-w-0 shrink-0 items-center gap-2 rounded-lg bg-primary/5 px-3 py-1.5">
        <Shield className="h-3.5 w-3.5 text-primary" />
        <span className="text-sm font-medium text-primary">{binding.role_name}</span>
        <span className="font-mono text-xs text-primary/60">{binding.role_code}</span>
      </div>

      <button
        onClick={() => onDelete(binding)}
        className="shrink-0 rounded-md p-1.5 text-faint hover:bg-red-50 hover:text-red-500"
        title={t('apps.roles.unbindTitle')}
      >
        <Trash2 className="h-4 w-4" />
      </button>
    </div>
  )
}

/* ─── Role create/edit modal ─── */

function RoleForm({
  owner, ownerId, editing, onClose, onSaved,
}: {
  owner: AppRoleOwner
  ownerId: string
  editing: AppRole | null
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [code, setCode] = useState(editing?.code ?? '')
  const [name, setName] = useState(editing?.name ?? '')
  const [description, setDescription] = useState(editing?.description ?? '')
  const [isDefault, setIsDefault] = useState(editing?.is_default ?? false)
  const [sortOrder, setSortOrder] = useState(editing?.sort_order ?? 0)
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (!code || !name) { toast.warning(t('apps.roles.codeNameRequired')); return }
    setSaving(true)
    try {
      if (editing) {
        await appRoleApi.updateRole(owner, ownerId, editing.id, { name, description, is_default: isDefault, sort_order: sortOrder })
      } else {
        await appRoleApi.createRole(owner, ownerId, { code, name, description, is_default: isDefault, sort_order: sortOrder })
      }
      toast.success(t("common.success"))
      onSaved()
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-xl bg-surface p-6 shadow-xl">
        <h3 className="mb-4 text-lg font-semibold">{editing ? t('apps.roles.editRole') : t('apps.roles.createRole')}</h3>
        <div className="space-y-4">
          <Field label={t('apps.roles.codeLabel')} hint={t('apps.roles.codeHint')}>
            <Input value={code} onChange={(e) => setCode(e.target.value)} disabled={!!editing} placeholder="admin" />
          </Field>
          <Field label={t('apps.roles.nameLabel')}>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('apps.roles.namePlaceholder')} />
          </Field>
          <Field label={t('apps.roles.descLabel')}>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
          </Field>
          <Field label={t('apps.roles.sortLabel')}>
            <Input type="number" value={sortOrder} onChange={(e) => setSortOrder(Number(e.target.value))} />
          </Field>
          <label className="flex items-center gap-2 text-sm text-ink">
            <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} className="h-4 w-4 rounded border-border" />
            <span>{t('apps.roles.setDefault')}</span>
          </label>
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={handleSave} disabled={saving}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('common.save')}
          </Button>
        </div>
      </div>
    </div>
  )
}

/* ─── Binding create modal ─── */

function BindingForm({
  owner, ownerId, roles, onClose, onSaved,
}: {
  owner: AppRoleOwner
  ownerId: string
  roles: AppRole[]
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [appRoleId, setAppRoleId] = useState<string>(String(roles[0]?.id ?? ''))
  const [subjectType, setSubjectType] = useState<AppRoleSubjectType>(AccessPolicySubjectType.Group)
  const [subjectId, setSubjectId] = useState<string>('')
  const [groups, setGroups] = useState<Group[]>([])
  const [users, setUsers] = useState<UserT[]>([])
  const [orgs, setOrgs] = useState<OrgNode[]>([])
  const [sysRoles, setSysRoles] = useState<Role[]>([])
  const [optsLoading, setOptsLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setSubjectId('')
    setOptsLoading(true)
    const load = async () => {
      try {
        if (subjectType === AccessPolicySubjectType.Group) setGroups((await groupApi.list({ page: 1, page_size: 200 })).items)
        else if (subjectType === AccessPolicySubjectType.User) setUsers((await userApi.list({ page: 1, page_size: 200 })).items)
        else if (subjectType === AccessPolicySubjectType.Org) {
          const tree = await orgApi.tree()
          const flat: OrgNode[] = []
          const walk = (n: OrgNode[]) => { for (const x of n) { flat.push(x); if (x.children) walk(x.children) } }
          walk(tree); setOrgs(flat)
        } else if (subjectType === AccessPolicySubjectType.Role) setSysRoles((await permissionApi.listRoles({ page: 1, page_size: 200 })).items)
      } finally { setOptsLoading(false) }
    }
    load()
  }, [subjectType])

  const handleSave = async () => {
    if (!appRoleId || !subjectId) { toast.warning(t('apps.roles.subjectRequired')); return }
    setSaving(true)
    try {
      await appRoleApi.createBinding(owner, ownerId, { app_role_id: appRoleId, subject_type: subjectType, subject_id: subjectId })
      toast.success(t('apps.roles.bound'))
      onSaved()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('apps.roles.bindFailed'), msg)
    } finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-xl bg-surface p-6 shadow-xl">
        <h3 className="mb-4 text-lg font-semibold">{t('apps.roles.createBindingTitle')}</h3>
        <div className="space-y-4">
          <Field label={t('apps.roles.targetRole')}>
            <Select value={appRoleId} onChange={(e) => setAppRoleId(e.target.value)}>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name} ({r.code})</option>)}
            </Select>
          </Field>
          <Field label={t('apps.roles.subjectType')}>
            <Select value={subjectType} onChange={(e) => setSubjectType(e.target.value as AppRoleSubjectType)}>
              <option value="user">{t('apps.roles.subjectTypes.user')}</option>
              <option value="group">{t('apps.roles.subjectTypes.group')}</option>
              <option value="org">{t('apps.roles.subjectTypes.org')}</option>
              <option value="role">{t('apps.roles.subjectTypes.role')}</option>
            </Select>
          </Field>
          <Field label={t('apps.roles.selectSubject')}>
            {optsLoading ? (
              <div className="flex h-10 items-center justify-center"><Loader2 className="h-4 w-4 animate-spin text-faint" /></div>
            ) : (
              <Select value={subjectId} onChange={(e) => setSubjectId(e.target.value)}>
                <option value="">{t('apps.roles.pleaseSelect')}</option>
                {subjectType === AccessPolicySubjectType.Group && groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name} ({g.code})</option>)}
                {subjectType === AccessPolicySubjectType.User && users.map((u) => <option key={String(u.id)} value={String(u.id)}>{u.display_name || u.username} ({u.username})</option>)}
                {subjectType === AccessPolicySubjectType.Org && orgs.map((o) => <option key={String(o.id)} value={String(o.id)}>{o.name} ({o.code})</option>)}
                {subjectType === AccessPolicySubjectType.Role && sysRoles.map((r) => <option key={String(r.id)} value={String(r.id)}>{r.name} ({r.code})</option>)}
              </Select>
            )}
          </Field>
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={handleSave} disabled={saving}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('apps.roles.bind')}
          </Button>
        </div>
      </div>
    </div>
  )
}
