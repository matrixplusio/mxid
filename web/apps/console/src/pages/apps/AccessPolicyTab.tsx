// AccessPolicyTab — manage who can launch a given app OR an entire app group.
//
// Owner = 'app' → policies attached directly to this single app
// Owner = 'app-group' → policies inherited by every app in this group
//
// Rules are the same on both sides; backend dispatches by the resource URL.
// On save the backend publishes app_access.changed → all connected portal
// SSE clients refetch /apps so users see new permissions without reload.
import { useCallback, useEffect, useState } from 'react'
import { Plus, Trash2, Loader2, ShieldCheck, ShieldOff, Globe2, UsersRound, User, Building2, Crown } from 'lucide-react'
import { appAccessApi, groupApi, userApi, orgApi, permissionApi, cn, useTranslation, AccessPolicySubjectType } from '@mxid/shared'
import type { AccessPolicy, AccessSubjectType, AccessEffect, AccessOwner, Group, User as UserT, OrgNode, Role } from '@mxid/shared'
import { Field, Select, Button, Tag, ConfirmDialog } from '../../components/ui'
import { toast } from '../../components/ui/toast'

export default function AccessPolicyTab({
  owner = 'app',
  ownerId,
}: {
  owner?: AccessOwner
  ownerId: string
}) {
  const { t } = useTranslation()
  const [list, setList] = useState<AccessPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [delPolicy, setDelPolicy] = useState<AccessPolicy | null>(null)
  const [deleting, setDeleting] = useState(false)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const rows = await appAccessApi.list(owner, ownerId)
      setList(rows)
    } catch {
      toast.error(t('apps.access.addLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [owner, ownerId])

  useEffect(() => {
    reload()
  }, [reload])

  const confirmDelete = async () => {
    const p = delPolicy
    if (!p) return
    setDeleting(true)
    try {
      await appAccessApi.remove(owner, ownerId, p.id)
      setDelPolicy(null)
      toast.success(t("common.success"))
      reload()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t("common.failed"), msg)
    } finally {
      setDeleting(false)
    }
  }

  const isGroup = owner === 'app-group'

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="text-base font-semibold text-ink">{t('apps.access.title')}</h3>
          <p className="mt-0.5 text-sm text-muted">
            {isGroup ? t('apps.access.hintGroup') : t('apps.access.hintApp')}
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="h-4 w-4" />
          {t('apps.access.addPolicy')}
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-faint" />
        </div>
      ) : list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-red-200 bg-red-50 px-4 py-6 text-center">
          <ShieldOff className="mx-auto h-8 w-8 text-red-400" />
          <p className="mt-2 text-sm font-medium text-red-700">
            {isGroup ? t('apps.access.emptyGroup') : t('apps.access.emptyApp')}
          </p>
          <p className="text-xs text-red-500">{t('apps.access.mustAllow')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {list.map((p) => (
            <PolicyRow key={p.id} policy={p} onDelete={setDelPolicy} />
          ))}
        </div>
      )}

      {showAdd && (
        <AddPolicyModal
          owner={owner}
          ownerId={ownerId}
          onClose={() => setShowAdd(false)}
          onSaved={() => {
            setShowAdd(false)
            reload()
          }}
        />
      )}

      <ConfirmDialog
        open={!!delPolicy}
        title={t('apps.access.confirmDelete', { label: delPolicy ? policyLabel(delPolicy, t) : '' })}
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDelPolicy(null)}
      />
    </div>
  )
}

/* ──────────── Row ──────────── */

function PolicyRow({ policy, onDelete }: { policy: AccessPolicy; onDelete: (p: AccessPolicy) => void }) {
  const { t } = useTranslation()
  const Icon = SUBJECT_ICON[policy.subject_type]
  const isAllow = policy.effect === 'allow'
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-surface px-4 py-3">
      <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg', isAllow ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700')}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <Tag variant={isAllow ? 'green' : 'red'}>{isAllow ? t('apps.access.allow') : t('apps.access.deny')}</Tag>
          <span className="text-sm font-medium text-ink">{t(`apps.access.subjectLabel.${policy.subject_type}`)}</span>
          {policy.subject_type !== AccessPolicySubjectType.Public && (
            <span className="text-sm text-ink">
              {policy.subject_name || t('apps.access.subjectLabel.unknown')} <span className="text-xs text-faint font-mono">{policy.subject_code}</span>
            </span>
          )}
          {policy.subject_type === AccessPolicySubjectType.Public && (
            <span className="text-sm text-muted">{t('apps.access.subjectLabel.publicLong')}</span>
          )}
        </div>
      </div>
      <button
        onClick={() => onDelete(policy)}
        className="rounded-md p-1.5 text-faint hover:bg-red-50 hover:text-red-500"
        title={t('common.delete')}
      >
        <Trash2 className="h-4 w-4" />
      </button>
    </div>
  )
}

function policyLabel(p: AccessPolicy, t: (k: string) => string): string {
  if (p.subject_type === AccessPolicySubjectType.Public) return 'public'
  return `${t(`apps.access.subjectLabel.${p.subject_type}`)}:${p.subject_name || p.subject_id}`
}

const SUBJECT_ICON: Record<AccessSubjectType, typeof Globe2> = {
  public: Globe2,
  user: User,
  group: UsersRound,
  org: Building2,
  role: Crown,
}

/* ──────────── Add modal ──────────── */

function AddPolicyModal({
  owner,
  ownerId,
  onClose,
  onSaved,
}: {
  owner: AccessOwner
  ownerId: string
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [subjectType, setSubjectType] = useState<AccessSubjectType>(AccessPolicySubjectType.Group)
  const [subjectId, setSubjectId] = useState<string>('')
  const [effect, setEffect] = useState<AccessEffect>('allow')

  const [groups, setGroups] = useState<Group[]>([])
  const [users, setUsers] = useState<UserT[]>([])
  const [orgs, setOrgs] = useState<OrgNode[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [optsLoading, setOptsLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setSubjectId('')
    if (subjectType === AccessPolicySubjectType.Public) return
    setOptsLoading(true)
    const load = async () => {
      try {
        if (subjectType === AccessPolicySubjectType.Group) {
          const r = await groupApi.list({ page: 1, page_size: 200 })
          setGroups(r.items)
        } else if (subjectType === AccessPolicySubjectType.User) {
          const r = await userApi.list({ page: 1, page_size: 200 })
          setUsers(r.items)
        } else if (subjectType === AccessPolicySubjectType.Org) {
          const r = await orgApi.tree()
          const flat: OrgNode[] = []
          const walk = (nodes: OrgNode[]) => {
            for (const n of nodes) {
              flat.push(n)
              if (n.children) walk(n.children)
            }
          }
          walk(r)
          setOrgs(flat)
        } else if (subjectType === AccessPolicySubjectType.Role) {
          const r = await permissionApi.listRoles({ page: 1, page_size: 200 })
          setRoles(r.items)
        }
      } finally {
        setOptsLoading(false)
      }
    }
    load()
  }, [subjectType])

  const handleSave = async () => {
    if (subjectType !== AccessPolicySubjectType.Public && !subjectId) {
      toast.warning(t('apps.access.pleaseChooseSubject'))
      return
    }
    setSaving(true)
    try {
      await appAccessApi.create(owner, ownerId, { subject_type: subjectType, subject_id: subjectId || undefined, effect })
      toast.success(t('apps.access.added'))
      onSaved()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('apps.access.addFailed'), msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-xl bg-surface p-6 shadow-xl">
        <h3 className="mb-4 text-lg font-semibold">{t('apps.access.addModalTitle')}</h3>
        <div className="space-y-4">
          <Field label={t('apps.access.effect')}>
            <Select value={effect} onChange={(e) => setEffect(e.target.value as AccessEffect)}>
              <option value="allow">{t('apps.access.allowEffect')}</option>
              <option value="deny">{t('apps.access.denyEffect')}</option>
            </Select>
          </Field>

          <Field label={t('apps.access.subjectType')}>
            <Select value={subjectType} onChange={(e) => setSubjectType(e.target.value as AccessSubjectType)}>
              <option value="public">{t('apps.access.subjectTypes.public')}</option>
              <option value="user">{t('apps.access.subjectTypes.user')}</option>
              <option value="group">{t('apps.access.subjectTypes.group')}</option>
              <option value="org">{t('apps.access.subjectTypes.org')}</option>
              <option value="role">{t('apps.access.subjectTypes.role')}</option>
            </Select>
          </Field>

          {subjectType !== AccessPolicySubjectType.Public && (
            <Field label={t('apps.access.selectSubject')}>
              {optsLoading ? (
                <div className="flex h-10 items-center justify-center"><Loader2 className="h-4 w-4 animate-spin text-faint" /></div>
              ) : (
                <Select value={subjectId} onChange={(e) => setSubjectId(e.target.value)}>
                  <option value="">{t('apps.access.pleaseSelect')}</option>
                  {subjectType === AccessPolicySubjectType.Group && groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name} ({g.code})</option>)}
                  {subjectType === AccessPolicySubjectType.User && users.map((u) => <option key={String(u.id)} value={String(u.id)}>{u.display_name || u.username} ({u.username})</option>)}
                  {subjectType === AccessPolicySubjectType.Org && orgs.map((o) => <option key={String(o.id)} value={String(o.id)}>{o.name} ({o.code})</option>)}
                  {subjectType === AccessPolicySubjectType.Role && roles.map((r) => <option key={String(r.id)} value={String(r.id)}>{r.name} ({r.code})</option>)}
                </Select>
              )}
            </Field>
          )}
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={handleSave} disabled={saving}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            <ShieldCheck className="h-4 w-4" />
            {t('apps.access.addBtn')}
          </Button>
        </div>
      </div>
    </div>
  )
}
