// AccessEligibility — JIT privileged access eligibility policy config.
//
// Gated on the `conditional_access` EE feature at the page level (mirrors
// the pattern in access-approvals/index.tsx). The API itself also 403s in CE,
// so this is defence-in-depth.
import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  accessApprovalApi,
  appApi,
  appRoleApi,
  groupApi,
  orgApi,
  permissionApi,
  userApi,
  useTranslation,
  useEdition,
} from '@mxid/shared'
import type {
  Eligibility,
  CreateEligibilityBody,
  App,
  AppRole,
  Group,
  OrgNode,
  Role,
  User,
} from '@mxid/shared'
import { pageMotion, Button, Field, Select, ConfirmDialog } from '@mxid/shared/ui'
import { toast, extractMessage } from '../../components/ui/toast'

const ALL_DURATIONS = [3600, 14400, 86400, 259200, 604800] as const
const DURATION_LABELS: Record<number, string> = {
  3600: '1h',
  14400: '4h',
  86400: '24h',
  259200: '72h',
  604800: '7d',
}

const DEFAULT_FORM: CreateEligibilityBody = {
  target_kind: 'app',
  role_id: '',
  app_id: '',
  requester_subject_type: 'group',
  requester_subject_id: '',
  allowed_durations: [3600, 14400],
  max_duration_seconds: 86400,
  approver_subject_type: 'role',
  approver_subject_id: '',
  require_justification: false,
  require_stepup: false,
}

export default function AccessEligibilityPage() {
  const { t } = useTranslation()
  const edition = useEdition()
  const [rows, setRows] = useState<Eligibility[]>([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState<CreateEligibilityBody>(DEFAULT_FORM)
  // Non-null while editing an existing row — the same form section below is
  // reused for both create and edit; submit() branches on this id.
  const [editingId, setEditingId] = useState<string | null>(null)
  const [delId, setDelId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  // Option lists for the dropdown pickers below. Each is fetched lazily,
  // only once the form actually needs it, and cached for the session.
  const [consoleRoles, setConsoleRoles] = useState<Role[]>([])
  const [consoleRolesLoading, setConsoleRolesLoading] = useState(false)
  const [apps, setApps] = useState<App[]>([])
  const [appsLoading, setAppsLoading] = useState(false)
  const [appRoles, setAppRoles] = useState<AppRole[]>([])
  const [appRolesLoading, setAppRolesLoading] = useState(false)
  const [groups, setGroups] = useState<Group[]>([])
  const [groupsLoading, setGroupsLoading] = useState(false)
  const [orgs, setOrgs] = useState<OrgNode[]>([])
  const [orgsLoading, setOrgsLoading] = useState(false)
  const [users, setUsers] = useState<User[]>([])
  const [usersLoading, setUsersLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setRows((await accessApprovalApi.listEligibilities()) ?? [])
    } catch (e) {
      toast.error(t('eligibility.loadFailed'), extractMessage(e))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    void load()
  }, [load])

  // Console RBAC roles — needed for the `console` target's role_id picker
  // AND for the approver picker when approver_subject_type === 'role'.
  useEffect(() => {
    const need = form.target_kind === 'console' || form.approver_subject_type === 'role'
    if (!need || consoleRoles.length > 0 || consoleRolesLoading) return
    setConsoleRolesLoading(true)
    permissionApi
      .listRoles({ page: 1, page_size: 200 })
      .then((d) => setConsoleRoles(d.items))
      .catch(() => toast.error(t('eligibility.loadOptionsFailed')))
      .finally(() => setConsoleRolesLoading(false))
  }, [form.target_kind, form.approver_subject_type, consoleRoles.length, consoleRolesLoading, t])

  // Apps — needed for the `app` target's app_id picker.
  useEffect(() => {
    if (form.target_kind !== 'app' || apps.length > 0 || appsLoading) return
    setAppsLoading(true)
    appApi
      .list({ page: 1, page_size: 200 })
      .then((d) => setApps(d.items))
      .catch(() => toast.error(t('eligibility.loadOptionsFailed')))
      .finally(() => setAppsLoading(false))
  }, [form.target_kind, apps.length, appsLoading, t])

  // App roles — cascades off the selected app_id. Re-fetched whenever
  // app_id changes; cleared when no app is selected.
  useEffect(() => {
    if (form.target_kind !== 'app' || !form.app_id) {
      setAppRoles([])
      return
    }
    let cancelled = false
    setAppRolesLoading(true)
    appRoleApi
      .listRoles('app', form.app_id)
      .then((d) => {
        if (!cancelled) setAppRoles(d)
      })
      .catch(() => {
        if (!cancelled) toast.error(t('eligibility.loadOptionsFailed'))
      })
      .finally(() => {
        if (!cancelled) setAppRolesLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [form.target_kind, form.app_id, t])

  // User groups — needed when requester or approver subject type is `group`.
  useEffect(() => {
    const need = form.requester_subject_type === 'group' || form.approver_subject_type === 'group'
    if (!need || groups.length > 0 || groupsLoading) return
    setGroupsLoading(true)
    groupApi
      .list({ page: 1, page_size: 200 })
      .then((d) => setGroups(d.items))
      .catch(() => toast.error(t('eligibility.loadOptionsFailed')))
      .finally(() => setGroupsLoading(false))
  }, [form.requester_subject_type, form.approver_subject_type, groups.length, groupsLoading, t])

  // Orgs — needed when requester subject type is `org`. Flatten the tree
  // since the picker just needs a flat name/id list.
  useEffect(() => {
    if (form.requester_subject_type !== 'org' || orgs.length > 0 || orgsLoading) return
    setOrgsLoading(true)
    orgApi
      .tree()
      .then((tree) => {
        const flat: OrgNode[] = []
        const walk = (nodes: OrgNode[]) => {
          for (const n of nodes) {
            flat.push(n)
            if (n.children) walk(n.children)
          }
        }
        walk(tree)
        setOrgs(flat)
      })
      .catch(() => toast.error(t('eligibility.loadOptionsFailed')))
      .finally(() => setOrgsLoading(false))
  }, [form.requester_subject_type, orgs.length, orgsLoading, t])

  // Users — needed when requester or approver subject type is `user`.
  // Note: this loads a single page of up to 200 users; for tenants with
  // more users than that, a real search-select would be needed.
  useEffect(() => {
    const need = form.requester_subject_type === 'user' || form.approver_subject_type === 'user'
    if (!need || users.length > 0 || usersLoading) return
    setUsersLoading(true)
    userApi
      .list({ page: 1, page_size: 200 })
      .then((d) => setUsers(d.items))
      .catch(() => toast.error(t('eligibility.loadOptionsFailed')))
      .finally(() => setUsersLoading(false))
  }, [form.requester_subject_type, form.approver_subject_type, users.length, usersLoading, t])

  const toggleDuration = (d: number) =>
    setForm((f) => ({
      ...f,
      allowed_durations: f.allowed_durations.includes(d)
        ? f.allowed_durations.filter((x) => x !== d)
        : [...f.allowed_durations, d],
    }))

  // startEdit pre-fills the (shared) form from an existing row and drives
  // the cascading pickers (target_kind -> role/app, subject types -> subject
  // lists) exactly like a fresh selection would, since they all key off
  // `form` state via the useEffect option-loaders above.
  const startEdit = (row: Eligibility) => {
    setEditingId(row.id)
    setForm({
      target_kind: row.target_kind,
      role_id: row.role_id,
      app_id: row.target_kind === 'app' ? row.app_id : undefined,
      requester_subject_type: row.requester_subject_type,
      requester_subject_id: row.requester_subject_id,
      allowed_durations: row.allowed_durations,
      max_duration_seconds: row.max_duration_seconds,
      approver_subject_type: row.approver_subject_type,
      approver_subject_id: row.approver_subject_id,
      require_justification: row.require_justification,
      require_stepup: row.require_stepup,
    })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const cancelEdit = () => {
    setEditingId(null)
    setForm(DEFAULT_FORM)
  }

  const submit = async () => {
    if (form.target_kind === 'app' && !form.app_id) {
      toast.error(t('eligibility.createFailed'), t('eligibility.appIdRequired'))
      return
    }
    if (!form.role_id.trim()) {
      toast.error(t('eligibility.createFailed'), t('eligibility.roleIdRequired'))
      return
    }
    // A concrete requester/approver subject is required unless the subject type
    // is "any" (requester) or "auto" (approver) — otherwise the backend gets an
    // empty ,string int64 and rejects with a raw unmarshal error.
    if (form.requester_subject_type !== 'any' && !(form.requester_subject_id ?? '').trim()) {
      toast.error(t('eligibility.createFailed'), t('eligibility.requesterRequired'))
      return
    }
    if (form.approver_subject_type !== 'auto' && !(form.approver_subject_id ?? '').trim()) {
      toast.error(t('eligibility.createFailed'), t('eligibility.approverRequired'))
      return
    }
    try {
      const body: CreateEligibilityBody = {
        ...form,
        // omit app_id when target is console
        app_id: form.target_kind === 'app' ? form.app_id : undefined,
        // omit the id fields when there's no concrete subject, so we never send
        // an empty string into a ,string-tagged int64 on the backend.
        requester_subject_id: form.requester_subject_type === 'any' ? undefined : form.requester_subject_id,
        approver_subject_id: form.approver_subject_type === 'auto' ? undefined : form.approver_subject_id,
      }
      if (editingId) {
        await accessApprovalApi.updateEligibility(editingId, body)
        toast.success(t('eligibility.updated'))
      } else {
        await accessApprovalApi.createEligibility(body)
        toast.success(t('eligibility.created'))
      }
      setEditingId(null)
      setForm(DEFAULT_FORM)
      void load()
    } catch (e) {
      toast.error(
        editingId ? t('eligibility.updateFailed') : t('eligibility.createFailed'),
        extractMessage(e),
      )
    }
  }

  const confirmRemove = async () => {
    const id = delId
    if (!id) return
    setDeleting(true)
    try {
      await accessApprovalApi.deleteEligibility(id)
      setDelId(null)
      toast.success(t('eligibility.deleted'))
      void load()
    } catch (e) {
      toast.error(t('eligibility.deleteFailed'), extractMessage(e))
    } finally {
      setDeleting(false)
    }
  }

  if (!edition.has('conditional_access')) {
    return (
      <motion.div {...pageMotion} className="p-6">
        <p className="text-gray-500">{t('eligibility.featureDisabled')}</p>
      </motion.div>
    )
  }

  return (
    <motion.div {...pageMotion} className="space-y-6">
      {/* Create / edit form — reused for both via editingId */}
      <section className="rounded-xl border border-gray-200 bg-white p-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-gray-900">
            {editingId ? t('eligibility.editTitle') : t('eligibility.createTitle')}
          </h2>
          <p className="mt-0.5 text-sm text-gray-500">
            {editingId ? t('eligibility.editDesc') : t('eligibility.createDesc')}
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={t('eligibility.targetKind')}>
            <select
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
              value={form.target_kind}
              onChange={(e) => {
                const value = e.target.value as 'console' | 'app'
                setForm((f) => ({
                  ...f,
                  target_kind: value,
                  role_id: '',
                  app_id: value === 'app' ? (f.app_id ?? '') : undefined,
                }))
              }}
            >
              <option value="app">{t('access.targetApp')}</option>
              <option value="console">{t('access.targetConsole')}</option>
            </select>
          </Field>

          {form.target_kind === 'console' ? (
            <Field label={t('eligibility.roleId')}>
              <Select
                value={form.role_id}
                disabled={consoleRolesLoading}
                onChange={(e) => setForm((f) => ({ ...f, role_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {consoleRoles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.code})
                  </option>
                ))}
              </Select>
            </Field>
          ) : (
            <Field label={t('eligibility.appId')}>
              <Select
                value={form.app_id ?? ''}
                disabled={appsLoading}
                onChange={(e) =>
                  setForm((f) => ({ ...f, app_id: e.target.value, role_id: '' }))
                }
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {apps.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.code})
                  </option>
                ))}
              </Select>
            </Field>
          )}

          {form.target_kind === 'app' && (
            <Field label={t('eligibility.roleId')}>
              <Select
                value={form.role_id}
                disabled={!form.app_id || appRolesLoading}
                onChange={(e) => setForm((f) => ({ ...f, role_id: e.target.value }))}
              >
                <option value="">
                  {form.app_id ? t('eligibility.pleaseSelect') : t('eligibility.selectAppFirst')}
                </option>
                {appRoles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.code})
                  </option>
                ))}
              </Select>
            </Field>
          )}

          <Field label={t('eligibility.requesterSubjectType')}>
            <Select
              value={form.requester_subject_type}
              onChange={(e) => {
                const value = e.target.value as CreateEligibilityBody['requester_subject_type']
                setForm((f) => ({ ...f, requester_subject_type: value, requester_subject_id: '' }))
              }}
            >
              <option value="any">{t('eligibility.requesterSubjectTypes.any')}</option>
              <option value="user">{t('eligibility.requesterSubjectTypes.user')}</option>
              <option value="group">{t('eligibility.requesterSubjectTypes.group')}</option>
              <option value="org">{t('eligibility.requesterSubjectTypes.org')}</option>
            </Select>
          </Field>

          <Field
            label={t('eligibility.requesterSubjectId')}
            hint={form.requester_subject_type === 'any' ? t('eligibility.requesterAnyHint') : undefined}
          >
            {form.requester_subject_type === 'any' ? (
              <Select value="" disabled>
                <option value="">{t('eligibility.requesterAnyHint')}</option>
              </Select>
            ) : form.requester_subject_type === 'group' ? (
              <Select
                value={form.requester_subject_id ?? ''}
                disabled={groupsLoading}
                onChange={(e) => setForm((f) => ({ ...f, requester_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({g.code})
                  </option>
                ))}
              </Select>
            ) : form.requester_subject_type === 'org' ? (
              <Select
                value={form.requester_subject_id ?? ''}
                disabled={orgsLoading}
                onChange={(e) => setForm((f) => ({ ...f, requester_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} ({o.code})
                  </option>
                ))}
              </Select>
            ) : (
              <Select
                value={form.requester_subject_id ?? ''}
                disabled={usersLoading}
                onChange={(e) => setForm((f) => ({ ...f, requester_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name || u.username} ({u.username})
                  </option>
                ))}
              </Select>
            )}
          </Field>

          <Field label={t('eligibility.approverSubjectType')}>
            <Select
              value={form.approver_subject_type}
              onChange={(e) => {
                const value = e.target.value as CreateEligibilityBody['approver_subject_type']
                setForm((f) => ({ ...f, approver_subject_type: value, approver_subject_id: '' }))
              }}
            >
              <option value="role">{t('eligibility.approverSubjectTypes.role')}</option>
              <option value="group">{t('eligibility.approverSubjectTypes.group')}</option>
              <option value="user">{t('eligibility.approverSubjectTypes.user')}</option>
              <option value="auto">{t('eligibility.approverSubjectTypes.auto')}</option>
            </Select>
          </Field>

          <Field
            label={t('eligibility.approverSubjectId')}
            hint={form.approver_subject_type === 'auto' ? t('eligibility.approverAutoHint') : undefined}
          >
            {form.approver_subject_type === 'auto' ? (
              <Select value="" disabled>
                <option value="">{t('eligibility.approverAutoHint')}</option>
              </Select>
            ) : form.approver_subject_type === 'role' ? (
              <Select
                value={form.approver_subject_id ?? ''}
                disabled={consoleRolesLoading}
                onChange={(e) => setForm((f) => ({ ...f, approver_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {consoleRoles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.code})
                  </option>
                ))}
              </Select>
            ) : form.approver_subject_type === 'group' ? (
              <Select
                value={form.approver_subject_id ?? ''}
                disabled={groupsLoading}
                onChange={(e) => setForm((f) => ({ ...f, approver_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({g.code})
                  </option>
                ))}
              </Select>
            ) : (
              <Select
                value={form.approver_subject_id ?? ''}
                disabled={usersLoading}
                onChange={(e) => setForm((f) => ({ ...f, approver_subject_id: e.target.value }))}
              >
                <option value="">{t('eligibility.pleaseSelect')}</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name || u.username} ({u.username})
                  </option>
                ))}
              </Select>
            )}
          </Field>

          <Field label={t('eligibility.maxDuration')}>
            <select
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
              value={form.max_duration_seconds}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  max_duration_seconds: Number(e.target.value),
                }))
              }
            >
              {ALL_DURATIONS.map((d) => (
                <option key={d} value={d}>
                  {DURATION_LABELS[d]}
                </option>
              ))}
            </select>
          </Field>

          <div className="md:col-span-2">
            <div className="mb-1.5 text-sm font-medium text-gray-700">
              {t('eligibility.allowedDurations')}
            </div>
            <div className="flex flex-wrap gap-4">
              {ALL_DURATIONS.map((d) => (
                <label key={d} className="flex cursor-pointer items-center gap-1.5 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-gray-300"
                    checked={form.allowed_durations.includes(d)}
                    onChange={() => toggleDuration(d)}
                  />
                  {DURATION_LABELS[d]}
                </label>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap gap-6 md:col-span-2">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300"
                checked={form.require_justification ?? false}
                onChange={(e) =>
                  setForm((f) => ({ ...f, require_justification: e.target.checked }))
                }
              />
              {t('eligibility.requireJustification')}
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300"
                checked={form.require_stepup ?? false}
                onChange={(e) =>
                  setForm((f) => ({ ...f, require_stepup: e.target.checked }))
                }
              />
              {t('eligibility.requireStepup')}
            </label>
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          {editingId && (
            <Button variant="secondary" onClick={cancelEdit}>
              {t('eligibility.cancelEdit')}
            </Button>
          )}
          <Button onClick={submit}>
            {editingId ? t('eligibility.update') : t('eligibility.create')}
          </Button>
        </div>
      </section>

      {/* Eligibility list */}
      <section className="rounded-xl border border-gray-200 bg-white">
        <div className="border-b border-gray-100 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">{t('eligibility.listTitle')}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('eligibility.columns.target')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.role')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.requester')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.approver')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.durations')}</th>
                <th className="px-6 py-3 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('eligibility.empty')}
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.id} className="hover:bg-gray-50/50">
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-700">
                      {row.target_kind === 'console'
                        ? t('access.targetConsole')
                        : t('access.targetApp')}
                      {row.target_kind === 'app' && row.app_id && (
                        <span className="ml-1 text-gray-400">
                          ({row.app_name || row.app_id})
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {row.target_name || row.role_id}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {row.requester_subject_type === 'any'
                        ? t('eligibility.everyone')
                        : row.requester_subject_name || row.requester_subject_id || '—'}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {row.approver_subject_type === 'auto'
                        ? t('eligibility.autoApprover')
                        : row.approver_subject_name || row.approver_subject_id || '—'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-600">
                      {row.allowed_durations
                        .map((d) => DURATION_LABELS[d] ?? `${d}s`)
                        .join(' / ')}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => startEdit(row)}
                        >
                          {t('common.edit')}
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => setDelId(row.id)}
                        >
                          {t('common.delete')}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <ConfirmDialog
        open={!!delId}
        title={t('eligibility.confirmDelete')}
        desc={t('common.cantUndo')}
        loading={deleting}
        onConfirm={confirmRemove}
        onCancel={() => setDelId(null)}
      />
    </motion.div>
  )
}
