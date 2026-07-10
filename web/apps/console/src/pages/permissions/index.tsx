import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Plus, Shield, Check, Loader2, Trash2, Users, UserPlus } from 'lucide-react'
import { permissionApi, formatDate, cn, useTranslation } from '@mxid/shared'
import { pageMotion, Button, Modal, ConfirmDialog } from '@mxid/shared/ui'
import type { Role, Permission, PaginatedData, RoleBinding } from '@mxid/shared'
import { RoleType, BindingSubjectType, BindingScopeType } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { useTabParam } from '../../hooks/useTabParam'
import { toast, extractMessage } from '../../components/ui/toast'
import SubjectPicker from '../../components/SubjectPicker'

// Reserved code of the built-in super-admin role. Its power lives on the user's
// is_super_admin flag (toggled via 用户 → 设为超级管理员), NOT role membership —
// so the console blocks assigning members here to avoid the "added to Superadmin
// but still 403" trap. Keep in sync with permission.SuperAdminRoleCode (backend).
const SUPER_ADMIN_ROLE_CODE = 'super_admin'

const DETAIL_TAB_VALUES = ['permissions', 'members'] as const

type DetailTab = 'permissions' | 'members'
type SubjectType = 'user' | 'group' | 'org'

const SUBJECT_TYPES: SubjectType[] = ['user', 'group', 'org']

export default function PermissionsPage() {
  const { t } = useTranslation()
  const subjectTypeLabels: Record<SubjectType, string> = {
    user: t('permissions.subjectTypes.user'),
    group: t('permissions.subjectTypes.group'),
    org: t('permissions.subjectTypes.org'),
  }
  const [roles, setRoles] = useState<PaginatedData<Role>>({ items: [], total: 0, page: 1, page_size: 50 })
  const [allPermissions, setAllPermissions] = useState<Permission[]>([])
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)
  const [rolePermissions, setRolePermissions] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  // Tab state — persisted to URL so refresh/share preserves selection
  const [activeTab, setActiveTab] = useTabParam<DetailTab>('tab', 'permissions', DETAIL_TAB_VALUES)

  // Members state
  const [members, setMembers] = useState<PaginatedData<RoleBinding>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [membersLoading, setMembersLoading] = useState(false)
  const [removingMemberId, setRemovingMemberId] = useState<string | null>(null)
  const [delRole, setDelRole] = useState<Role | null>(null)
  const [deletingRole, setDeletingRole] = useState(false)
  const [delBinding, setDelBinding] = useState<RoleBinding | null>(null)

  // Add member modal
  const [showAddMember, setShowAddMember] = useState(false)
  const [addMemberForm, setAddMemberForm] = useState<{
    subject_type: SubjectType
    subject_id: string
    subject_label: string
    scope_type: '' | 'org' | 'group'
    scope_id: string
  }>({
    subject_type: 'user',
    subject_id: '',
    subject_label: '',
    scope_type: '',
    scope_id: '',
  })
  const [addingMember, setAddingMember] = useState(false)

  // Create modal
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ name: '', code: '', description: '' })
  const [creating, setCreating] = useState(false)

  const loadRoles = useCallback(async () => {
    setLoading(true)
    try {
      const [rolesData, permsData] = await Promise.all([
        permissionApi.listRoles({ page: 1, page_size: 50 }),
        permissionApi.listPermissions(),
      ])
      setRoles(rolesData)
      setAllPermissions(permsData)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRoles()
  }, [loadRoles])

  const loadMembers = useCallback(async (roleId: string, page = 1) => {
    setMembersLoading(true)
    try {
      const data = await permissionApi.listMembers(roleId, { page, page_size: 20 })
      setMembers(data)
    } catch {
      setMembers({ items: [], total: 0, page: 1, page_size: 20 })
    } finally {
      setMembersLoading(false)
    }
  }, [])

  const handleSelectRole = async (role: Role) => {
    setSelectedRole(role)
    setActiveTab('permissions')
    try {
      const perms = await permissionApi.getRolePermissions(role.id)
      setRolePermissions(perms.map((p) => p.id))
    } catch {
      setRolePermissions([])
    }
  }

  const handleTabChange = (tab: DetailTab) => {
    setActiveTab(tab)
    if (tab === 'members' && selectedRole) {
      loadMembers(selectedRole.id)
    }
  }

  const togglePermission = (permId: string) => {
    setRolePermissions((prev) =>
      prev.includes(permId) ? prev.filter((id) => id !== permId) : [...prev, permId]
    )
  }

  const handleSavePermissions = async () => {
    if (!selectedRole) return
    setSaving(true)
    try {
      await permissionApi.setRolePermissions(selectedRole.id, rolePermissions)
      toast.success(t('permissions.saved'))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createForm.name || !createForm.code) return
    setCreating(true)
    try {
      await permissionApi.createRole({
        name: createForm.name,
        code: createForm.code,
        description: createForm.description || undefined,
      })
      setShowCreate(false)
      setCreateForm({ name: '', code: '', description: '' })
      loadRoles()
      toast.success(t('permissions.roleCreated'))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setCreating(false)
    }
  }

  const confirmDeleteRole = async () => {
    const role = delRole
    if (!role || role.type === RoleType.System) return
    setDeletingRole(true)
    try {
      await permissionApi.deleteRole(role.id)
      if (selectedRole?.id === role.id) {
        setSelectedRole(null)
        setRolePermissions([])
        setMembers({ items: [], total: 0, page: 1, page_size: 20 })
      }
      setDelRole(null)
      loadRoles()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setDeletingRole(false)
    }
  }

  // Reset the form and open the add-member modal. The super_admin role only
  // accepts user subjects (it's a façade over the per-user is_super_admin flag),
  // so default the subject type to user there.
  const openAddMember = () => {
    setAddMemberForm({ subject_type: 'user', subject_id: '', subject_label: '', scope_type: '', scope_id: '' })
    setShowAddMember(true)
  }

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedRole || !addMemberForm.subject_id) return
    const subjectIdNum = Number(addMemberForm.subject_id)
    if (isNaN(subjectIdNum) || subjectIdNum <= 0) return
    if (addMemberForm.scope_type && !addMemberForm.scope_id) {
      alert(t('permissions.scopeRequired'))
      return
    }
    setAddingMember(true)
    try {
      const body: Record<string, unknown> = {
        subject_type: addMemberForm.subject_type,
        subject_id: addMemberForm.subject_id,
      }
      if (addMemberForm.scope_type && addMemberForm.scope_id) {
        body.scope_type = addMemberForm.scope_type
        body.scope_id = addMemberForm.scope_id
      }
      await permissionApi.addMember(selectedRole.id, body as Parameters<typeof permissionApi.addMember>[1])
      setShowAddMember(false)
      setAddMemberForm({ subject_type: 'user', subject_id: '', subject_label: '', scope_type: '', scope_id: '' })
      loadMembers(selectedRole.id, members.page)
      loadRoles()
      toast.success(t('permissions.memberAdded'))
    } catch (e) {
      toast.error(t('permissions.addMemberFailed'), extractMessage(e))
    } finally {
      setAddingMember(false)
    }
  }

  const confirmRemoveMember = async () => {
    const binding = delBinding
    if (!selectedRole || !binding) return
    setRemovingMemberId(binding.id)
    try {
      await permissionApi.removeMember(selectedRole.id, binding.id)
      setDelBinding(null)
      loadMembers(selectedRole.id, members.page)
      loadRoles()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setRemovingMemberId(null)
    }
  }

  // Group permissions by resource
  const groupedPermissions = allPermissions.reduce<Record<string, Permission[]>>((acc, perm) => {
    const key = perm.resource
    if (!acc[key]) acc[key] = []
    acc[key].push(perm)
    return acc
  }, {})

  const totalMemberPages = Math.max(1, Math.ceil(members.total / members.page_size))
  const isSuperAdminRole = selectedRole?.code === SUPER_ADMIN_ROLE_CODE

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('permissions.title')}
        description={t('permissions.subtitle')}
        actions={
          <Button onClick={() => setShowCreate(true)} icon={<Plus className="h-4 w-4" />}>
            {t('permissions.createRole')}
          </Button>
        }
      />

      <div className="flex gap-6">
        {/* Roles list */}
        <div className="w-72 shrink-0 rounded-xl border border-border bg-surface shadow-sm">
          <div className="border-b border-border px-4 py-3">
            <h3 className="text-sm font-semibold text-ink">{t('permissions.rolesList')}</h3>
          </div>
          <div className="p-2">
            {loading ? (
              <p className="py-8 text-center text-sm text-faint">{t('common.loading')}</p>
            ) : roles.items.length === 0 ? (
              <p className="py-8 text-center text-sm text-faint">{t('permissions.emptyRoles')}</p>
            ) : (
              <div className="space-y-1">
                {roles.items.map((role) => (
                  <button
                    key={role.id}
                    onClick={() => handleSelectRole(role)}
                    className={cn(
                      'flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm transition-colors',
                      selectedRole?.id === role.id
                        ? 'bg-primary/10 text-primary font-medium'
                        : 'text-ink hover:bg-surface-muted'
                    )}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Shield className="h-4 w-4 shrink-0 text-faint" />
                      <div className="min-w-0">
                        <p className="truncate">{role.name}</p>
                        <p className="truncate text-xs text-faint">
                          {role.code}
                          {role.member_count > 0 && (
                            <span className="ml-1.5">
                              · {role.member_count} {t('permissions.memberCountSuffix')}
                            </span>
                          )}
                        </p>
                      </div>
                    </div>
                    {role.type === RoleType.System && (
                      <span className="ml-2 shrink-0 rounded bg-surface-muted px-1.5 py-0.5 text-[10px] text-muted">
                        {t('permissions.systemTag')}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Role detail panel */}
        <div className="flex-1 rounded-xl border border-border bg-surface shadow-sm">
          {selectedRole ? (
            <div>
              {/* Header */}
              <div className="flex items-center justify-between border-b border-border px-6 py-4">
                <div>
                  <h3 className="text-lg font-semibold text-ink">{selectedRole.name}</h3>
                  <p className="text-sm text-muted">
                    {selectedRole.description || t('permissions.noDescription')} &middot; {t('permissions.createdAtPrefix', { date: formatDate(selectedRole.created_at) })}
                    {selectedRole.member_count > 0 && (
                      <span> &middot; {t('permissions.memberCountFragment', { count: selectedRole.member_count })}</span>
                    )}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {selectedRole.type !== RoleType.System && (
                    <button
                      onClick={() => setDelRole(selectedRole)}
                      className="rounded-lg border border-border px-3 py-1.5 text-sm text-red-500 hover:bg-red-50"
                    >
                      {t('permissions.deleteRole')}
                    </button>
                  )}
                  {activeTab === 'permissions' && (
                    <button
                      onClick={handleSavePermissions}
                      disabled={saving}
                      className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
                    >
                      {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                      {t('permissions.savePermissions')}
                    </button>
                  )}
                  {activeTab === 'members' && (
                    <button
                      onClick={() => openAddMember()}
                      className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
                    >
                      <UserPlus className="h-4 w-4" />
                      {t('permissions.addMember')}
                    </button>
                  )}
                </div>
              </div>

              {/* Tabs */}
              <div className="flex border-b border-border px-6">
                <button
                  onClick={() => handleTabChange('permissions')}
                  className={cn(
                    'relative px-4 py-3 text-sm font-medium transition-colors',
                    activeTab === 'permissions'
                      ? 'text-primary'
                      : 'text-muted hover:text-ink'
                  )}
                >
                  {t('permissions.tabPermissions')}
                  {activeTab === 'permissions' && (
                    <motion.div
                      layoutId="tab-indicator"
                      className="absolute inset-x-0 bottom-0 h-0.5 bg-primary"
                    />
                  )}
                </button>
                <button
                  onClick={() => handleTabChange('members')}
                  className={cn(
                    'relative px-4 py-3 text-sm font-medium transition-colors',
                    activeTab === 'members'
                      ? 'text-primary'
                      : 'text-muted hover:text-ink'
                  )}
                >
                  <span className="inline-flex items-center gap-1.5">
                    {t('permissions.tabMembers')}
                    {selectedRole.member_count > 0 && (
                      <span className={cn(
                        'inline-flex h-5 min-w-[20px] items-center justify-center rounded-full px-1.5 text-[11px] font-medium',
                        activeTab === 'members'
                          ? 'bg-primary/10 text-primary'
                          : 'bg-surface-muted text-muted'
                      )}>
                        {selectedRole.member_count}
                      </span>
                    )}
                  </span>
                  {activeTab === 'members' && (
                    <motion.div
                      layoutId="tab-indicator"
                      className="absolute inset-x-0 bottom-0 h-0.5 bg-primary"
                    />
                  )}
                </button>
              </div>

              {/* Tab content */}
              {activeTab === 'permissions' && (
                <div className="p-6">
                  {allPermissions.length === 0 ? (
                    <p className="py-8 text-center text-sm text-faint">{t('permissions.emptyPermissions')}</p>
                  ) : (
                    <div className="space-y-6">
                      {Object.entries(groupedPermissions).map(([resource, perms]) => (
                        <div key={resource}>
                          <h4 className="mb-3 text-sm font-semibold text-ink uppercase tracking-wide">
                            {resource}
                          </h4>
                          <div className="grid grid-cols-2 gap-2 lg:grid-cols-3">
                            {perms.map((perm) => {
                              const checked = rolePermissions.includes(perm.id)
                              return (
                                <button
                                  key={perm.id}
                                  onClick={() => togglePermission(perm.id)}
                                  className={cn(
                                    'flex items-center gap-2.5 rounded-lg border px-3 py-2 text-left text-sm transition-colors',
                                    checked
                                      ? 'border-primary/30 bg-primary/5 text-primary'
                                      : 'border-border text-muted hover:bg-surface-muted'
                                  )}
                                >
                                  <div
                                    className={cn(
                                      'flex h-4 w-4 shrink-0 items-center justify-center rounded border',
                                      checked
                                        ? 'border-primary bg-primary text-white'
                                        : 'border-border'
                                    )}
                                  >
                                    {checked && <Check className="h-3 w-3" />}
                                  </div>
                                  <div className="min-w-0">
                                    <p className="truncate font-medium">{perm.name}</p>
                                    <p className="truncate text-xs text-faint">
                                      {perm.action}
                                    </p>
                                  </div>
                                </button>
                              )
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'members' && (
                <div className="p-6">
                  {membersLoading ? (
                    <div className="flex items-center justify-center py-12">
                      <Loader2 className="h-5 w-5 animate-spin text-faint" />
                      <span className="ml-2 text-sm text-faint">{t('common.loading')}</span>
                    </div>
                  ) : members.items.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12">
                      <Users className="h-10 w-10 text-faint" />
                      <p className="mt-3 text-sm text-faint">{t('permissions.emptyMembers')}</p>
                      <button
                        onClick={() => openAddMember()}
                        className="mt-4 inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted hover:bg-surface-muted"
                      >
                        <UserPlus className="h-4 w-4" />
                        {t('permissions.addMember')}
                      </button>
                    </div>
                  ) : (
                    <div>
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-border text-left text-xs font-medium uppercase tracking-wider text-muted">
                            <th className="pb-3 pr-4">{t('permissions.columns.subjectType')}</th>
                            <th className="pb-3 pr-4">{t('permissions.columns.subjectId')}</th>
                            <th className="pb-3 pr-4">{t('permissions.columns.scope')}</th>
                            <th className="pb-3 pr-4">{t('permissions.columns.boundAt')}</th>
                            <th className="pb-3 w-16">{t('permissions.columns.actions')}</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {members.items.map((binding) => (
                            <tr key={binding.id} className="group">
                              <td className="py-3 pr-4">
                                <span className={cn(
                                  'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium',
                                  binding.subject_type === BindingSubjectType.User && 'bg-blue-50 text-blue-700',
                                  binding.subject_type === BindingSubjectType.Group && 'bg-emerald-50 text-emerald-700',
                                  binding.subject_type === BindingSubjectType.Org && 'bg-purple-50 text-purple-700',
                                )}>
                                  {subjectTypeLabels[binding.subject_type as SubjectType] || binding.subject_type}
                                </span>
                              </td>
                              <td className="py-3 pr-4 text-sm text-ink">
                                <div className="min-w-0">
                                  <p className="truncate font-medium">{binding.subject_name || binding.subject_id}</p>
                                  <p className="truncate text-xs text-faint">
                                    {binding.subject_secondary ? `${binding.subject_secondary} · #${binding.subject_id}` : `#${binding.subject_id}`}
                                  </p>
                                </div>
                              </td>
                              <td className="py-3 pr-4 text-sm">
                                {binding.scope_type ? (
                                  <span className="inline-flex items-center rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700">
                                    {binding.scope_type === BindingScopeType.Org ? t('permissions.scopeOrg') : t('permissions.scopeGroup')} #{binding.scope_id}
                                  </span>
                                ) : (
                                  <span className="text-xs text-faint">{t('permissions.scopeGlobal')}</span>
                                )}
                              </td>
                              <td className="py-3 pr-4 text-sm text-muted">
                                {formatDate(binding.created_at)}
                              </td>
                              <td className="py-3 w-16">
                                <button
                                  onClick={() => setDelBinding(binding)}
                                  disabled={removingMemberId === binding.id}
                                  className="inline-flex items-center rounded-md p-1 text-faint opacity-0 transition-all hover:bg-red-50 hover:text-red-500 group-hover:opacity-100 disabled:opacity-50"
                                  title={t('permissions.removeMember')}
                                >
                                  {removingMemberId === binding.id ? (
                                    <Loader2 className="h-4 w-4 animate-spin" />
                                  ) : (
                                    <Trash2 className="h-4 w-4" />
                                  )}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>

                      {/* Pagination */}
                      {totalMemberPages > 1 && (
                        <div className="mt-4 flex items-center justify-between border-t border-border pt-4">
                          <p className="text-xs text-muted">
                            {t('permissions.totalRecords', { total: members.total })}
                          </p>
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => selectedRole && loadMembers(selectedRole.id, members.page - 1)}
                              disabled={members.page <= 1}
                              className="rounded-md border border-border px-2.5 py-1 text-xs text-muted hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {t('permissions.prevPage')}
                            </button>
                            <span className="px-2 text-xs text-muted">
                              {members.page} / {totalMemberPages}
                            </span>
                            <button
                              onClick={() => selectedRole && loadMembers(selectedRole.id, members.page + 1)}
                              disabled={members.page >= totalMemberPages}
                              className="rounded-md border border-border px-2.5 py-1 text-xs text-muted hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {t('permissions.nextPage')}
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-64 items-center justify-center text-sm text-faint">
              {t('permissions.selectRoleHint')}
            </div>
          )}
        </div>
      </div>

      {/* Create Role Modal */}
      {showCreate && (
        <Modal open title={t('permissions.createRoleModal.title')} onClose={() => setShowCreate(false)} size="md">
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('permissions.createRoleModal.nameRequired')}</label>
                <input
                  type="text"
                  value={createForm.name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('permissions.createRoleModal.codeRequired')}</label>
                <input
                  type="text"
                  value={createForm.code}
                  onChange={(e) => setCreateForm((f) => ({ ...f, code: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('permissions.createRoleModal.description')}</label>
                <textarea
                  value={createForm.description}
                  onChange={(e) => setCreateForm((f) => ({ ...f, description: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  rows={3}
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowCreate(false)}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={creating}>
                  {t('permissions.createRoleModal.createBtn')}
                </Button>
              </div>
            </form>
        </Modal>
      )}

      {/* Add Member Modal */}
      {showAddMember && selectedRole && (
        <Modal open title={t('permissions.addMemberModal.title')} onClose={() => setShowAddMember(false)} size="md">
            <p className="mb-4 text-sm text-muted">
              {t('permissions.addMemberModal.subtitle', { name: selectedRole.name })}
            </p>
            {isSuperAdminRole && (
              <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                {t('permissions.superAdminRoleNotice')}
              </div>
            )}
            <form onSubmit={handleAddMember} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('permissions.addMemberModal.subjectTypeRequired')}</label>
                <div className="flex gap-2">
                  {(isSuperAdminRole ? (['user'] as SubjectType[]) : SUBJECT_TYPES).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setAddMemberForm((f) => ({ ...f, subject_type: st, subject_id: '', subject_label: '' }))}
                      className={cn(
                        'flex-1 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                        addMemberForm.subject_type === st
                          ? 'border-primary bg-primary/5 text-primary'
                          : 'border-border text-muted hover:bg-surface-muted'
                      )}
                    >
                      {subjectTypeLabels[st]}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">
                  {t('permissions.addMemberModal.subjectIdLabel', { type: subjectTypeLabels[addMemberForm.subject_type] })}
                </label>
                <SubjectPicker
                  subjectType={addMemberForm.subject_type}
                  value={addMemberForm.subject_id}
                  selectedLabel={addMemberForm.subject_label}
                  onChange={(id, label) => setAddMemberForm((f) => ({ ...f, subject_id: id, subject_label: label }))}
                  placeholder={t('permissions.addMemberModal.subjectIdPlaceholder', { type: subjectTypeLabels[addMemberForm.subject_type] })}
                />
              </div>

              {!isSuperAdminRole && (
              <div>
                <label className="mb-1 block text-sm font-medium text-ink">{t('permissions.addMemberModal.scope')}</label>
                <div className="flex gap-2">
                  {([
                    { v: '', label: t('permissions.addMemberModal.scopeGlobal') },
                    { v: 'org', label: t('permissions.addMemberModal.scopeOrg') },
                    { v: 'group', label: t('permissions.addMemberModal.scopeGroup') },
                  ] as const).map((opt) => (
                    <button
                      key={opt.v}
                      type="button"
                      onClick={() => setAddMemberForm((f) => ({ ...f, scope_type: opt.v, scope_id: '' }))}
                      className={cn(
                        'flex-1 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                        addMemberForm.scope_type === opt.v
                          ? 'border-primary bg-primary/5 text-primary'
                          : 'border-border text-muted hover:bg-surface-muted',
                      )}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
                <p className="mt-1 text-xs text-faint">
                  {t('permissions.addMemberModal.scopeHint')}
                </p>
              </div>
              )}

              {!isSuperAdminRole && addMemberForm.scope_type !== '' && (
                <div>
                  <label className="mb-1 block text-sm font-medium text-ink">
                    {addMemberForm.scope_type === BindingScopeType.Org ? t('permissions.addMemberModal.scopeIdOrgLabel') : t('permissions.addMemberModal.scopeIdGroupLabel')}
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={addMemberForm.scope_id}
                    onChange={(e) => setAddMemberForm((f) => ({ ...f, scope_id: e.target.value }))}
                    placeholder={addMemberForm.scope_type === BindingScopeType.Org ? t('permissions.addMemberModal.scopeIdOrgPlaceholder') : t('permissions.addMemberModal.scopeIdGroupPlaceholder')}
                    className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    required
                  />
                </div>
              )}
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowAddMember(false)}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={addingMember}>
                  {t('permissions.addMemberModal.addBtn')}
                </Button>
              </div>
            </form>
        </Modal>
      )}

      <ConfirmDialog
        open={!!delRole}
        title={t('permissions.confirmDeleteRole', { name: delRole?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingRole}
        onConfirm={confirmDeleteRole}
        onCancel={() => setDelRole(null)}
      />
      <ConfirmDialog
        open={!!delBinding}
        title={t('permissions.confirmRemoveBinding')}
        loading={removingMemberId === delBinding?.id}
        onConfirm={confirmRemoveMember}
        onCancel={() => setDelBinding(null)}
      />
    </motion.div>
  )
}
