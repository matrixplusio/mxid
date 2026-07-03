import { useEffect, useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plus,
  Search,
  Trash2,
  Loader2,
  UsersRound,
  Pencil,
  X,
  UserPlus,
  UserMinus,
  Zap,
  RefreshCw,
} from 'lucide-react'
import { groupApi, userApi, formatDate, cn, useTranslation } from '@mxid/shared'
import type { Group, User, PaginatedData, GroupMember, RuleExpr, GroupRule } from '@mxid/shared'
import axios from 'axios'
import PageHeader from '../../components/layout/PageHeader'
import RuleEditor from './RuleEditor'
import { CodeField, pageMotion, Button, ConfirmDialog } from '../../components/ui'
import AppRolesReverseTab from './AppRolesReverseTab'
import { toast, extractMessage } from '../../components/ui/toast'

const EMPTY_RULE: RuleExpr = { op: 'and', conditions: [] }

export default function GroupsPage() {
  const { t } = useTranslation()
  const [data, setData] = useState<PaginatedData<Group>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  // Create modal
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ name: '', code: '', description: '' })
  const [createType, setCreateType] = useState<1 | 2>(1) // 1=static, 2=dynamic
  const [createRule, setCreateRule] = useState<RuleExpr>(EMPTY_RULE)
  const [creating, setCreating] = useState(false)

  // Edit modal
  const [editGroup, setEditGroup] = useState<Group | null>(null)
  const [editForm, setEditForm] = useState({ name: '', description: '' })
  const [editRule, setEditRule] = useState<RuleExpr | null>(null) // null while loading
  const [editing, setEditing] = useState(false)

  // Member drawer — sync state for dynamic groups
  const [groupRule, setGroupRule] = useState<GroupRule | null>(null)
  const [syncing, setSyncing] = useState(false)

  // Member management drawer
  const [memberGroup, setMemberGroup] = useState<Group | null>(null)
  const [delGroup, setDelGroup] = useState<Group | null>(null)
  const [deletingGroup, setDeletingGroup] = useState(false)
  const [cascadeGroup, setCascadeGroup] = useState<Group | null>(null)
  const [cascadingGroup, setCascadingGroup] = useState(false)
  const [memberModalTab, setMemberModalTab] = useState<'members' | 'app-roles'>('members')
  const [members, setMembers] = useState<PaginatedData<GroupMember>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [membersLoading, setMembersLoading] = useState(false)
  const [memberPage, setMemberPage] = useState(1)
  const [removingMemberId, setRemovingMemberId] = useState<string | null>(null)

  // Add member dialog
  const [showAddMember, setShowAddMember] = useState(false)
  const [userSearch, setUserSearch] = useState('')
  const [userResults, setUserResults] = useState<User[]>([])
  const [userSearching, setUserSearching] = useState(false)
  const [addingUserId, setAddingUserId] = useState<string | null>(null)
  const userSearchTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  // ─── Group list ────────────────────────────────────────────────

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: 20 }
      if (search) params.keyword = search
      const result = await groupApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [page, search])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleSearchChange = (val: string) => {
    setSearch(val)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      setPage(1)
    }, 400)
  }

  // ─── Create ────────────────────────────────────────────────────

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createForm.name || !createForm.code) return
    if (createType === 2 && createRule.conditions.length === 0) {
      alert(t("groups.needAtLeastOneRule"))
      return
    }
    setCreating(true)
    try {
      const created = await groupApi.create({
        name: createForm.name,
        code: createForm.code,
        description: createForm.description || undefined,
      })
      // For dynamic groups, attach the rule right after creation — the backend
      // flips type to dynamic and runs the initial sync.
      if (createType === 2 && created) {
        await groupApi.upsertRule(created.id, createRule)
      }
      setShowCreate(false)
      setCreateForm({ name: '', code: '', description: '' })
      setCreateType(1)
      setCreateRule(EMPTY_RULE)
      setPage(1)
      loadData()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setCreating(false)
    }
  }

  // ─── Edit ──────────────────────────────────────────────────────

  const openEdit = (group: Group) => {
    setEditGroup(group)
    setEditForm({ name: group.name, description: group.description || '' })
    if (group.type === 2) {
      setEditRule(null)
      groupApi
        .getRule(group.id)
        .then((r) => setEditRule(r.expr))
        .catch(() => setEditRule({ op: 'and', conditions: [] }))
    } else {
      setEditRule(null)
    }
  }

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editGroup || !editForm.name) return
    setEditing(true)
    try {
      await groupApi.update(editGroup.id, {
        name: editForm.name,
        description: editForm.description || undefined,
      })
      // For dynamic groups also persist the (possibly edited) rule; backend
      // re-syncs membership automatically.
      if (editGroup.type === 2 && editRule) {
        if (editRule.conditions.length === 0) {
          alert(t("groups.needAtLeastOneRule"))
          setEditing(false)
          return
        }
        await groupApi.upsertRule(editGroup.id, editRule)
      }
      setEditGroup(null)
      setEditRule(null)
      loadData()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setEditing(false)
    }
  }

  // ─── Delete ────────────────────────────────────────────────────

  // Delete flow is two-stage: a plain delete, and — if the API 409s because the
  // group still has members — a follow-up cascade confirm.
  const confirmDelete = async () => {
    const group = delGroup
    if (!group) return
    setDeletingGroup(true)
    try {
      await groupApi.delete(group.id)
      if (memberGroup?.id === group.id) setMemberGroup(null)
      setDelGroup(null)
      loadData()
      toast.success(t("common.success"))
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 409) {
        // Still has members → escalate to the cascade confirm.
        setDelGroup(null)
        setCascadeGroup(group)
      } else {
        toast.error(t("common.failed"), extractMessage(err))
      }
    } finally {
      setDeletingGroup(false)
    }
  }

  const confirmCascade = async () => {
    const group = cascadeGroup
    if (!group) return
    setCascadingGroup(true)
    try {
      await groupApi.delete(group.id, true)
      if (memberGroup?.id === group.id) setMemberGroup(null)
      setCascadeGroup(null)
      loadData()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setCascadingGroup(false)
    }
  }

  // ─── Members ───────────────────────────────────────────────────

  const loadMembers = useCallback(async (groupId: string, pg: number) => {
    setMembersLoading(true)
    try {
      const result = await groupApi.listMembers(groupId, { page: pg, page_size: 20 })
      setMembers(result)
    } catch {
      // ignore
    } finally {
      setMembersLoading(false)
    }
  }, [])

  const openMembers = (group: Group) => {
    setMemberGroup(group)
    setMemberPage(1)
    loadMembers(group.id, 1)
    if (group.type === 2) {
      groupApi.getRule(group.id).then(setGroupRule).catch(() => setGroupRule(null))
    } else {
      setGroupRule(null)
    }
  }

  const handleSync = async () => {
    if (!memberGroup) return
    setSyncing(true)
    try {
      const report = await groupApi.syncRule(memberGroup.id)
      alert(t("groups.syncDone", { added: report.added, removed: report.removed }))
      await loadMembers(memberGroup.id, memberPage)
      const fresh = await groupApi.getRule(memberGroup.id)
      setGroupRule(fresh)
      loadData()
    } catch (err) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.message || err.message : t("groups.syncFailed")
      alert(t("groups.syncFailedDetail", { msg }))
    } finally {
      setSyncing(false)
    }
  }

  useEffect(() => {
    if (memberGroup) {
      loadMembers(memberGroup.id, memberPage)
    }
  }, [memberPage, memberGroup, loadMembers])

  const handleRemoveMember = async (userId: string) => {
    if (!memberGroup) return
    setRemovingMemberId(userId)
    try {
      await groupApi.removeMember(memberGroup.id, userId)
      loadMembers(memberGroup.id, memberPage)
      loadData()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setRemovingMemberId(null)
    }
  }

  // ─── Add member ────────────────────────────────────────────────

  // Load the first page of users immediately when the dialog opens so admins
  // can pick from a default list without typing — search narrows the list.
  const loadUserCandidates = useCallback(async (keyword: string) => {
    setUserSearching(true)
    try {
      const params: Record<string, unknown> = { page: 1, page_size: 20 }
      if (keyword.trim()) params.keyword = keyword.trim()
      const result = await userApi.list(params)
      setUserResults(result.items ?? [])
    } finally {
      setUserSearching(false)
    }
  }, [])

  useEffect(() => {
    if (showAddMember) {
      loadUserCandidates('')
    }
  }, [showAddMember, loadUserCandidates])

  const handleUserSearch = (val: string) => {
    setUserSearch(val)
    if (userSearchTimer.current) clearTimeout(userSearchTimer.current)
    // Debounce search; empty keyword reloads the default list rather than
    // clearing it so the picker remains usable.
    userSearchTimer.current = setTimeout(() => {
      loadUserCandidates(val)
    }, 400)
  }

  const handleAddMember = async (userId: string) => {
    if (!memberGroup) return
    setAddingUserId(userId)
    try {
      await groupApi.addMember(memberGroup.id, userId)
      toast.success(t('common.saveSuccess'))
      loadMembers(memberGroup.id, memberPage)
      loadData()
      setUserSearch('')
      setUserResults([])
      setShowAddMember(false)
    } catch (e) {
      toast.error(t('common.saveFailed'), extractMessage(e))
    } finally {
      setAddingUserId(null)
    }
  }

  const closeMembers = () => {
    setMemberGroup(null)
    setMembers({ items: [], total: 0, page: 1, page_size: 20 })
    setMemberPage(1)
    setShowAddMember(false)
    setUserSearch('')
    setUserResults([])
  }

  const totalPages = Math.ceil(data.total / data.page_size) || 1
  const memberTotalPages = Math.ceil(members.total / members.page_size) || 1

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('groups.title')}
        description={t('groups.subtitle')}
        actions={
          <Button onClick={() => setShowCreate(true)} icon={<Plus className="h-4 w-4" />}>
            {t('groups.create')}
          </Button>
        }
      />

      {/* Search */}
      <div className="mb-4">
        <div className="relative max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => handleSearchChange(e.target.value)}
            placeholder={t('groups.searchPlaceholder')}
            className="w-full rounded-lg border border-gray-200 py-2 pl-10 pr-4 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('groups.columns.name')}</th>
                <th className="px-6 py-3">{t('groups.columns.code')}</th>
                <th className="px-6 py-3">{t('groups.columns.desc')}</th>
                <th className="px-6 py-3">{t('groups.columns.memberCount')}</th>
                <th className="px-6 py-3">{t('groups.columns.createdAt')}</th>
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
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.empty')}
                  </td>
                </tr>
              ) : (
                data.items.map((group) => (
                  <tr
                    key={group.id}
                    className={cn(
                      'hover:bg-gray-50/50 transition-colors',
                      memberGroup?.id === group.id && 'bg-primary/5',
                    )}
                  >
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEdit(group)}
                          className="text-sm font-medium text-gray-900 hover:text-primary transition-colors"
                          title={t('groups.titleHint.edit')}
                        >
                          {group.name}
                        </button>
                        {group.type === 2 && (
                          <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700" title={t('groups.dynamicTagHint')}>
                            <Zap className="h-3 w-3" />
                            {t('groups.dynamicTag')}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <code className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                        {group.code}
                      </code>
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {group.description || '-'}
                    </td>
                    <td className="px-6 py-3">
                      <button
                        onClick={() => openMembers(group)}
                        className={cn(
                          'inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-sm transition-colors',
                          memberGroup?.id === group.id
                            ? 'bg-primary/10 text-primary font-medium'
                            : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
                        )}
                        title={t('groups.titleHint.manageMembers')}
                      >
                        <UsersRound className="h-3.5 w-3.5" />
                        {group.member_count}
                      </button>
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                      {formatDate(group.created_at)}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => openEdit(group)}
                          className="rounded p-1 text-gray-400 hover:bg-blue-50 hover:text-blue-500"
                          title={t('common.edit')}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setDelGroup(group)}
                          className="rounded p-1 text-gray-400 hover:bg-red-50 hover:text-red-500"
                          title={t('common.delete')}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data.total > 0 && (
          <div className="flex items-center justify-between border-t border-gray-100 px-6 py-3">
            <p className="text-sm text-gray-500">
              {t('groups.pagingSummary', { total: data.total, page, pages: totalPages })}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
              >
                {t('groups.prevPage')}
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
              >
                {t('groups.nextPage')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ─── Member Management Drawer ─────────────────────────────── */}
      <AnimatePresence>
        {memberGroup && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            transition={{ duration: 0.2 }}
            className="mt-4 rounded-xl border border-gray-100 bg-white shadow-sm"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
              <div className="flex items-center gap-3">
                <UsersRound className="h-5 w-5 text-primary" />
                <div>
                  <h3 className="text-sm font-semibold text-gray-900">
                    {t('groups.memberMgmt', { name: memberGroup.name })}
                  </h3>
                  <p className="text-xs text-gray-500">
                    {t('groups.memberTotal', { n: members.total })}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {memberModalTab === 'members' && (memberGroup.type === 2 ? (
                  <button
                    onClick={handleSync}
                    disabled={syncing}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-amber-600 disabled:opacity-60"
                    title={t('groups.manualSyncHint')}
                  >
                    {syncing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                    {t('groups.manualSync')}
                  </button>
                ) : (
                  <button
                    onClick={() => setShowAddMember(true)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover"
                  >
                    <UserPlus className="h-3.5 w-3.5" />
                    {t('groups.addMember')}
                  </button>
                ))}
                <button
                  onClick={closeMembers}
                  className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Tab bar */}
            <div className="flex gap-6 border-b border-gray-100 px-6">
              {(['members', 'app-roles'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setMemberModalTab(tab)}
                  className={cn(
                    'border-b-2 px-1 py-2.5 text-sm font-medium transition-colors',
                    memberModalTab === tab ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700',
                  )}
                >
                  {tab === 'members' ? t('groups.tabMembers') : t('groups.tabAppRoles')}
                </button>
              ))}
            </div>

            {/* Dynamic group sync banner */}
            {memberModalTab === 'members' && memberGroup.type === 2 && groupRule && (
              <div className="border-b border-gray-100 bg-amber-50/40 px-6 py-2 text-xs text-gray-600">
                <Zap className="mr-1 inline h-3 w-3 text-amber-500" />
                {groupRule.last_sync_at
                  ? t('groups.dynamicLastSync', {
                      at: formatDate(groupRule.last_sync_at),
                      added: groupRule.last_sync_added,
                      removed: groupRule.last_sync_removed,
                    })
                  : t('groups.dynamicNotSynced')}
                {groupRule.last_sync_error && <span className="ml-2 text-red-600">{t('groups.syncError', { msg: groupRule.last_sync_error })}</span>}
              </div>
            )}

            {memberModalTab === 'app-roles' && (
              <div className="px-6 py-4">
                <AppRolesReverseTab groupId={memberGroup.id} />
              </div>
            )}

            {/* Member list */}
            {memberModalTab === 'members' && (
            <>
            <div className="px-6 py-4">
              {membersLoading ? (
                <div className="flex items-center justify-center py-8 text-sm text-gray-400">
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t('common.loading')}
                </div>
              ) : members.items.length === 0 ? (
                <div className="py-8 text-center text-sm text-gray-400">
                  {memberGroup.type === 2 ? t('groups.membersEmptyDynamic') : t('groups.membersEmptyStatic')}
                </div>
              ) : (
                <div className="space-y-2">
                  {members.items.map((m) => {
                    const initial = (m.display_name || m.username || '?').charAt(0).toUpperCase()
                    return (
                      <div
                        key={m.user_id}
                        className="flex items-center justify-between rounded-lg border border-gray-100 px-4 py-2.5 transition-colors hover:bg-gray-50"
                      >
                        <div className="flex min-w-0 items-center gap-3">
                          {m.avatar ? (
                            <img
                              src={m.avatar}
                              alt={m.username}
                              className="h-8 w-8 rounded-full object-cover"
                            />
                          ) : (
                            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
                              {initial}
                            </div>
                          )}
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="truncate text-sm font-medium text-gray-900">
                                {m.display_name || m.username}
                              </span>
                              <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">
                                {m.username}
                              </code>
                            </div>
                            {m.email && (
                              <p className="truncate text-xs text-gray-400">{m.email}</p>
                            )}
                          </div>
                        </div>
                        {memberGroup.type === 2 ? (
                          <span className="text-xs text-gray-400" title={t('groups.dynamicMemberLocked')}>
                            —
                          </span>
                        ) : (
                          <button
                            onClick={() => handleRemoveMember(m.user_id)}
                            disabled={removingMemberId === m.user_id}
                            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
                            title={t('groups.removeMember')}
                          >
                            {removingMemberId === m.user_id ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <UserMinus className="h-3.5 w-3.5" />
                            )}
                            {t('common.remove')}
                          </button>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Member pagination */}
            {members.total > 0 && (
              <div className="flex items-center justify-between border-t border-gray-100 px-6 py-3">
                <p className="text-sm text-gray-500">
                  {t('groups.pagingSummary', { total: members.total, page: memberPage, pages: memberTotalPages })}
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setMemberPage((p) => Math.max(1, p - 1))}
                    disabled={memberPage <= 1}
                    className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
                  >
                    {t('groups.prevPage')}
                  </button>
                  <button
                    onClick={() => setMemberPage((p) => Math.min(memberTotalPages, p + 1))}
                    disabled={memberPage >= memberTotalPages}
                    className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
                  >
                    {t('groups.nextPage')}
                  </button>
                </div>
              </div>
            )}
            </>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ─── Create Modal ─────────────────────────────────────────── */}
      <AnimatePresence>
        {showCreate && (
          <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-8">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="my-auto w-full max-w-2xl rounded-xl bg-white p-6 shadow-xl"
            >
              <h3 className="mb-4 text-lg font-semibold">{t('groups.createModal.title')}</h3>
              <form onSubmit={handleCreate} className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.nameRequired')}</label>
                  <input
                    type="text"
                    value={createForm.name}
                    onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    required
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('groups.createModal.nameHint')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.codeRequired')}</label>
                  <CodeField
                    value={createForm.code}
                    onChange={(v) => setCreateForm((f) => ({ ...f, code: v }))}
                    nameForSlug={createForm.name}
                    prefix="ug"
                    placeholder="engineering / devops / admins ..."
                  />
                  <p className="mt-1 text-xs text-gray-400">
                    {t('groups.createModal.harborHint')}
                    <span className="text-amber-600">{t('groups.createModal.codeImmutable')}</span>
                  </p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.desc')}</label>
                  <textarea
                    value={createForm.description}
                    onChange={(e) => setCreateForm((f) => ({ ...f, description: e.target.value }))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    rows={3}
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('groups.createModal.descHint')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.groupType')}</label>
                  <div className="flex gap-3">
                    <label className={cn('flex flex-1 cursor-pointer items-start gap-2 rounded-lg border p-3', createType === 1 ? 'border-primary bg-primary/5' : 'border-gray-200')}>
                      <input type="radio" name="group_type" checked={createType === 1} onChange={() => setCreateType(1)} className="mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-gray-900">{t('groups.createModal.staticName')}</div>
                        <div className="text-xs text-gray-500">{t('groups.createModal.staticDesc')}</div>
                      </div>
                    </label>
                    <label className={cn('flex flex-1 cursor-pointer items-start gap-2 rounded-lg border p-3', createType === 2 ? 'border-primary bg-primary/5' : 'border-gray-200')}>
                      <input type="radio" name="group_type" checked={createType === 2} onChange={() => setCreateType(2)} className="mt-0.5" />
                      <div>
                        <div className="text-sm font-medium text-gray-900">{t('groups.createModal.dynamicName')}</div>
                        <div className="text-xs text-gray-500">{t('groups.createModal.dynamicDesc')}</div>
                      </div>
                    </label>
                  </div>
                </div>
                {createType === 2 && (
                  <RuleEditor value={createRule} onChange={setCreateRule} />
                )}
                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="secondary" onClick={() => setShowCreate(false)}>
                    {t('common.cancel')}
                  </Button>
                  <Button type="submit" loading={creating}>
                    {t('groups.createModal.createBtn')}
                  </Button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ─── Edit Modal ───────────────────────────────────────────── */}
      <AnimatePresence>
        {editGroup && (
          <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-8">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="my-auto w-full max-w-2xl rounded-xl bg-white p-6 shadow-xl"
            >
              <h3 className="mb-4 text-lg font-semibold">{t('groups.editModal.title')}</h3>
              <form onSubmit={handleEdit} className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.nameRequired')}</label>
                  <input
                    type="text"
                    value={editForm.name}
                    onChange={(e) => setEditForm((f) => ({ ...f, name: e.target.value }))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    required
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('groups.editModal.nameHintEditable')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.editModal.code')}</label>
                  <input
                    type="text"
                    value={editGroup.code}
                    disabled
                    className="w-full rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-500"
                  />
                  <p className="mt-1 text-xs text-gray-400">
                    {t('groups.editModal.codeImmutableHint')}
                    <span className="text-amber-600">{t('groups.editModal.codeImmutableLabel')}</span>
                    {t('groups.editModal.codeImmutableTail')}
                  </p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.createModal.desc')}</label>
                  <textarea
                    value={editForm.description}
                    onChange={(e) => setEditForm((f) => ({ ...f, description: e.target.value }))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    rows={3}
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('groups.editModal.descHint')}</p>
                </div>
                {editGroup.type === 2 && (
                  <div>
                    <label className="mb-1 block text-sm font-medium text-gray-700">
                      <Zap className="mr-1 inline h-3.5 w-3.5 text-amber-500" />
                      {t('groups.editModal.dynamicRule')}
                    </label>
                    {editRule === null ? (
                      <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-center text-xs text-gray-400">
                        <Loader2 className="mx-auto h-4 w-4 animate-spin" />
                      </div>
                    ) : (
                      <RuleEditor value={editRule} onChange={setEditRule} />
                    )}
                    <p className="mt-1 text-xs text-gray-400">{t('groups.editModal.ruleSavedHint')}</p>
                  </div>
                )}
                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="secondary" onClick={() => setEditGroup(null)}>
                    {t('common.cancel')}
                  </Button>
                  <Button type="submit" loading={editing}>
                    {t('common.save')}
                  </Button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ─── Add Member Modal ─────────────────────────────────────── */}
      <AnimatePresence>
        {showAddMember && memberGroup && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-xl bg-white p-6 shadow-xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold">{t('groups.addMemberModal.title')}</h3>
                <button
                  onClick={() => {
                    setShowAddMember(false)
                    setUserSearch('')
                    setUserResults([])
                  }}
                  className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('groups.addMemberModal.searchLabel')}</label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                    <input
                      type="text"
                      value={userSearch}
                      onChange={(e) => handleUserSearch(e.target.value)}
                      placeholder={t('groups.addMemberModal.searchPlaceholder')}
                      className="w-full rounded-lg border border-gray-300 py-2 pl-10 pr-4 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                      autoFocus
                    />
                    {userSearching && (
                      <Loader2 className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-gray-400" />
                    )}
                  </div>
                </div>

                {/* Search results */}
                <div className="max-h-64 overflow-y-auto">
                  {!userSearching && userResults.length === 0 && (
                    <div className="py-6 text-center text-sm text-gray-400">
                      {userSearch.trim() ? t('groups.addMemberModal.noMatch') : t('groups.addMemberModal.noCandidates')}
                    </div>
                  )}
                  {userResults.length > 0 && (
                    <div className="space-y-1">
                      {userResults.map((user) => (
                        <div
                          key={user.id}
                          className="flex items-center justify-between rounded-lg px-3 py-2.5 transition-colors hover:bg-gray-50"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-gray-900">
                                {user.display_name || user.username}
                              </span>
                              <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">
                                {user.username}
                              </code>
                            </div>
                            <p className="mt-0.5 text-xs text-gray-400">
                              ID: {user.id}
                              {user.email ? ` / ${user.email}` : ''}
                            </p>
                          </div>
                          <button
                            onClick={() => handleAddMember(user.id)}
                            disabled={addingUserId === user.id}
                            className="ml-3 inline-flex items-center gap-1 rounded-md bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                          >
                            {addingUserId === user.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <UserPlus className="h-3 w-3" />
                            )}
                            {t('groups.addMemberModal.addBtn')}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <ConfirmDialog
        open={!!delGroup}
        title={t('groups.confirmDelete', { name: delGroup?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingGroup}
        onConfirm={confirmDelete}
        onCancel={() => setDelGroup(null)}
      />
      <ConfirmDialog
        open={!!cascadeGroup}
        title={t('groups.confirmCascade', { name: cascadeGroup?.name ?? '', count: cascadeGroup?.member_count ?? 0 })}
        desc={t('common.cantUndo')}
        loading={cascadingGroup}
        onConfirm={confirmCascade}
        onCancel={() => setCascadeGroup(null)}
      />
    </motion.div>
  )
}
