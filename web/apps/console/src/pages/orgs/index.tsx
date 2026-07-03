import { useEffect, useState, useRef, useCallback } from 'react'
import { motion } from 'framer-motion'
import {
  ChevronRight,
  ChevronDown,
  Plus,
  Pencil,
  Trash2,
  Building2,
  Loader2,
  Users,
  Search,
  X,
  FolderTree,
  UserPlus,
  UserMinus,
} from 'lucide-react'
import { orgApi, userApi, cn, statusLabel, statusColor, useTranslation } from '@mxid/shared'
import { pageMotion, Button, ConfirmDialog } from '@mxid/shared/ui'
import type { OrgNode, User, PaginatedData } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { useTabParam } from '../../hooks/useTabParam'
import { toast, extractMessage } from '../../components/ui/toast'

const ORG_TAB_VALUES = ['info', 'members'] as const

/* ───────────────────────── Tree node (recursive) ───────────────────────── */

function TreeNode({
  node,
  selectedId,
  onSelect,
  depth = 0,
}: {
  node: OrgNode
  selectedId: string | null
  onSelect: (node: OrgNode) => void
  depth?: number
}) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children && node.children.length > 0

  return (
    <div>
      <button
        onClick={() => onSelect(node)}
        className={cn(
          'flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors hover:bg-gray-100',
          selectedId === node.id && 'bg-primary/10 text-primary font-medium'
        )}
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
      >
        {hasChildren ? (
          // span (not button) — nesting <button> inside <button> is invalid
          // HTML and warns at hydration. Keyboard focus stays on the outer
          // row button; the toggle is reachable via click on the chevron.
          <span
            role="button"
            tabIndex={-1}
            onClick={(e) => {
              e.stopPropagation()
              setExpanded(!expanded)
            }}
            className="shrink-0 cursor-pointer"
          >
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronRight className="h-4 w-4 text-gray-400" />
            )}
          </span>
        ) : (
          <span className="w-4" />
        )}
        <Building2 className="h-4 w-4 shrink-0 text-gray-400" />
        <span className="truncate">{node.name}</span>
      </button>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child) => (
            <TreeNode
              key={child.id}
              node={child}
              selectedId={selectedId}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  )
}

/* ──────────────── Selectable tree (for move dialog) ────────────────────── */

function SelectableTreeNode({
  node,
  selectedId,
  disabledId,
  onSelect,
  depth = 0,
}: {
  node: OrgNode
  selectedId: string | null
  disabledId: string
  onSelect: (id: string | null) => void
  depth?: number
}) {
  const [expanded, setExpanded] = useState(true)
  const hasChildren = node.children && node.children.length > 0
  const isDisabled = node.id === disabledId
  const isDescendant = isDescendantOf(node, disabledId)

  return (
    <div>
      <button
        onClick={() => {
          if (!isDisabled && !isDescendant) onSelect(node.id)
        }}
        disabled={isDisabled || isDescendant}
        className={cn(
          'flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors',
          isDisabled || isDescendant
            ? 'cursor-not-allowed text-gray-300'
            : 'hover:bg-gray-100',
          selectedId === node.id && !isDisabled && 'bg-primary/10 text-primary font-medium'
        )}
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
      >
        {hasChildren ? (
          <span
            onClick={(e) => {
              e.stopPropagation()
              setExpanded(!expanded)
            }}
            className="shrink-0 cursor-pointer"
          >
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronRight className="h-4 w-4 text-gray-400" />
            )}
          </span>
        ) : (
          <span className="w-4" />
        )}
        <Building2 className="h-4 w-4 shrink-0 text-gray-400" />
        <span className="truncate">{node.name}</span>
      </button>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child) => (
            <SelectableTreeNode
              key={child.id}
              node={child}
              selectedId={selectedId}
              disabledId={disabledId}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  )
}

/** Check whether `node` is a descendant of the node with `ancestorId` */
function isDescendantOf(node: OrgNode, ancestorId: string): boolean {
  if (!node.children) return false
  for (const child of node.children) {
    if (child.id === ancestorId) return true
    if (isDescendantOf(child, ancestorId)) return true
  }
  return false
}

/* ─────────────────────────────── Main page ──────────────────────────────── */

export default function OrgsPage() {
  const { t } = useTranslation()
  const [tree, setTree] = useState<OrgNode[]>([])
  const [selected, setSelected] = useState<OrgNode | null>(null)
  const [loading, setLoading] = useState(true)

  // Detail panel tab
  const [activeTab, setActiveTab] = useTabParam<'info' | 'members'>('tab', 'info', ORG_TAB_VALUES)

  // Create child modal
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ name: '', code: '' })
  const [creating, setCreating] = useState(false)

  // Edit modal
  const [showEdit, setShowEdit] = useState(false)
  const [editName, setEditName] = useState('')
  const [editing, setEditing] = useState(false)

  // Move modal
  const [showMove, setShowMove] = useState(false)
  const [moveTargetId, setMoveTargetId] = useState<string | null>(null)
  const [moving, setMoving] = useState(false)
  const [showDeleteOrg, setShowDeleteOrg] = useState(false)
  const [deletingOrg, setDeletingOrg] = useState(false)
  const [delMemberId, setDelMemberId] = useState<string | null>(null)
  const [removingMember, setRemovingMember] = useState(false)

  // Members state
  const [members, setMembers] = useState<PaginatedData<string>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [membersLoading, setMembersLoading] = useState(false)
  const [memberPage, setMemberPage] = useState(1)
  const [memberUsers, setMemberUsers] = useState<Map<string, User>>(new Map())

  // Add member modal
  const [showAddMember, setShowAddMember] = useState(false)
  const [userSearch, setUserSearch] = useState('')
  const [userSearchResults, setUserSearchResults] = useState<User[]>([])
  const [userSearchLoading, setUserSearchLoading] = useState(false)
  const [addingMemberId, setAddingMemberId] = useState<string | null>(null)
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  /* ── Helpers: find node in tree by id ──
   * Pure recursion, no closure state — kept module-local via the function
   * statement form so eslint stops flagging the self-call as "use before
   * declared" that the const + useCallback form triggers. */
  function findNodeById(nodes: OrgNode[], id: string): OrgNode | null {
    for (const n of nodes) {
      if (n.id === id) return n
      if (n.children) {
        const found = findNodeById(n.children, id)
        if (found) return found
      }
    }
    return null
  }

  /* ── Load tree ── */
  const loadTree = async () => {
    try {
      const data = (await orgApi.tree()) ?? []
      setTree(data)
      if (selected) {
        const refreshed = findNodeById(data, selected.id)
        if (refreshed) setSelected(refreshed)
        else setSelected(data.length > 0 ? data[0] : null)
      } else if (data.length > 0) {
        setSelected(data[0])
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTree()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /* ── Load members when selected org or page changes ── */
  const loadMembers = useCallback(async (orgId: string, page: number) => {
    setMembersLoading(true)
    try {
      const data = await orgApi.listMembers(orgId, { page, page_size: 20 })
      setMembers(data)

      // Resolve user details for the IDs we don't already have
      const unknownIds = data.items.filter((uid) => !memberUsers.has(uid))
      if (unknownIds.length > 0) {
        const newMap = new Map(memberUsers)
        await Promise.all(
          unknownIds.map(async (uid) => {
            try {
              // Resolve by id directly. The user list endpoint has no id
              // filter, so list({id}) returned the first user for EVERY member
              // — every row rendered as the same person.
              const user = await userApi.getById(uid)
              if (user) {
                newMap.set(uid, user)
              }
            } catch {
              // ignore individual failures
            }
          })
        )
        setMemberUsers(newMap)
      }
    } catch {
      // ignore
    } finally {
      setMembersLoading(false)
    }
  }, [memberUsers])

  useEffect(() => {
    if (selected && activeTab === 'members') {
      loadMembers(selected.id, memberPage)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id, activeTab, memberPage])

  /* ── When selection changes, reset member tab state ── */
  useEffect(() => {
    setMemberPage(1)
    setMembers({ items: [], total: 0, page: 1, page_size: 20 })
  }, [selected?.id])

  /* ── User search for add-member modal ── */
  //
  // Mirrors the groups page: the dialog loads a default list of users when
  // opened so the admin can pick without typing; keystrokes filter the same
  // endpoint via the keyword param.
  const loadUserCandidates = useCallback(async (keyword: string) => {
    setUserSearchLoading(true)
    try {
      const params: Record<string, unknown> = { page: 1, page_size: 20 }
      if (keyword.trim()) params.keyword = keyword.trim()
      const result = await userApi.list(params)
      setUserSearchResults(result.items ?? [])
    } finally {
      setUserSearchLoading(false)
    }
  }, [])

  useEffect(() => {
    if (showAddMember) {
      loadUserCandidates('')
    }
  }, [showAddMember, loadUserCandidates])

  const handleUserSearch = (val: string) => {
    setUserSearch(val)
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current)
    searchTimerRef.current = setTimeout(() => {
      loadUserCandidates(val)
    }, 400)
  }

  /* ── CRUD handlers ── */

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createForm.name || !createForm.code) return
    setCreating(true)
    try {
      await orgApi.create({
        parent_id: selected?.id,
        name: createForm.name,
        code: createForm.code,
      })
      setShowCreate(false)
      setCreateForm({ name: '', code: '' })
      loadTree()
      toast.success(t('orgs.orgCreated'))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setCreating(false)
    }
  }

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected || !editName) return
    setEditing(true)
    try {
      await orgApi.update(selected.id, { name: editName })
      setShowEdit(false)
      loadTree()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setEditing(false)
    }
  }

  const confirmDeleteOrg = async () => {
    if (!selected) return
    setDeletingOrg(true)
    try {
      await orgApi.delete(selected.id)
      setShowDeleteOrg(false)
      setSelected(null)
      loadTree()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setDeletingOrg(false)
    }
  }

  const handleMove = async () => {
    if (!selected) return
    setMoving(true)
    try {
      await orgApi.move(selected.id, moveTargetId)
      setShowMove(false)
      setMoveTargetId(null)
      loadTree()
      toast.success(t('orgs.moved'))
    } catch (e) {
      toast.error(t('orgs.moveFailed'), extractMessage(e))
    } finally {
      setMoving(false)
    }
  }

  const handleAddMember = async (userId: string) => {
    if (!selected) return
    setAddingMemberId(userId)
    try {
      await orgApi.addMember(selected.id, userId)
      setShowAddMember(false)
      setUserSearch('')
      setUserSearchResults([])
      loadMembers(selected.id, memberPage)
      toast.success(t('orgs.memberAdded'))
    } catch (e) {
      toast.error(t('orgs.addMemberFailed'), extractMessage(e))
    } finally {
      setAddingMemberId(null)
    }
  }

  const confirmRemoveMember = async () => {
    if (!selected || !delMemberId) return
    setRemovingMember(true)
    try {
      await orgApi.removeMember(selected.id, delMemberId)
      setDelMemberId(null)
      loadMembers(selected.id, memberPage)
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setRemovingMember(false)
    }
  }

  const delMemberLabel = (() => {
    if (!delMemberId) return ''
    const u = memberUsers.get(delMemberId)
    return u ? u.display_name || u.username : `ID ${delMemberId}`
  })()

  const memberTotalPages = Math.ceil(members.total / members.page_size) || 1

  /* ────────────────────────────── Render ────────────────────────────────── */

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('orgs.title')}
        description={t('orgs.subtitle')}
        actions={
          <Button onClick={() => setShowCreate(true)} icon={<Plus className="h-4 w-4" />}>
            {t('orgs.addChild')}
          </Button>
        }
      />

      <div className="flex gap-6">
        {/* ───── Tree panel ───── */}
        <div className="w-80 shrink-0 rounded-xl border border-gray-100 bg-white p-4 shadow-sm">
          <h3 className="mb-3 text-sm font-semibold text-gray-700">{t('orgs.structure')}</h3>
          {loading ? (
            <p className="py-8 text-center text-sm text-gray-400">{t('common.loading')}</p>
          ) : tree.length === 0 ? (
            <p className="py-8 text-center text-sm text-gray-400">{t('orgs.empty')}</p>
          ) : (
            <div className="space-y-0.5">
              {tree.map((node) => (
                <TreeNode
                  key={node.id}
                  node={node}
                  selectedId={selected?.id ?? null}
                  onSelect={(n) => {
                    setSelected(n)
                    setActiveTab('info')
                  }}
                />
              ))}
            </div>
          )}
        </div>

        {/* ───── Detail panel ───── */}
        <div className="flex-1 rounded-xl border border-gray-100 bg-white shadow-sm">
          {selected ? (
            <div>
              {/* Header with actions */}
              <div className="flex items-start justify-between border-b border-gray-100 p-6">
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">{selected.name}</h2>
                  <p className="mt-1 text-sm text-gray-500">{t('orgs.codePrefix', { code: selected.code })}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setMoveTargetId(selected.parent_id)
                      setShowMove(true)
                    }}
                    className="rounded-lg border border-gray-200 p-2 text-gray-500 hover:bg-gray-50 hover:text-gray-700"
                    title={t('orgs.moveTo')}
                  >
                    <FolderTree className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => {
                      setEditName(selected.name)
                      setShowEdit(true)
                    }}
                    className="rounded-lg border border-gray-200 p-2 text-gray-500 hover:bg-gray-50 hover:text-gray-700"
                    title={t('orgs.edit')}
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => setShowDeleteOrg(true)}
                    className="rounded-lg border border-gray-200 p-2 text-gray-500 hover:bg-red-50 hover:text-red-500"
                    title={t('orgs.delete')}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex border-b border-gray-100">
                <button
                  onClick={() => setActiveTab('info')}
                  className={cn(
                    'px-6 py-3 text-sm font-medium transition-colors',
                    activeTab === 'info'
                      ? 'border-b-2 border-primary text-primary'
                      : 'text-gray-500 hover:text-gray-700'
                  )}
                >
                  {t('orgs.tabInfo')}
                </button>
                <button
                  onClick={() => setActiveTab('members')}
                  className={cn(
                    'px-6 py-3 text-sm font-medium transition-colors',
                    activeTab === 'members'
                      ? 'border-b-2 border-primary text-primary'
                      : 'text-gray-500 hover:text-gray-700'
                  )}
                >
                  <span className="inline-flex items-center gap-1.5">
                    <Users className="h-4 w-4" />
                    {t('orgs.tabMembers')}
                  </span>
                </button>
              </div>

              {/* Tab content */}
              <div className="p-6">
                {activeTab === 'info' && (
                  <dl className="grid grid-cols-2 gap-4">
                    <div className="rounded-lg bg-gray-50 p-4">
                      <dt className="text-xs font-medium text-gray-500">ID</dt>
                      <dd className="mt-1 text-sm font-medium text-gray-900">{selected.id}</dd>
                    </div>
                    <div className="rounded-lg bg-gray-50 p-4">
                      <dt className="text-xs font-medium text-gray-500">{t('orgs.fields.path')}</dt>
                      <dd className="mt-1 text-sm font-medium text-gray-900">{selected.path}</dd>
                    </div>
                    <div className="rounded-lg bg-gray-50 p-4">
                      <dt className="text-xs font-medium text-gray-500">{t('orgs.fields.sortOrder')}</dt>
                      <dd className="mt-1 text-sm font-medium text-gray-900">{selected.sort_order}</dd>
                    </div>
                    <div className="rounded-lg bg-gray-50 p-4">
                      <dt className="text-xs font-medium text-gray-500">{t('orgs.fields.status')}</dt>
                      <dd className={cn('mt-1 text-sm font-medium', statusColor(selected.status))}>
                        {statusLabel(selected.status)}
                      </dd>
                    </div>
                    <div className="rounded-lg bg-gray-50 p-4">
                      <dt className="text-xs font-medium text-gray-500">{t('orgs.fields.parentId')}</dt>
                      <dd className="mt-1 text-sm font-medium text-gray-900">
                        {selected.parent_id ?? t('orgs.rootNode')}
                      </dd>
                    </div>
                  </dl>
                )}

                {activeTab === 'members' && (
                  <div>
                    {/* Add member button */}
                    <div className="mb-4 flex items-center justify-between">
                      <p className="text-sm text-gray-500">
                        {t('orgs.memberTotal', { total: members.total })}
                      </p>
                      <button
                        onClick={() => {
                          setShowAddMember(true)
                          setUserSearch('')
                          setUserSearchResults([])
                        }}
                        className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover"
                      >
                        <UserPlus className="h-4 w-4" />
                        {t('orgs.addMember')}
                      </button>
                    </div>

                    {/* Members table */}
                    <div className="rounded-lg border border-gray-100">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                            <th className="px-4 py-3">{t('orgs.columns.userId')}</th>
                            <th className="px-4 py-3">{t('orgs.columns.username')}</th>
                            <th className="px-4 py-3">{t('orgs.columns.displayName')}</th>
                            <th className="px-4 py-3">{t('orgs.columns.email')}</th>
                            <th className="px-4 py-3 text-right">{t('orgs.columns.actions')}</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-50">
                          {membersLoading ? (
                            <tr>
                              <td colSpan={5} className="px-4 py-8 text-center text-sm text-gray-400">
                                <Loader2 className="mx-auto h-5 w-5 animate-spin text-gray-300" />
                              </td>
                            </tr>
                          ) : members.items.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="px-4 py-8 text-center text-sm text-gray-400">
                                {t('orgs.emptyMembers')}
                              </td>
                            </tr>
                          ) : (
                            members.items.map((userId) => {
                              const user = memberUsers.get(userId)
                              return (
                                <tr key={userId} className="hover:bg-gray-50/50">
                                  <td className="px-4 py-3 text-sm text-gray-600">{userId}</td>
                                  <td className="px-4 py-3 text-sm font-medium text-gray-900">
                                    {user?.username ?? '-'}
                                  </td>
                                  <td className="px-4 py-3 text-sm text-gray-600">
                                    {user?.display_name ?? '-'}
                                  </td>
                                  <td className="px-4 py-3 text-sm text-gray-600">
                                    {user?.email ?? '-'}
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    <button
                                      onClick={() => setDelMemberId(userId)}
                                      className="rounded p-1 text-gray-400 hover:bg-red-50 hover:text-red-500"
                                      title={t('orgs.removeMember')}
                                    >
                                      <UserMinus className="h-4 w-4" />
                                    </button>
                                  </td>
                                </tr>
                              )
                            })
                          )}
                        </tbody>
                      </table>

                      {/* Pagination */}
                      {members.total > 0 && (
                        <div className="flex items-center justify-between border-t border-gray-100 px-4 py-3">
                          <p className="text-sm text-gray-500">
                            {t('orgs.pagingSummary', { total: members.total, page: memberPage, pages: memberTotalPages })}
                          </p>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setMemberPage((p) => Math.max(1, p - 1))}
                              disabled={memberPage <= 1}
                              className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
                            >
                              {t('orgs.prevPage')}
                            </button>
                            <button
                              onClick={() => setMemberPage((p) => Math.min(memberTotalPages, p + 1))}
                              disabled={memberPage >= memberTotalPages}
                              className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
                            >
                              {t('orgs.nextPage')}
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex h-48 items-center justify-center text-sm text-gray-400">
              {t('orgs.selectNodeHint')}
            </div>
          )}
        </div>
      </div>

      {/* ───── Create Child Modal ───── */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
          >
            <h3 className="mb-4 text-lg font-semibold">
              {selected ? t('orgs.createModal.titleWithParent', { name: selected.name }) : t('orgs.createModal.title')}
            </h3>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('orgs.createModal.nameRequired')}</label>
                <input
                  type="text"
                  value={createForm.name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
                <p className="mt-1 text-xs text-gray-400">{t('orgs.createModal.nameHint')}</p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('orgs.createModal.codeRequired')}</label>
                <input
                  type="text"
                  value={createForm.code}
                  onChange={(e) => setCreateForm((f) => ({ ...f, code: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
                <p className="mt-1 text-xs text-gray-400">
                  {t('orgs.createModal.codeHint1')}<code className="rounded bg-gray-100 px-1">tech-team</code>{t('orgs.createModal.codeHint2')}<code className="rounded bg-gray-100 px-1">root.tech-team</code>{t('orgs.createModal.codeHint3')}<span className="text-amber-600">{t('orgs.createModal.codeImmutable')}</span>
                </p>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowCreate(false)}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={creating}>
                  {t('orgs.createModal.createBtn')}
                </Button>
              </div>
            </form>
          </motion.div>
        </div>
      )}

      {/* ───── Edit Modal ───── */}
      {showEdit && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl"
          >
            <h3 className="mb-4 text-lg font-semibold">{t('orgs.editModal.title')}</h3>
            <form onSubmit={handleEdit} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('orgs.editModal.nameLabel')}</label>
                <input
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                  autoFocus
                />
                <p className="mt-1 text-xs text-gray-400">{t('orgs.editModal.nameHint')}</p>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowEdit(false)}>
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

      {/* ───── Move Org Modal ───── */}
      {showMove && selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-md rounded-xl bg-white shadow-xl"
          >
            <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
              <h3 className="text-lg font-semibold">
                {t('orgs.moveModal.title', { name: selected.name })}
              </h3>
              <button
                onClick={() => {
                  setShowMove(false)
                  setMoveTargetId(null)
                }}
                className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="px-6 py-4">
              <p className="mb-3 text-sm text-gray-500">
                {t('orgs.moveModal.hint')}
              </p>

              {/* Root option */}
              <button
                onClick={() => setMoveTargetId(null)}
                className={cn(
                  'mb-2 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors hover:bg-gray-100',
                  moveTargetId === null && 'bg-primary/10 text-primary font-medium'
                )}
              >
                <Building2 className="h-4 w-4 shrink-0 text-gray-400" />
                <span>{t('orgs.rootNode')}</span>
              </button>

              {/* Tree selector */}
              <div className="max-h-64 overflow-y-auto rounded-lg border border-gray-100 p-2">
                {tree.map((node) => (
                  <SelectableTreeNode
                    key={node.id}
                    node={node}
                    selectedId={moveTargetId}
                    disabledId={selected.id}
                    onSelect={(id) => setMoveTargetId(id)}
                  />
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3 border-t border-gray-100 px-6 py-4">
              <Button
                variant="secondary"
                onClick={() => {
                  setShowMove(false)
                  setMoveTargetId(null)
                }}
              >
                {t('common.cancel')}
              </Button>
              <Button onClick={handleMove} loading={moving}>
                {t('orgs.moveModal.confirmBtn')}
              </Button>
            </div>
          </motion.div>
        </div>
      )}

      {/* ───── Add Member Modal ───── */}
      {showAddMember && selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-lg rounded-xl bg-white shadow-xl"
          >
            <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
              <h3 className="text-lg font-semibold">{t('orgs.addMemberModal.title', { name: selected.name })}</h3>
              <button
                onClick={() => {
                  setShowAddMember(false)
                  setUserSearch('')
                  setUserSearchResults([])
                }}
                className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="px-6 py-4">
              {/* Search input */}
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  value={userSearch}
                  onChange={(e) => handleUserSearch(e.target.value)}
                  placeholder={t('orgs.addMemberModal.searchPlaceholder')}
                  className="w-full rounded-lg border border-gray-200 py-2 pl-10 pr-4 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  autoFocus
                />
              </div>

              {/* Results */}
              <div className="max-h-72 overflow-y-auto">
                {userSearchLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-5 w-5 animate-spin text-gray-300" />
                  </div>
                ) : userSearchResults.length === 0 ? (
                  <p className="py-8 text-center text-sm text-gray-400">
                    {userSearch.trim() ? t('orgs.addMemberModal.noMatch') : t('orgs.addMemberModal.noCandidates')}
                  </p>
                ) : (
                  <div className="space-y-1">
                    {userSearchResults.map((user) => {
                      const alreadyMember = members.items.includes(user.id)
                      return (
                        <div
                          key={user.id}
                          className="flex items-center justify-between rounded-lg px-3 py-2 hover:bg-gray-50"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-medium text-gray-900">
                              {user.display_name || user.username}
                            </p>
                            <p className="text-xs text-gray-500">
                              {user.username}
                              {user.email ? ` / ${user.email}` : ''}
                            </p>
                          </div>
                          {alreadyMember ? (
                            <span className="shrink-0 rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-500">
                              {t('orgs.addMemberModal.added')}
                            </span>
                          ) : (
                            <button
                              onClick={() => handleAddMember(user.id)}
                              disabled={addingMemberId === user.id}
                              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-primary px-3 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/5 disabled:opacity-60"
                            >
                              {addingMemberId === user.id ? (
                                <Loader2 className="h-3 w-3 animate-spin" />
                              ) : (
                                <Plus className="h-3 w-3" />
                              )}
                              {t('orgs.addMemberModal.addBtn')}
                            </button>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end border-t border-gray-100 px-6 py-4">
              <Button
                variant="secondary"
                onClick={() => {
                  setShowAddMember(false)
                  setUserSearch('')
                  setUserSearchResults([])
                }}
              >
                {t('common.close')}
              </Button>
            </div>
          </motion.div>
        </div>
      )}

      <ConfirmDialog
        open={showDeleteOrg}
        title={t('orgs.confirmDeleteOrg', { name: selected?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingOrg}
        onConfirm={confirmDeleteOrg}
        onCancel={() => setShowDeleteOrg(false)}
      />
      <ConfirmDialog
        open={!!delMemberId}
        title={t('orgs.confirmRemoveMember', { label: delMemberLabel })}
        loading={removingMember}
        onConfirm={confirmRemoveMember}
        onCancel={() => setDelMemberId(null)}
      />
    </motion.div>
  )
}
