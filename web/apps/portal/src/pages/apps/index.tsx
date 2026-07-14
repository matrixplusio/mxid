import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { portalApi, protocolLabel, AppIcon, useSSE, useTranslation } from '@mxid/shared'
import { Modal, Button, Field, Input } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import type { PortalApp, PortalAppGroup } from '@mxid/shared'
import {
  AlertCircle,
  ExternalLink,
  GripVertical,
  KeyRound,
  LayoutGrid,
  Loader2,
  Search,
  Star,
  Clock,
} from 'lucide-react'

// Sidebar entries are either one of three reserved string keys or a real
// group ID. Group IDs are string-typed because the backend emits int64
// Snowflakes as JSON strings — they overflow 2^53 if kept numeric. The
// three reserved labels cannot collide with numeric strings.
type SidebarKey = 'favorites' | 'recent' | 'all' | string

interface SectionView {
  id: SidebarKey
  name: string
  apps: PortalApp[]
}

// Canonical environment ordering for portal sub-grouping. Values are compared
// lower-cased; anything not listed is a custom env sorted after these.
const ENV_ORDER = ['prod', 'uat', 'qa', 'staging', 'dev']

// useExtInstalled detects the MXID Login extension. The extension's content
// script tags <html data-mxid-login-ext> (+ fires a 'mxid-login-ext' event) on
// the portal origin. Returns null while checking, then true/false.
function useExtInstalled(): boolean | null {
  const [installed, setInstalled] = useState<boolean | null>(null)
  useEffect(() => {
    const present = () => document.documentElement.hasAttribute('data-mxid-login-ext')
    if (present()) { setInstalled(true); return }
    const onEvt = () => setInstalled(true)
    window.addEventListener('mxid-login-ext', onEvt)
    // The content script sets the marker at document_idle — poll ~3s before
    // concluding it's absent.
    let n = 0
    const iv = setInterval(() => {
      if (present()) { setInstalled(true); clearInterval(iv) }
      else if (++n > 15) { setInstalled(false); clearInterval(iv) }
    }, 200)
    return () => { window.removeEventListener('mxid-login-ext', onEvt); clearInterval(iv) }
  }, [])
  return installed
}

export default function AppsPage() {
  const { t } = useTranslation()
  const UNGROUPED_LABEL = t('portal.ungrouped')
  const [apps, setApps] = useState<PortalApp[]>([])
  const [groups, setGroups] = useState<PortalAppGroup[]>([])
  // `favoriteOrder` is the canonical list the server stored; `favoriteSet`
  // is a O(1) lookup for the toggle-star button on every card. Both update
  // together to avoid render-time drift.
  const [favoriteOrder, setFavoriteOrder] = useState<string[]>([])
  const [favoriteSet, setFavoriteSet] = useState<Set<string>>(new Set())
  const [recent, setRecent] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [launching, setLaunching] = useState<string | null>(null)
  const [selected, setSelected] = useState<SidebarKey>('all')
  const [query, setQuery] = useState('')
  const [dragId, setDragId] = useState<string | null>(null)
  // Form-fill (SWA): the app whose per-user credential the user is editing.
  const [credApp, setCredApp] = useState<PortalApp | null>(null)
  // MXID Login extension detection + setup guide.
  const extInstalled = useExtInstalled()
  const [showSetup, setShowSetup] = useState(false)
  const hasFormApp = useMemo(() => apps.some((a) => a.protocol === 'form'), [apps])

  const fetchAll = useCallback(async () => {
    try {
      const [appsRes, groupsRes, favRes, recentRes] = await Promise.all([
        portalApi.listApps(),
        portalApi.listAppGroups(),
        portalApi.listFavorites(),
        portalApi.listRecentApps(4),
      ])
      setApps(appsRes)
      setGroups(groupsRes)
      setFavoriteOrder(favRes)
      setFavoriteSet(new Set(favRes))
      setRecent(recentRes)
      setError('')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('common.loading'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAll()
  }, [fetchAll])

  useSSE({
    apps_updated: () => fetchAll(),
  })

  // Index for O(1) lookups.
  const appById = useMemo(() => {
    const m = new Map<string, PortalApp>()
    apps.forEach(a => m.set(a.id, a))
    return m
  }, [apps])

  const groupNameById = useMemo(() => {
    const m = new Map<string, string>()
    groups.forEach(g => m.set(g.id, g.name))
    return m
  }, [groups])

  // Client-side filter by search box.
  const filteredApps = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return apps
    return apps.filter(
      a =>
        a.name.toLowerCase().includes(q) ||
        a.code.toLowerCase().includes(q) ||
        (a.description ?? '').toLowerCase().includes(q),
    )
  }, [apps, query])

  // App groups are flat — one level only. parent_id was a previous-iteration
  // design and is intentionally ignored from here on.

  // Right-pane sections depend on which sidebar entry is selected.
  const sections: SectionView[] = useMemo(() => {
    if (selected === 'favorites') {
      // Render favorites in user-defined order (drag-drop persists via
      // /apps/favorites/order). filteredApps is used as the lookup so the
      // search query still narrows results, but the SORT comes from
      // favoriteOrder.
      const inFilter = new Set(filteredApps.map(a => a.id))
      const favApps = favoriteOrder
        .filter(id => inFilter.has(id))
        .map(id => appById.get(id))
        .filter((a): a is PortalApp => !!a)
      return [{ id: 'favorites', name: t('portal.favorites'), apps: favApps }]
    }
    if (selected === 'recent') {
      const recentApps = recent
        .map(id => appById.get(id))
        .filter((a): a is PortalApp => !!a)
        // Drop ones filtered out by the search query.
        .filter(a => filteredApps.includes(a))
      return [{ id: 'recent', name: t('portal.recent'), apps: recentApps }]
    }
    if (selected !== 'all' && selected !== 'favorites' && selected !== 'recent') {
      const gid = selected
      const groupApps = filteredApps.filter(a => a.group_ids?.includes(gid))
      return [{ id: gid, name: groupNameById.get(gid) ?? '', apps: groupApps }]
    }
    // "All" view: render one section per non-empty group, plus an
    // "未分组" bucket. Apps belonging to multiple groups appear in each
    // — same behavior as Okta when tags overlap.
    const sortedGroups = [...groups].sort((a, b) => a.sort_order - b.sort_order)
    const out: SectionView[] = []
    for (const g of sortedGroups) {
      const inGroup = filteredApps.filter(a => a.group_ids?.includes(g.id))
      if (inGroup.length > 0) out.push({ id: g.id, name: g.name, apps: inGroup })
    }
    const ungrouped = filteredApps.filter(a => !a.group_ids || a.group_ids.length === 0)
    if (ungrouped.length > 0) {
      out.push({ id: 'all', name: UNGROUPED_LABEL, apps: ungrouped })
    }
    return out
  }, [appById, favoriteOrder, favoriteSet, filteredApps, groupNameById, groups, recent, selected])

  // Recent-used ribbon (shown only on "全部" with no active search).
  const recentRibbonApps = useMemo(() => {
    if (selected !== 'all' || query.trim()) return []
    return recent
      .map(id => appById.get(id))
      .filter((a): a is PortalApp => !!a)
      .slice(0, 4)
  }, [appById, query, recent, selected])

  // App groups are flat — one level only by product decision. Sort by
  // admin-controlled sort_order to keep the sidebar deterministic.
  const sortedGroups = useMemo(
    () => [...groups].sort((a, b) => a.sort_order - b.sort_order),
    [groups],
  )

  const handleLaunch = async (app: PortalApp) => {
    if (launching) return
    setLaunching(app.id)
    // Open the tab NOW, synchronously inside the click gesture. A window.open()
    // AFTER `await` is treated as non-user-initiated and silently killed by the
    // popup blocker (the "clicking does nothing" bug). We open about:blank here,
    // sever its opener (tabnabbing defense — replaces the noopener flag, which
    // would make open() return null and leave us nothing to navigate), then
    // point it at the resolved launch URL once the API returns.
    const win = window.open('about:blank', '_blank')
    if (win) win.opener = null
    try {
      const { launch_url } = await portalApi.launchApp(app.id)
      if (win) win.location.replace(launch_url)
      else window.location.assign(launch_url) // popup blocked → same-tab fallback
      // Best-effort refresh of recent — server has logged the launch.
      portalApi
        .listRecentApps(4)
        .then(setRecent)
        .catch(() => {})
    } catch (err: unknown) {
      if (win) win.close()
      const msg = err instanceof Error ? err.message : t('portal.launchFailed')
      toast.error(t('portal.launchFailed'), msg)
    } finally {
      setLaunching(null)
    }
  }

  const toggleFavorite = async (app: PortalApp, e: React.MouseEvent) => {
    e.stopPropagation()
    const wasFav = favoriteSet.has(app.id)
    // Optimistic update — touch both set + order so order stays canonical.
    setFavoriteSet(prev => {
      const next = new Set(prev)
      if (wasFav) next.delete(app.id)
      else next.add(app.id)
      return next
    })
    setFavoriteOrder(prev => (wasFav ? prev.filter(id => id !== app.id) : [...prev, app.id]))
    try {
      if (wasFav) {
        await portalApi.removeFavorite(app.id)
        toast.success(t('portal.favoriteRemoved'), app.name)
      } else {
        await portalApi.addFavorite(app.id)
        toast.success(t('portal.favoriteAdded'), app.name)
      }
    } catch (err: unknown) {
      // Roll back on failure.
      setFavoriteSet(prev => {
        const next = new Set(prev)
        if (wasFav) next.add(app.id)
        else next.delete(app.id)
        return next
      })
      setFavoriteOrder(prev =>
        wasFav ? [...prev, app.id] : prev.filter(id => id !== app.id),
      )
      const msg = err instanceof Error ? err.message : t('common.failed')
      toast.error(t('portal.favoriteFailed'), msg)
    }
  }

  // HTML5 drag-and-drop: keep deps zero. onDragOver swaps the dragged ID
  // ahead of the target; commit to server once the drop happens. Failures
  // roll back to the server's last-known order via a re-fetch.
  const handleDragStart = (id: string) => setDragId(id)
  const handleDragEnter = (overId: string) => {
    if (dragId == null || dragId === overId) return
    setFavoriteOrder(prev => {
      const from = prev.indexOf(dragId)
      const to = prev.indexOf(overId)
      if (from < 0 || to < 0) return prev
      const next = prev.slice()
      next.splice(from, 1)
      next.splice(to, 0, dragId)
      return next
    })
  }
  const handleDragEnd = async () => {
    const finalOrder = favoriteOrder
    setDragId(null)
    try {
      await portalApi.reorderFavorites(finalOrder)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('portal.favoriteSaveOrderFailed')
      toast.error(t('portal.favoriteSaveFailed'), msg)
      // Re-fetch authoritative order to undo any optimistic drift.
      portalApi
        .listFavorites()
        .then(ids => {
          setFavoriteOrder(ids)
          setFavoriteSet(new Set(ids))
        })
        .catch(() => {})
    }
  }


  const protocolBadge = (protocol: string) => {
    const colors: Record<string, string> = {
      oidc: 'bg-blue-100 text-blue-700',
      saml: 'bg-purple-100 text-purple-700',
      cas: 'bg-teal-100 text-teal-700',
      jwt: 'bg-amber-100 text-amber-700',
      form: 'bg-surface-muted text-ink',
    }
    return colors[protocol] || 'bg-surface-muted text-muted'
  }

  const appIconValue = (app: PortalApp) => app.logo_url || app.icon || ''

  // Within a project (app group) the portal sub-groups apps by environment.
  // Canonical order keeps prod first; unknown custom envs sort after the known
  // ones (alphabetically), and unlabelled apps go last.
  const bucketAppsByEnv = (list: PortalApp[]): { env: string; apps: PortalApp[] }[] => {
    const buckets = new Map<string, PortalApp[]>()
    for (const a of list) {
      const key = (a.env || '').toLowerCase()
      const arr = buckets.get(key)
      if (arr) arr.push(a)
      else buckets.set(key, [a])
    }
    const rank = (env: string) => {
      const i = ENV_ORDER.indexOf(env)
      if (i !== -1) return i
      return env ? ENV_ORDER.length : ENV_ORDER.length + 1 // custom before unlabelled
    }
    return [...buckets.entries()]
      .map(([env, apps]) => ({ env, apps }))
      .sort((a, b) => rank(a.env) - rank(b.env) || a.env.localeCompare(b.env))
  }

  const renderCards = (list: PortalApp[], draggable: boolean) => (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {list.map((app, i) => (
        <AppCard
          key={app.id}
          app={app}
          delay={i * 0.04}
          launching={launching === app.id}
          isFavorite={favoriteSet.has(app.id)}
          protocolBadgeClass={protocolBadge(app.protocol)}
          iconValue={appIconValue(app)}
          draggable={draggable}
          dragging={dragId === app.id}
          onLaunch={() => handleLaunch(app)}
          onToggleFavorite={e => toggleFavorite(app, e)}
          onManageCred={e => { e.stopPropagation(); setCredApp(app) }}
          onDragStart={() => handleDragStart(app.id)}
          onDragEnter={() => handleDragEnter(app.id)}
          onDragEnd={handleDragEnd}
        />
      ))}
    </div>
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-32 text-muted">
        <AlertCircle className="h-10 w-10 text-red-400" />
        <p className="text-sm">{error}</p>
      </div>
    )
  }

  const favCount = favoriteSet.size
  const recentCount = recent.length

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Top bar: search + title */}
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ink">{t('portal.appsTitle')}</h1>
          <p className="mt-0.5 text-xs text-muted">
            {t('portal.appsHint')}
          </p>
        </div>
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={t('portal.searchPlaceholder')}
            className="w-full rounded-lg border border-border bg-surface py-2 pl-9 pr-3 text-sm text-ink outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-primary/15"
          />
        </div>
      </div>

      {hasFormApp && extInstalled === false && (
        <div className="mb-5 flex flex-col gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2 text-sm text-amber-800">
            <KeyRound className="h-4 w-4 shrink-0" />
            <span>{t('portal.extBanner.text')}</span>
          </div>
          <button
            onClick={() => setShowSetup(true)}
            className="shrink-0 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-amber-700"
          >
            {t('portal.extBanner.action')}
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[200px_1fr]">
        {/* Sidebar */}
        <aside className="lg:sticky lg:top-4 lg:max-h-[calc(100vh-6rem)] lg:overflow-y-auto">
          <nav className="flex flex-row gap-2 overflow-x-auto lg:flex-col lg:gap-1">
            <SideItem
              active={selected === 'favorites'}
              icon={<Star className="h-4 w-4" />}
              label={t('portal.favorites')}
              count={favCount}
              onClick={() => setSelected('favorites')}
            />
            <SideItem
              active={selected === 'recent'}
              icon={<Clock className="h-4 w-4" />}
              label={t('portal.recent')}
              count={recentCount}
              onClick={() => setSelected('recent')}
            />
            <SideItem
              active={selected === 'all'}
              icon={<LayoutGrid className="h-4 w-4" />}
              label={t('common.all')}
              count={apps.length}
              onClick={() => setSelected('all')}
            />
            <div className="hidden h-px w-full bg-surface-muted lg:block" />
            {sortedGroups.map(g => (
              <SideItem
                key={g.id}
                active={selected === g.id}
                label={g.name}
                count={g.app_count}
                onClick={() => setSelected(g.id)}
              />
            ))}
          </nav>
        </aside>

        {/* Content */}
        <div className="min-w-0">
          {/* Recent ribbon — only on All + no search */}
          {recentRibbonApps.length > 0 && (
            <section className="mb-6">
              <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted">
                <Clock className="h-3.5 w-3.5" /> {t('portal.recent')}
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
                {recentRibbonApps.map(app => (
                  <CompactAppCard
                    key={app.id}
                    app={app}
                    launching={launching === app.id}
                    onLaunch={() => handleLaunch(app)}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Sections */}
          {sections.length === 0 || sections.every(s => s.apps.length === 0) ? (
            <EmptyState selected={selected} hasQuery={!!query.trim()} />
          ) : (
            sections.map(section => (
              <section key={String(section.id)} className="mb-7">
                <div className="mb-3 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-ink">
                    {section.name}
                    <span className="ml-2 text-xs font-normal text-faint">
                      {section.apps.length}
                    </span>
                  </h2>
                </div>
                {section.apps.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-border px-4 py-6 text-center text-xs text-faint">
                    {t('portal.appsEmpty')}
                  </div>
                ) : (() => {
                  // favorites/recent keep their own ordering (drag / recency);
                  // only project (group) sections sub-group by environment, and
                  // only when the section actually spans more than one env.
                  const canSubGroup = section.id !== 'favorites' && section.id !== 'recent'
                  const buckets = canSubGroup ? bucketAppsByEnv(section.apps) : []
                  if (!canSubGroup || buckets.length <= 1) {
                    return renderCards(section.apps, section.id === 'favorites')
                  }
                  return (
                    <div className="space-y-4">
                      {buckets.map(bucket => (
                        <div key={bucket.env || '_unlabelled'}>
                          <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-faint">
                            {bucket.env || t('portal.envUnlabelled')}
                            <span className="font-normal normal-case">{bucket.apps.length}</span>
                          </h3>
                          {renderCards(bucket.apps, false)}
                        </div>
                      ))}
                    </div>
                  )
                })()}
              </section>
            ))
          )}
        </div>
      </div>

      {credApp && (
        <CredentialModal
          app={credApp}
          onClose={() => setCredApp(null)}
        />
      )}

      {showSetup && <ExtSetupModal onClose={() => setShowSetup(false)} />}
    </motion.div>
  )
}

// ExtSetupModal — the in-app install tutorial for the MXID Login extension. The
// portal cannot install it (browsers block web-page installs); this guides the
// user. The CRX itself is served/pushed by the deployment (managed policy or a
// download link the admin provides).
function ExtSetupModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Modal open title={t('portal.extSetup.title')} onClose={onClose}>
      <div className="space-y-4 text-sm text-ink">
        <p className="text-muted">{t('portal.extSetup.intro')}</p>
        <ol className="list-decimal space-y-2 pl-5">
          <li>{t('portal.extSetup.step1')}</li>
          <li>{t('portal.extSetup.step2')}</li>
          <li>{t('portal.extSetup.step3')}</li>
        </ol>
        <p className="rounded-lg bg-surface-muted px-3 py-2 text-xs text-muted">
          {t('portal.extSetup.note')}
        </p>
        <div className="flex justify-end">
          <Button type="button" onClick={onClose}>{t('common.close')}</Button>
        </div>
      </div>
    </Modal>
  )
}

// CredentialModal lets a user store or clear their own downstream credential for
// a form-fill (SWA) app. The browser extension auto-submits it on launch; the
// plaintext is never read back into the portal (reveal is extension-only).
function CredentialModal({ app, onClose }: { app: PortalApp; onClose: () => void }) {
  const { t } = useTranslation()
  const [account, setAccount] = useState('')
  const [credential, setCredential] = useState('')
  const [saving, setSaving] = useState(false)

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!account || !credential) return
    setSaving(true)
    try {
      await portalApi.setAppCredential(app.id, { account, credential })
      toast.success(t('portal.formCred.saved'))
      onClose()
    } catch (err) {
      toast.error(t('portal.formCred.saveFailed'), extractMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const clear = async () => {
    setSaving(true)
    try {
      await portalApi.deleteAppCredential(app.id)
      toast.success(t('portal.formCred.cleared'))
      onClose()
    } catch (err) {
      toast.error(t('portal.formCred.clearFailed'), extractMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open title={t('portal.formCred.title', { name: app.name })} onClose={onClose}>
      <form onSubmit={save} className="space-y-4">
        <p className="text-xs text-muted">{t('portal.formCred.hint')}</p>
        <Field label={t('portal.formCred.account')}>
          <Input value={account} onChange={e => setAccount(e.target.value)} autoComplete="off" required />
        </Field>
        <Field label={t('portal.formCred.password')}>
          <Input type="password" value={credential} onChange={e => setCredential(e.target.value)} autoComplete="new-password" required />
        </Field>
        <div className="flex items-center justify-between pt-2">
          <Button type="button" variant="ghost" onClick={clear} disabled={saving}>
            {t('portal.formCred.clear')}
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="secondary" onClick={onClose} disabled={saving}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={saving}>{t('common.save')}</Button>
          </div>
        </div>
      </form>
    </Modal>
  )
}

interface SideItemProps {
  active: boolean
  icon?: React.ReactNode
  label: string
  count: number
  depth?: number
  hasChildren?: boolean
  isExpanded?: boolean
  onClick: () => void
  onToggleExpand?: () => void
}

function SideItem({
  active,
  icon,
  label,
  count,
  depth = 0,
  hasChildren = false,
  isExpanded = false,
  onClick,
  onToggleExpand,
}: SideItemProps) {
  const { t } = useTranslation()
  return (
    <button
      onClick={onClick}
      style={{ paddingLeft: depth > 0 ? `${0.75 + depth * 0.75}rem` : undefined }}
      className={`group inline-flex shrink-0 items-center justify-between gap-2 rounded-lg px-3 py-2 text-left text-sm transition lg:w-full ${
        active
          ? 'bg-primary/10 text-primary font-medium'
          : 'text-muted hover:bg-surface-muted hover:text-ink'
      }`}
    >
      <span className="inline-flex items-center gap-2 truncate">
        {hasChildren && (
          <span
            role="button"
            tabIndex={0}
            onClick={e => {
              e.stopPropagation()
              onToggleExpand?.()
            }}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.stopPropagation()
                onToggleExpand?.()
              }
            }}
            className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded text-faint hover:bg-surface-muted"
            title={isExpanded ? t('portal.collapse') : t('portal.expand')}
          >
            <span className="text-[10px]">{isExpanded ? '▾' : '▸'}</span>
          </span>
        )}
        {icon}
        <span className="truncate">{label}</span>
      </span>
      <span
        className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] tabular-nums ${
          active ? 'bg-primary/15 text-primary' : 'bg-surface-muted text-muted'
        }`}
      >
        {count}
      </span>
    </button>
  )
}

interface AppCardProps {
  app: PortalApp
  delay: number
  launching: boolean
  isFavorite: boolean
  protocolBadgeClass: string
  iconValue: string
  draggable?: boolean
  dragging?: boolean
  onLaunch: () => void
  onToggleFavorite: (e: React.MouseEvent) => void
  onManageCred?: (e: React.MouseEvent) => void
  onDragStart?: () => void
  onDragEnter?: () => void
  onDragEnd?: () => void
}

function AppCard({
  app,
  delay,
  launching,
  isFavorite,
  protocolBadgeClass,
  iconValue,
  draggable,
  dragging,
  onLaunch,
  onToggleFavorite,
  onManageCred,
  onDragStart,
  onDragEnter,
  onDragEnd,
}: AppCardProps) {
  const { t } = useTranslation()
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay }}
      draggable={draggable}
      onDragStart={onDragStart}
      onDragEnter={onDragEnter}
      onDragOver={e => e.preventDefault()}
      onDragEnd={onDragEnd}
      className={`group relative h-full ${dragging ? 'opacity-40' : ''}`}
    >
      <button
        onClick={onLaunch}
        disabled={launching}
        className={`flex h-full w-full items-start gap-4 rounded-xl border border-border bg-surface p-5 text-left transition-all hover:border-primary/30 hover:shadow-md hover:shadow-primary/5 disabled:opacity-60 ${draggable ? 'cursor-grab active:cursor-grabbing' : ''}`}
      >
        {draggable && (
          <GripVertical className="mt-1 h-4 w-4 shrink-0 text-faint group-hover:text-faint" />
        )}
        <AppIcon value={iconValue} fallbackName={app.name} size={48} className="rounded-xl" />
        <div className="min-w-0 flex-1">
          <div className="flex min-h-[2.5rem] items-start gap-2">
            <h3 className="line-clamp-2 text-sm font-semibold text-ink" title={app.name}>{app.name}</h3>
            <span
              className={`mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${protocolBadgeClass}`}
            >
              {protoLabelLocalized(t, app.protocol)}
            </span>
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-muted">
            {app.description || t('portal.noDesc')}
          </p>
        </div>
        <div className="absolute right-4 top-5 text-faint transition-colors group-hover:text-primary">
          {launching ? <Loader2 className="h-4 w-4 animate-spin" /> : <ExternalLink className="h-4 w-4" />}
        </div>
      </button>
      <button
        type="button"
        onClick={onToggleFavorite}
        title={isFavorite ? t('portal.favoriteRemoved') : t('portal.favoriteAdded')}
        className={`absolute right-4 bottom-4 rounded-full p-1.5 transition ${
          isFavorite
            ? 'text-amber-500 hover:bg-amber-50'
            : 'text-faint opacity-0 hover:text-amber-500 hover:bg-amber-50 group-hover:opacity-100'
        }`}
      >
        <Star className={`h-4 w-4 ${isFavorite ? 'fill-current' : ''}`} />
      </button>
      {app.protocol === 'form' && onManageCred && (
        <button
          type="button"
          onClick={onManageCred}
          title={t('portal.formCred.manage')}
          className="absolute right-12 bottom-4 rounded-full p-1.5 text-faint opacity-0 transition hover:bg-emerald-50 hover:text-emerald-600 group-hover:opacity-100"
        >
          <KeyRound className="h-4 w-4" />
        </button>
      )}
    </motion.div>
  )
}

// protoLabelLocalized localizes the descriptive protocol badges (form / link);
// OIDC / SAML / CAS keep their universal names via protocolLabel.
function protoLabelLocalized(t: (k: string) => string, protocol: string): string {
  if (protocol === 'form') return t('portal.protoForm')
  if (protocol === 'link') return t('portal.protoLink')
  return protocolLabel(protocol)
}

function CompactAppCard({
  app,
  launching,
  onLaunch,
}: {
  app: PortalApp
  launching: boolean
  onLaunch: () => void
}) {
  const { t } = useTranslation()
  const iconValue = app.logo_url || app.icon || ''
  return (
    <button
      onClick={onLaunch}
      disabled={launching}
      className="group flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-left transition hover:border-primary/30 hover:shadow-sm disabled:opacity-60"
    >
      <AppIcon value={iconValue} fallbackName={app.name} size={32} className="rounded-lg" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-ink" title={app.name}>{app.name}</div>
        <div className="truncate text-[10px] uppercase tracking-wide text-faint">
          {protoLabelLocalized(t, app.protocol)}
        </div>
      </div>
      {launching ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
      ) : (
        <ExternalLink className="h-3.5 w-3.5 text-faint group-hover:text-primary" />
      )}
    </button>
  )
}

function EmptyState({
  selected,
  hasQuery,
}: {
  selected: SidebarKey
  hasQuery: boolean
}) {
  const { t } = useTranslation()
  let label = t('portal.noApp')
  if (hasQuery) label = t('portal.noMatch')
  else if (selected === 'favorites') label = t('portal.noFavorite')
  else if (selected === 'recent') label = t('portal.noRecent')
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-faint">
      <LayoutGrid className="h-12 w-12" />
      <p className="text-sm">{label}</p>
    </div>
  )
}
