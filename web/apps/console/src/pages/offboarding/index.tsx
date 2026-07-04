import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { ChevronDown, ChevronRight, Check, UserX } from 'lucide-react'
import {
  offboardingApi,
  formatDate,
  useTranslation,
  type OffboardingTask,
  type OffboardingItem,
  OffboardingTaskStatus,
  OffboardingItemStatus,
} from '@mxid/shared'
import { pageMotion, Button, Card, StatusTag, LoadingState, EmptyState } from '@mxid/shared/ui'
import { toast, extractMessage } from '../../components/ui/toast'
import PageHeader from '../../components/layout/PageHeader'

export default function OffboardingPage() {
  const { t } = useTranslation()
  const [tasks, setTasks] = useState<OffboardingTask[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await offboardingApi.listTasks(1, 50)
      setTasks(res.items ?? [])
    } catch (e) {
      setError(extractMessage(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('offboarding.title')}
        description={t('offboarding.subtitle')}
        actions={
          <Button variant="secondary" onClick={load}>
            {t('common.refresh')}
          </Button>
        }
      />

      <Card className="overflow-hidden hover:shadow-card">
        {loading ? (
          <LoadingState />
        ) : error ? (
          <div className="px-6 py-12 text-center text-sm text-danger">{error}</div>
        ) : tasks.length === 0 ? (
          <EmptyState>{t('offboarding.empty')}</EmptyState>
        ) : (
          <ul className="divide-y divide-border">
            {tasks.map((task) => (
              <TaskRow
                key={task.id}
                task={task}
                open={expanded === task.id}
                onToggle={() => setExpanded(expanded === task.id ? null : task.id)}
                onItemDone={load}
              />
            ))}
          </ul>
        )}
      </Card>
    </motion.div>
  )
}

function TaskRow({
  task,
  open,
  onToggle,
  onItemDone,
}: {
  task: OffboardingTask
  open: boolean
  onToggle: () => void
  onItemDone: () => void
}) {
  const { t } = useTranslation()
  const [items, setItems] = useState<OffboardingItem[] | null>(null)
  const [loadingItems, setLoadingItems] = useState(false)
  const resolved = task.status === OffboardingTaskStatus.Resolved

  useEffect(() => {
    if (open && items === null) {
      setLoadingItems(true)
      offboardingApi
        .listItems(task.id)
        .then(setItems)
        .catch(() => setItems([]))
        .finally(() => setLoadingItems(false))
    }
  }, [open, items, task.id])

  const markDone = async (item: OffboardingItem) => {
    try {
      await offboardingApi.markItemDone(item.id)
      toast.success(t('offboarding.itemDoneOk'))
      setItems((prev) => prev?.map((i) => (i.id === item.id ? { ...i, status: 1 } : i)) ?? null)
      onItemDone()
    } catch (e) {
      toast.error(t('offboarding.itemDoneFail'), extractMessage(e))
    }
  }

  return (
    <li>
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 px-6 py-4 text-left transition-colors hover:bg-surface-muted"
      >
        {open ? <ChevronDown className="h-4 w-4 text-faint" /> : <ChevronRight className="h-4 w-4 text-faint" />}
        <UserX className="h-4 w-4 text-danger" />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-ink">{task.username || task.user_id}</div>
          <div className="text-xs text-faint">
            {formatDate(task.created_at)} · {t('offboarding.sessionsKilled', { n: task.sessions_killed })}
          </div>
        </div>
        <StatusTag tone={resolved ? 'success' : 'warning'}>
          {resolved
            ? t('offboarding.statusResolved')
            : t('offboarding.progress', { done: task.done_count, total: task.item_count })}
        </StatusTag>
      </button>

      {open && (
        <div className="border-t border-border bg-surface-muted/40 px-6 py-3">
          {loadingItems ? (
            <div className="py-3 text-center text-xs text-faint">{t('common.loading')}</div>
          ) : !items || items.length === 0 ? (
            <div className="py-3 text-center text-xs text-faint">{t('offboarding.noItems')}</div>
          ) : (
            <ul className="space-y-1">
              {items.map((item) => (
                <li
                  key={item.id}
                  className="flex items-center gap-3 rounded-lg bg-surface px-3 py-2 ring-1 ring-border"
                >
                  <span className="rounded bg-surface-muted px-1.5 py-0.5 text-[10px] font-medium text-muted">
                    {item.tier}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-ink">{item.app_name || item.app_code}</div>
                    <div className="truncate font-mono text-[11px] text-faint">{item.app_code}</div>
                  </div>
                  {item.status === OffboardingItemStatus.Done ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-success">
                      <Check className="h-3.5 w-3.5" />
                      {t('offboarding.done')}
                    </span>
                  ) : (
                    <Button size="sm" variant="secondary" onClick={() => markDone(item)}>
                      {t('offboarding.markDone')}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  )
}
