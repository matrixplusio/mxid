import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { ChevronDown, ChevronRight, Check, UserX } from 'lucide-react'
import {
  offboardingApi,
  formatDate,
  useTranslation,
  type OffboardingTask,
  type OffboardingItem,
} from '@mxid/shared'
import { pageMotion } from '@mxid/shared/ui'
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
      <div className="flex items-start justify-between">
        <PageHeader title={t('offboarding.title')} description={t('offboarding.subtitle')} />
        <button
          onClick={load}
          className="mt-1 rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50"
        >
          {t('common.refresh')}
        </button>
      </div>

      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        {loading ? (
          <div className="px-6 py-10 text-center text-sm text-gray-400">{t('common.loading')}</div>
        ) : error ? (
          <div className="px-6 py-12 text-center text-sm text-red-500">{error}</div>
        ) : tasks.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-gray-400">{t('offboarding.empty')}</div>
        ) : (
          <ul className="divide-y divide-gray-50">
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
      </div>
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
  const resolved = task.status === 1

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
        className="flex w-full items-center gap-3 px-6 py-4 text-left hover:bg-gray-50/60"
      >
        {open ? <ChevronDown className="h-4 w-4 text-gray-400" /> : <ChevronRight className="h-4 w-4 text-gray-400" />}
        <UserX className="h-4 w-4 text-red-500" />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-gray-900">{task.username || task.user_id}</div>
          <div className="text-xs text-gray-400">
            {formatDate(task.created_at)} · {t('offboarding.sessionsKilled', { n: task.sessions_killed })}
          </div>
        </div>
        <span
          className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
            resolved ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'
          }`}
        >
          {resolved
            ? t('offboarding.statusResolved')
            : t('offboarding.progress', { done: task.done_count, total: task.item_count })}
        </span>
      </button>

      {open && (
        <div className="border-t border-gray-50 bg-gray-50/40 px-6 py-3">
          {loadingItems ? (
            <div className="py-3 text-center text-xs text-gray-400">{t('common.loading')}</div>
          ) : !items || items.length === 0 ? (
            <div className="py-3 text-center text-xs text-gray-400">{t('offboarding.noItems')}</div>
          ) : (
            <ul className="space-y-1">
              {items.map((item) => (
                <li
                  key={item.id}
                  className="flex items-center gap-3 rounded-lg bg-white px-3 py-2 ring-1 ring-gray-100"
                >
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-500">
                    {item.tier}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-gray-800">{item.app_name || item.app_code}</div>
                    <div className="truncate font-mono text-[11px] text-gray-400">{item.app_code}</div>
                  </div>
                  {item.status === 1 ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
                      <Check className="h-3.5 w-3.5" />
                      {t('offboarding.done')}
                    </span>
                  ) : (
                    <button
                      onClick={() => markDone(item)}
                      className="rounded-lg border border-gray-200 px-2.5 py-1 text-xs font-medium text-gray-700 hover:border-emerald-400 hover:text-emerald-700"
                    >
                      {t('offboarding.markDone')}
                    </button>
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
