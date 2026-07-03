// Drawer (right-slide detail/edit panel) + ConfirmDialog (destructive-action
// second confirm). Modal itself lives in ./index; these build on it.
import { AnimatePresence, motion } from 'framer-motion'
import { X } from 'lucide-react'
import { useTranslation } from '@mxid/shared'
import type { ReactNode } from 'react'
import { Button, Modal } from './index'

export function Drawer({
  open,
  onClose,
  title,
  width = 480,
  children,
  footer,
}: {
  open: boolean
  onClose: () => void
  title: string
  width?: number
  children: ReactNode
  footer?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50">
          <motion.div
            className="absolute inset-0 bg-black/40"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            className="absolute right-0 top-0 flex h-full max-w-[92vw] flex-col bg-surface shadow-float"
            style={{ width }}
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'tween', duration: 0.25 }}
          >
            <div className="flex h-16 shrink-0 items-center justify-between border-b border-border px-6">
              <h3 className="text-base font-semibold text-ink">{title}</h3>
              <button
                type="button"
                onClick={onClose}
                className="rounded-control p-1 text-muted transition-colors hover:bg-surface-muted hover:text-ink"
                aria-label={t('common.close')}
              >
                <X className="h-[18px] w-[18px]" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6">{children}</div>
            {footer && (
              <div className="flex shrink-0 justify-end gap-2 border-t border-border p-4">{footer}</div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}

export function ConfirmDialog({
  open,
  title,
  desc,
  confirmText,
  danger = true,
  loading,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  desc?: ReactNode
  confirmText?: string
  danger?: boolean
  loading?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  if (!open) return null
  return (
    <Modal open={open} onClose={onCancel} title={title} size="sm">
      {desc && <p className="text-sm text-muted">{desc}</p>}
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} loading={loading}>
          {confirmText ?? t('common.confirm')}
        </Button>
      </div>
    </Modal>
  )
}
