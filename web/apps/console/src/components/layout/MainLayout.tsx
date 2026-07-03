import { AnimatePresence, motion } from 'framer-motion'
import { useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import { Toaster } from '../ui/toast'

const pageVariants = {
  initial: { opacity: 0, y: 8 },
  in: { opacity: 1, y: 0 },
  out: { opacity: 0, y: -8 },
}

const pageTransition = {
  type: 'tween' as const,
  ease: 'easeInOut' as const,
  duration: 0.25,
}

// Floating-panel shell: the whole app sits in a single inset rounded panel
// (not edge-to-edge). Dark sidebar column on the left, header + scrollable
// content on the right. The content area is a <main> so the dark-mode compat
// shim (.dark main …) keeps applying to legacy page markup.
export default function MainLayout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div className="h-screen bg-bg p-3 lg:p-4">
      <Toaster />
      <div className="flex h-full overflow-hidden rounded-panel border border-border bg-surface shadow-card">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Header />
          <main className="flex-1 overflow-y-auto bg-surface-muted/40">
            <AnimatePresence mode="wait">
              <motion.div
                key={location.pathname}
                initial="initial"
                animate="in"
                exit="out"
                variants={pageVariants}
                transition={pageTransition}
                className="p-6 lg:p-8"
              >
                {children}
              </motion.div>
            </AnimatePresence>
          </main>
        </div>
      </div>
    </div>
  )
}
