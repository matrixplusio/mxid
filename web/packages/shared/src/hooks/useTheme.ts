import { create } from 'zustand'

// Theme is a class strategy (.dark on <html>) with localStorage persistence.
// We deliberately do NOT follow prefers-color-scheme — once the user picks a
// mode it sticks across reloads/devices-of-the-same-browser. The FOUC guard in
// each app's index.html reads the same key before React mounts so there's no
// light-flash on a dark-preference reload.
export type ThemeMode = 'light' | 'dark'

// Keep the key in sync with the inline <script> in apps/*/index.html.
const STORAGE_KEY = 'mxid.theme'

function readStored(): ThemeMode {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'light' || v === 'dark') return v
  } catch {
    // ignore — SSR/locked storage falls back to light
  }
  return 'light'
}

// applyTheme toggles the root class. Exported so the FOUC script and tests can
// reuse the exact same behaviour.
export function applyTheme(mode: ThemeMode) {
  if (typeof document === 'undefined') return
  document.documentElement.classList.toggle('dark', mode === 'dark')
}

function persist(mode: ThemeMode) {
  try {
    localStorage.setItem(STORAGE_KEY, mode)
  } catch {
    // ignore
  }
}

interface ThemeState {
  mode: ThemeMode
  toggle: () => void
  setMode: (m: ThemeMode) => void
  // init reads the stored mode and applies it. Call once at app mount; the
  // inline FOUC script has already set the class, this syncs the store to it.
  init: () => void
}

export const useTheme = create<ThemeState>((set, get) => ({
  mode: 'light',
  toggle: () => get().setMode(get().mode === 'light' ? 'dark' : 'light'),
  setMode: (m) => {
    persist(m)
    applyTheme(m)
    set({ mode: m })
  },
  init: () => {
    const mode = readStored()
    applyTheme(mode)
    set({ mode })
  },
}))
