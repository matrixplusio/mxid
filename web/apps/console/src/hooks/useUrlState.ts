import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

// useUrlState syncs a flat filter/pagination object to the URL query string, so
// list state is shareable and survives back/forward. Keys equal to their
// default are dropped from the URL to keep it clean. Number-typed defaults are
// parsed back to numbers; everything else stays a string.
//
//   const [q, setQ] = useUrlState({ page: 1, page_size: 20, keyword: '', status: '' })
//   setQ({ keyword: 'bob', page: 1 })   // → ?keyword=bob
export function useUrlState<T extends Record<string, string | number>>(
  defaults: T,
): [T, (patch: Partial<T>) => void] {
  const [sp, setSp] = useSearchParams()

  const state = useMemo(() => {
    const out = { ...defaults }
    for (const key in defaults) {
      const raw = sp.get(key)
      if (raw != null) {
        out[key] = (typeof defaults[key] === 'number' ? Number(raw) : raw) as T[Extract<keyof T, string>]
      }
    }
    return out
  }, [sp]) // eslint-disable-line react-hooks/exhaustive-deps

  const set = useCallback(
    (patch: Partial<T>) => {
      setSp(
        (prev: URLSearchParams) => {
          const next = new URLSearchParams(prev)
          for (const key in patch) {
            const v = patch[key]
            if (v === '' || v == null || v === defaults[key]) next.delete(key)
            else next.set(key, String(v))
          }
          return next
        },
        { replace: true },
      )
    },
    [setSp], // eslint-disable-line react-hooks/exhaustive-deps
  )

  return [state, set]
}
