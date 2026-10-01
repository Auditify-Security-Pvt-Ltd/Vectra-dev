'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Loader for admin API reads.
 *
 * Admin data comes from HTTP rather than the Firestore listeners the rest of
 * the app uses, so it needs explicit loading/error state plus opt-in polling
 * for the live task view. A poll is skipped while the previous one is still in
 * flight, so a slow backend can't build up a queue of overlapping requests.
 */
export function useAdminData<T>(
  load: () => Promise<T>,
  opts: { pollMs?: number; deps?: unknown[] } = {},
) {
  const { pollMs = 0, deps = [] } = opts

  const [data, setData]       = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)

  const inFlight = useRef(false)
  const mounted  = useRef(true)
  const loadRef  = useRef(load)
  loadRef.current = load

  const run = useCallback(async (showSpinner: boolean) => {
    if (inFlight.current) return
    inFlight.current = true
    if (showSpinner) setLoading(true)
    try {
      const result = await loadRef.current()
      if (mounted.current) {
        setData(result)
        setError(null)
      }
    } catch (err: unknown) {
      if (mounted.current) {
        setError(err instanceof Error ? err.message : 'Request failed')
      }
    } finally {
      inFlight.current = false
      if (mounted.current && showSpinner) setLoading(false)
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    run(true)
    return () => { mounted.current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    if (!pollMs) return
    const id = setInterval(() => run(false), pollMs)
    return () => clearInterval(id)
  }, [pollMs, run])

  return { data, loading, error, refresh: () => run(false) }
}
