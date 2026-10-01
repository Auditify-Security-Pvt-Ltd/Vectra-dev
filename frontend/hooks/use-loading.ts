'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Suppress a loading indicator for very short waits.
 *
 * Firestore often serves the first snapshot from cache in a few milliseconds.
 * Rendering a skeleton for that long is a flash, not feedback — so the flag
 * only flips on once `active` has held for `delayMs`.
 */
export function useDelayedLoading(active: boolean, delayMs = 180): boolean {
  const [show, setShow] = useState(false)

  useEffect(() => {
    if (!active) {
      setShow(false)
      return
    }
    const t = setTimeout(() => setShow(true), delayMs)
    return () => clearTimeout(t)
  }, [active, delayMs])

  return show
}

/**
 * Wrap an async action so it cannot be run concurrently with itself.
 *
 * Returns the in-flight flag plus a runner that ignores calls made while the
 * previous one is still pending — the guard behind "no duplicate submissions",
 * independent of whatever the button is doing visually.
 */
export function useAsyncAction<A extends unknown[]>(
  fn: (...args: A) => Promise<void>,
): [boolean, (...args: A) => Promise<void>] {
  const [pending, setPending] = useState(false)
  const inFlight = useRef(false)
  const mounted  = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const run = useCallback(async (...args: A) => {
    if (inFlight.current) return
    inFlight.current = true
    setPending(true)
    try {
      await fn(...args)
    } finally {
      inFlight.current = false
      if (mounted.current) setPending(false)
    }
  }, [fn])

  return [pending, run]
}
