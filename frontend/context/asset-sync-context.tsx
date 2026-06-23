'use client'

/**
 * AssetSyncProvider — mirrors ScanSyncContext for asset discoveries.
 *
 * Responsibilities:
 * 1. Listen to users/{uid}/discoveries for active discoveries.
 * 2. Open one SSE connection per active discovery.
 * 3. Write each new asset immediately to users/{uid}/assets/{assetId}.
 * 4. Debounce-write discovery status/progress/logs every 2s (0ms on terminal).
 */

import { createContext, useEffect, useRef, useState } from 'react'
import {
  listenToDiscoveries,
  updateFirestoreDiscovery,
  writeAsset,
  ACTIVE_DISCOVERY_STATUSES,
  type FirestoreDiscovery,
  type FirestoreAsset,
} from '@/lib/firestore-assets'
import { discoveryStreamUrl, type ApiAsset } from '@/lib/api-assets'
import { useAuth } from '@/context/auth-context'

export const AssetSyncContext = createContext<null>(null)

interface DiscConn {
  es: EventSource
  lastAssetCount: number
  domain: string
}

function toFirestoreAsset(a: ApiAsset): FirestoreAsset {
  return {
    assetId:      a.assetId,
    discoveryId:  a.discoveryId,
    domain:       a.domain,
    subdomain:    a.subdomain,
    alive:        a.alive,
    statusCode:   a.statusCode ?? undefined,
    title:        a.title ?? undefined,
    server:       a.server ?? undefined,
    ip:           a.ip ?? undefined,
    contentType:  a.contentType ?? undefined,
    technologies: a.technologies ?? [],
    url:          a.url ?? undefined,
    createdAt:    a.createdAt,
  }
}

export function AssetSyncProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const [discoveries, setDiscoveries] = useState<FirestoreDiscovery[]>([])

  const connectionsRef  = useRef<Map<string, DiscConn>>(new Map())
  const statusTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  // Firestore realtime listener for all discoveries
  useEffect(() => {
    if (!user) return
    return listenToDiscoveries(user.uid, setDiscoveries)
  }, [user])

  // SSE management + Firestore writes
  useEffect(() => {
    if (!user) return

    const uid = user.uid
    const connections  = connectionsRef.current
    const statusTimers = statusTimersRef.current

    // Open SSE for newly active discoveries
    for (const disc of discoveries) {
      if (!ACTIVE_DISCOVERY_STATUSES.has(disc.status)) continue
      if (connections.has(disc.discoveryId)) continue

      const { discoveryId, domain } = disc
      const es = new EventSource(discoveryStreamUrl(discoveryId))
      const conn: DiscConn = { es, lastAssetCount: 0, domain }
      connections.set(discoveryId, conn)

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string)
          const currentConn = connections.get(discoveryId)
          if (!currentConn) return

          // Write every NEW asset immediately to Firestore
          const allAssets: ApiAsset[] = data.assets ?? []
          if (allAssets.length > currentConn.lastAssetCount) {
            allAssets.slice(currentConn.lastAssetCount).forEach((a) => {
              writeAsset(uid, toFirestoreAsset(a)).catch(() => {})
            })
            currentConn.lastAssetCount = allAssets.length
          }

          // Debounce discovery metadata writes
          const isTerminal = !ACTIVE_DISCOVERY_STATUSES.has(data.status)
          const existing = statusTimers.get(discoveryId)
          if (existing) clearTimeout(existing)

          const updates: Partial<FirestoreDiscovery> = {
            status:          data.status,
            currentStep:     data.currentStep,
            subdomainsFound: data.subdomainsFound ?? 0,
            liveAssets:      data.liveAssets ?? 0,
            logs:            data.logs ?? [],
            error:           data.error ?? undefined,
          }
          if (isTerminal) updates.completedAt = new Date().toISOString()

          const timer = setTimeout(
            () => {
              updateFirestoreDiscovery(uid, discoveryId, updates).catch(() => {})
              statusTimers.delete(discoveryId)
            },
            isTerminal ? 0 : 2000,
          )
          statusTimers.set(discoveryId, timer)

          if (isTerminal) {
            es.close()
            connections.delete(discoveryId)
          }
        } catch {
          // ignore JSON parse errors
        }
      }

      es.onerror = () => {
        es.close()
        connections.delete(discoveryId)
      }
    }

    // Close connections for discoveries no longer active
    for (const [discId, conn] of Array.from(connections.entries())) {
      const disc = discoveries.find((d) => d.discoveryId === discId)
      if (!disc || !ACTIVE_DISCOVERY_STATUSES.has(disc.status)) {
        conn.es.close()
        connections.delete(discId)
      }
    }
  }, [discoveries, user])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      for (const conn of connectionsRef.current.values()) conn.es.close()
      connectionsRef.current.clear()
      for (const t of statusTimersRef.current.values()) clearTimeout(t)
      statusTimersRef.current.clear()
    }
  }, [])

  return <AssetSyncContext.Provider value={null}>{children}</AssetSyncContext.Provider>
}
