'use client'

/**
 * ScanSyncProvider — global background service at app-layout level.
 *
 * Writes scan metadata + findings/assets/CVEs to Firestore sub-collections
 * as SSE events arrive, and backfills completed scans once per session.
 */

import { createContext, useEffect, useRef, useState } from 'react'
import {
  listenToScans,
  updateFirestoreScan,
  ACTIVE_STATUSES,
  type FirestoreScan,
} from '@/lib/firestore-scans'
import { writeFinding, type FirestoreFinding } from '@/lib/firestore-findings'
import { writeAsset, type FirestoreAsset } from '@/lib/firestore-assets'
import { writeCve, type FirestoreCve } from '@/lib/firestore-cves'
import { API_BASE, type ApiFinding } from '@/lib/api'
import { useAuth } from '@/context/auth-context'

export const ScanSyncContext = createContext<null>(null)

interface SseConn {
  es: EventSource
  lastFindingCount: number
  lastAssetCount:   number
  lastCveCount:     number
  lastStatus:       string
  target:           string
}

function findingToDoc(
  finding: ApiFinding,
  idx: number,
  scanId: string,
  target: string,
  timestamp: string,
): FirestoreFinding {
  return {
    findingId:   `${scanId}_${String(idx).padStart(4, '0')}`,
    scanId,
    target,
    title:       finding.title,
    severity:    finding.severity,
    template:    finding.template,
    source:      finding.source ?? 'nuclei',
    description: finding.description ?? undefined,
    matchedAt:   finding.matched_at ?? undefined,
    host:        finding.host ?? undefined,
    createdAt:   timestamp,
  }
}

export function ScanSyncProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const [scans, setScans] = useState<FirestoreScan[]>([])

  const connectionsRef = useRef<Map<string, SseConn>>(new Map())
  const bulkTimersRef  = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())
  const backfilledRef  = useRef<Set<string>>(new Set())

  // ── Realtime scan listener ──────────────────────────────────────────
  useEffect(() => {
    if (!user) return
    return listenToScans(user.uid, setScans)
  }, [user])

  // ── Manage SSE connections + Firestore writes ───────────────────────
  useEffect(() => {
    if (!user) return

    const uid         = user.uid
    const connections = connectionsRef.current
    const bulkTimers  = bulkTimersRef.current
    const backfilled  = backfilledRef.current

    // Open connections for newly active scans
    for (const scan of scans) {
      if (!ACTIVE_STATUSES.has(scan.status)) continue
      if (connections.has(scan.scanId)) continue

      const scanId     = scan.scanId
      const target     = scan.target
      const isFullScan = scan.scanProfile === 'FULL_SCAN'
      const es         = new EventSource(`${API_BASE}/scan/${scanId}/stream`)
      const conn: SseConn = {
        es,
        lastFindingCount: 0,
        lastAssetCount:   0,
        lastCveCount:     0,
        lastStatus:       scan.status,
        target,
      }
      connections.set(scanId, conn)

      es.onmessage = (event) => {
        try {
          const data        = JSON.parse(event.data as string)
          const currentConn = connections.get(scanId)
          if (!currentConn) return

          const newStatus: string = data.status ?? currentConn.lastStatus
          const isTerminal        = !ACTIVE_STATUSES.has(newStatus)
          const statusChanged     = newStatus !== currentConn.lastStatus

          // ── Immediate: write status + counts on every change ───────────
          if (statusChanged) {
            currentConn.lastStatus = newStatus
            const immediateUpdate: Partial<FirestoreScan> = {
              status:        newStatus,
              progress:      data.progress ?? 0,
              currentStep:   data.currentStep ?? '',
              totalFindings: data.total_findings ?? 0,
              totalCves:     data.total_cves ?? 0,
              totalAssets:   data.total_assets ?? 0,
            }
            if (isTerminal) {
              immediateUpdate.completedAt = new Date().toISOString()
              if (data.duration) immediateUpdate.duration = data.duration
              if (data.error)    immediateUpdate.error    = data.error
            }
            updateFirestoreScan(uid, scanId, immediateUpdate).catch(() => {})
          }

          // ── Immediate: write each new finding to findings sub-collection ──
          const allFindings: ApiFinding[] = data.findings ?? []
          if (allFindings.length > currentConn.lastFindingCount) {
            const ts = new Date().toISOString()
            allFindings.slice(currentConn.lastFindingCount).forEach((f, i) => {
              const idx = currentConn.lastFindingCount + i
              writeFinding(uid, findingToDoc(f, idx, scanId, target, ts)).catch(() => {})
            })
            currentConn.lastFindingCount = allFindings.length
          }

          // ── Full Scan: write each new asset + CVE ──────────────────────
          if (isFullScan) {
            const allAssets: FirestoreAsset[] = data.assets ?? []
            if (allAssets.length > currentConn.lastAssetCount) {
              allAssets.slice(currentConn.lastAssetCount).forEach((asset) => {
                writeAsset(uid, asset).catch(() => {})
              })
              currentConn.lastAssetCount = allAssets.length
            }

            const allCves: FirestoreCve[] = data.cves ?? []
            if (allCves.length > currentConn.lastCveCount) {
              allCves.slice(currentConn.lastCveCount).forEach((cve) => {
                writeCve(uid, cve).catch(() => {})
              })
              currentConn.lastCveCount = allCves.length
            }
          }

          // ── Debounced: write bulk scan metadata (logs, findings array, etc.) ──
          const existing = bulkTimers.get(scanId)
          if (existing) clearTimeout(existing)

          const bulkUpdate: Partial<FirestoreScan> = {
            status:            newStatus,
            progress:          data.progress ?? 0,
            currentStep:       data.currentStep ?? '',
            logs:              data.logs ?? [],
            totalFindings:     data.total_findings ?? 0,
            findings:          data.findings ?? [],
            templatesExecuted: data.templatesExecuted,
            duration:          data.duration ?? undefined,
            error:             data.error ?? undefined,
            totalAssets:       data.total_assets ?? undefined,
            liveAssetsCount:   data.live_assets_count ?? undefined,
            totalCves:         data.total_cves ?? undefined,
            engines:           data.engines ?? undefined,
          }
          if (isTerminal) bulkUpdate.completedAt = new Date().toISOString()

          const timer = setTimeout(
            () => {
              updateFirestoreScan(uid, scanId, bulkUpdate).catch(() => {})
              bulkTimers.delete(scanId)
            },
            isTerminal ? 0 : 2000,
          )
          bulkTimers.set(scanId, timer)

          if (isTerminal || data.done) {
            es.close()
            connections.delete(scanId)
          }
        } catch {
          // ignore JSON parse errors
        }
      }

      es.onerror = () => {
        es.close()
        connections.delete(scanId)
      }
    }

    // Close connections for scans no longer active
    for (const [scanId, conn] of Array.from(connections.entries())) {
      const scan = scans.find((s) => s.scanId === scanId)
      if (!scan || !ACTIVE_STATUSES.has(scan.status)) {
        conn.es.close()
        connections.delete(scanId)
      }
    }

    // ── Backfill: ensure findings/CVEs/assets are in Firestore for completed scans.
    // Fetches fresh data from the backend API first; falls back to scan.findings if unavailable.
    // This handles the race where SSE was missed (fast scan completed before SSE opened).
    for (const scan of scans) {
      if (scan.status !== 'completed' && scan.status !== 'completed_timeout') continue
      if (backfilled.has(scan.scanId)) continue
      backfilled.add(scan.scanId)

      const scanId     = scan.scanId
      const target     = scan.target
      const isFullScan = scan.scanProfile === 'FULL_SCAN'
      const ts         = scan.completedAt ?? scan.createdAt

      fetch(`${API_BASE}/scan/${scanId}`)
        .then(async (res) => {
          if (!res.ok) throw new Error('scan not in backend memory')
          const apiScan = await res.json()

          const findings: ApiFinding[] = apiScan.findings ?? []

          // Write each finding to the findings collection
          findings.forEach((f, idx) => {
            writeFinding(uid, findingToDoc(f, idx, scanId, target, ts)).catch(() => {})
          })

          // Ensure scan doc has accurate final counts + findings array
          updateFirestoreScan(uid, scanId, {
            totalFindings:     apiScan.total_findings ?? findings.length,
            findings:          findings,
            totalCves:         apiScan.total_cves ?? 0,
            templatesExecuted: apiScan.templatesExecuted ?? 0,
          }).catch(() => {})

          // Full Scan: write CVEs and assets to their sub-collections
          if (isFullScan) {
            ;(apiScan.cves ?? []).forEach((cve: FirestoreCve) => {
              writeCve(uid, cve).catch(() => {})
            })
            ;(apiScan.assets ?? []).forEach((asset: FirestoreAsset) => {
              writeAsset(uid, asset).catch(() => {})
            })
          }
        })
        .catch(() => {
          // Backend scan no longer in memory (server restarted) — fall back to scan doc
          const findings = scan.findings ?? []
          if (findings.length > 0) {
            findings.forEach((f, idx) => {
              writeFinding(uid, findingToDoc(f, idx, scanId, target, ts)).catch(() => {})
            })
          }
        })
    }
  }, [scans, user])

  // ── Cleanup on unmount ──────────────────────────────────────────────
  useEffect(() => {
    return () => {
      for (const conn of connectionsRef.current.values()) conn.es.close()
      connectionsRef.current.clear()
      for (const t of bulkTimersRef.current.values()) clearTimeout(t)
      bulkTimersRef.current.clear()
    }
  }, [])

  return <ScanSyncContext.Provider value={null}>{children}</ScanSyncContext.Provider>
}
