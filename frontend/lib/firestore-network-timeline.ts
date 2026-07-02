import {
  collection,
  doc,
  setDoc,
  onSnapshot,
  query,
  orderBy,
  where,
  getDocs,
  limit,
} from 'firebase/firestore'
import { db } from './firebase'
import type { FirestoreNetworkHost } from './firestore-network-assets'

export interface TimelineChange {
  type: 'new_host' | 'removed_host' | 'new_port' | 'closed_port' | 'service_changed' | 'new_cve' | 'risk_increased' | 'risk_decreased' | 'ssl_issue'
  host: string
  details: string
  severity: 'info' | 'warning' | 'critical'
}

export interface FirestoreNetworkTimeline {
  eventId: string
  userId: string
  target: string
  scanId: string
  previousScanId: string | null
  timestamp: string
  changeCount: number
  newHosts: number
  removedHosts: number
  portChanges: number
  riskChanges: number
  changes: TimelineChange[]
}

function col(uid: string) {
  return collection(db, 'users', uid, 'network_timeline')
}

export async function writeTimelineEvent(uid: string, event: FirestoreNetworkTimeline): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'network_timeline', event.eventId), event)
}

export function listenToNetworkTimeline(
  uid: string,
  callback: (events: FirestoreNetworkTimeline[]) => void,
): () => void {
  const q = query(col(uid), orderBy('timestamp', 'desc'))
  return onSnapshot(q, (snap) =>
    callback(snap.docs.map((d) => d.data() as FirestoreNetworkTimeline)),
  )
}

export function listenToTimelineByTarget(
  uid: string,
  target: string,
  callback: (events: FirestoreNetworkTimeline[]) => void,
): () => void {
  const q = query(col(uid), where('target', '==', target), orderBy('timestamp', 'desc'))
  return onSnapshot(q, (snap) =>
    callback(snap.docs.map((d) => d.data() as FirestoreNetworkTimeline)),
  )
}

// ── Diff computation ─────────────────────────────────────────────────

export async function computeAndStoreTimeline(
  uid: string,
  scanId: string,
  target: string,
  currentHosts: FirestoreNetworkHost[],
): Promise<void> {
  try {
    // Find most recent previously completed scan for this target
    const scansCol = collection(db, 'users', uid, 'network_scans')
    const prevQ    = query(
      scansCol,
      where('target', '==', target),
      where('status', 'in', ['completed', 'completed_timeout']),
      orderBy('createdAt', 'desc'),
      limit(2),
    )
    const prevSnap = await getDocs(prevQ)
    // Filter out the current scan to get the truly previous one
    const prevScan = prevSnap.docs
      .map((d) => d.data())
      .find((s) => s.scanId !== scanId)

    const changes: TimelineChange[] = []
    let previousScanId: string | null = null

    if (prevScan) {
      previousScanId = prevScan.scanId

      // Get previous scan's hosts
      const prevHostsQ   = query(
        collection(db, 'users', uid, 'network_assets'),
        where('scanId', '==', prevScan.scanId),
      )
      const prevHostsSnap = await getDocs(prevHostsQ)
      const prevHosts     = prevHostsSnap.docs.map((d) => d.data() as FirestoreNetworkHost)

      const prevByIp    = new Map(prevHosts.map((h) => [h.ip, h]))
      const currentByIp = new Map(currentHosts.map((h) => [h.ip, h]))

      // New hosts
      for (const [ip, host] of currentByIp) {
        if (!prevByIp.has(ip)) {
          changes.push({
            type: 'new_host',
            host: ip,
            details: `New host discovered: ${ip}${host.hostname ? ` (${host.hostname})` : ''} — ${host.ports.length} open port(s)`,
            severity: 'warning',
          })
        }
      }

      // Removed hosts
      for (const [ip] of prevByIp) {
        if (!currentByIp.has(ip)) {
          changes.push({
            type: 'removed_host',
            host: ip,
            details: `Host no longer reachable: ${ip}`,
            severity: 'info',
          })
        }
      }

      // Port / service changes for hosts present in both scans
      for (const [ip, curr] of currentByIp) {
        const prev = prevByIp.get(ip)
        if (!prev) continue

        const prevPorts    = new Set(prev.ports.map((p) => p.port))
        const currentPorts = new Set(curr.ports.map((p) => p.port))

        for (const p of currentPorts) {
          if (!prevPorts.has(p)) {
            const portInfo = curr.ports.find((x) => x.port === p)
            changes.push({
              type: 'new_port',
              host: ip,
              details: `New open port: ${ip}:${p}/${portInfo?.service ?? 'unknown'}`,
              severity: 'warning',
            })
          }
        }
        for (const p of prevPorts) {
          if (!currentPorts.has(p)) {
            changes.push({
              type: 'closed_port',
              host: ip,
              details: `Port closed: ${ip}:${p}`,
              severity: 'info',
            })
          }
        }

        // Risk score change
        const prevRisk = prev.riskScore ?? 0
        const currRisk = curr.riskScore ?? 0
        if (currRisk > prevRisk + 10) {
          changes.push({
            type: 'risk_increased',
            host: ip,
            details: `Risk score increased: ${prevRisk} → ${currRisk}/100 (${curr.riskLevel?.toUpperCase() ?? 'UNKNOWN'})`,
            severity: currRisk >= 71 ? 'critical' : 'warning',
          })
        } else if (currRisk < prevRisk - 10) {
          changes.push({
            type: 'risk_decreased',
            host: ip,
            details: `Risk score decreased: ${prevRisk} → ${currRisk}/100`,
            severity: 'info',
          })
        }

        // SSL issues (new endpoint with problems)
        for (const ssl of curr.ssl ?? []) {
          if (ssl.isExpired || ssl.isSelfSigned || ssl.isWeakTls) {
            const issue = ssl.isExpired ? 'expired' : ssl.isSelfSigned ? 'self-signed' : 'weak TLS'
            changes.push({
              type: 'ssl_issue',
              host: ip,
              details: `SSL issue on ${ip}:${ssl.port} — ${issue} certificate (${ssl.subject})`,
              severity: ssl.isExpired ? 'critical' : 'warning',
            })
          }
        }
      }
    } else {
      // First scan — record as baseline
      for (const host of currentHosts) {
        changes.push({
          type: 'new_host',
          host: host.ip,
          details: `Host discovered: ${host.ip} — ${host.ports.length} open port(s), risk ${host.riskScore ?? 0}/100`,
          severity: (host.riskScore ?? 0) >= 71 ? 'critical' : 'info',
        })
      }
    }

    if (changes.length === 0) return

    const eventId = `tl_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
    const event: FirestoreNetworkTimeline = {
      eventId,
      userId:         uid,
      target,
      scanId,
      previousScanId,
      timestamp:      new Date().toISOString(),
      changeCount:    changes.length,
      newHosts:       changes.filter((c) => c.type === 'new_host').length,
      removedHosts:   changes.filter((c) => c.type === 'removed_host').length,
      portChanges:    changes.filter((c) => c.type === 'new_port' || c.type === 'closed_port').length,
      riskChanges:    changes.filter((c) => c.type === 'risk_increased' || c.type === 'risk_decreased').length,
      changes,
    }

    await writeTimelineEvent(uid, event)
  } catch {
    // Timeline is non-critical — don't propagate errors
  }
}
