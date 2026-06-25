import {
  collection,
  doc,
  setDoc,
  onSnapshot,
  query,
  orderBy,
  where,
} from 'firebase/firestore'
import { db } from './firebase'

export interface FirestoreNetworkFinding {
  findingId: string
  scanId: string
  hostId: string
  ip: string
  source: string
  severity: string
  title: string
  template: string
  host?: string | null
  matched_at?: string | null
  description?: string | null
  port?: number | null
  createdAt: string
}

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
}

function col(uid: string) {
  return collection(db, 'users', uid, 'network_findings')
}

export async function writeNetworkFinding(
  uid: string,
  finding: FirestoreNetworkFinding,
): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'network_findings', finding.findingId), finding)
}

export function listenToNetworkFindings(
  uid: string,
  callback: (findings: FirestoreNetworkFinding[]) => void,
): () => void {
  const q = query(col(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreNetworkFinding)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreNetworkFinding)
          .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

export function listenToNetworkFindingsByScan(
  uid: string,
  scanId: string,
  callback: (findings: FirestoreNetworkFinding[]) => void,
): () => void {
  const q = query(col(uid), where('scanId', '==', scanId))
  return onSnapshot(q, (snap) => {
    const sorted = snap.docs
      .map((d) => d.data() as FirestoreNetworkFinding)
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
    callback(sorted)
  })
}
