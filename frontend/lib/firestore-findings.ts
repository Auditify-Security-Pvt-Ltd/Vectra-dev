import {
  collection,
  doc,
  setDoc,
  onSnapshot,
  query,
  where,
  orderBy,
} from 'firebase/firestore'
import { db } from './firebase'

export interface FirestoreFinding {
  findingId: string
  scanId: string
  target: string
  title: string
  severity: string
  template: string
  source?: string       // nuclei | vectra | wpscan
  description?: string
  matchedAt?: string
  host?: string
  createdAt: string
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
}

function findingsCol(uid: string) {
  return collection(db, 'users', uid, 'findings')
}

export async function writeFinding(uid: string, finding: FirestoreFinding): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'findings', finding.findingId), finding)
}

export function listenToFindings(
  uid: string,
  callback: (findings: FirestoreFinding[]) => void,
): () => void {
  const q = query(findingsCol(uid), orderBy('createdAt', 'desc'))
  const unsubscribe = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreFinding)),
    () => {
      // Firestore index not ready — fall back to unordered with client sort
      const fallback = onSnapshot(findingsCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreFinding)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsubscribe()
      return fallback
    },
  )
  return unsubscribe
}

export function listenToFindingsByScan(
  uid: string,
  scanId: string,
  callback: (findings: FirestoreFinding[]) => void,
): () => void {
  const q = query(findingsCol(uid), where('scanId', '==', scanId))
  return onSnapshot(q, (snap) => {
    const sorted = snap.docs
      .map((d) => d.data() as FirestoreFinding)
      .sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5),
      )
    callback(sorted)
  })
}
