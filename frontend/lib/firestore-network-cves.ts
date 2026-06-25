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

export interface FirestoreNetworkCve {
  id: string
  scanId: string
  hostId: string
  ip: string
  port: number
  cveId: string
  technology: string
  version: string
  cvssScore: number
  severity: string
  description: string
  exploitAvailable: boolean
  published?: string
  createdAt: string
}

function col(uid: string) {
  return collection(db, 'users', uid, 'network_cves')
}

export async function writeNetworkCve(uid: string, cve: FirestoreNetworkCve): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'network_cves', cve.id), cve)
}

export function listenToNetworkCves(
  uid: string,
  callback: (cves: FirestoreNetworkCve[]) => void,
): () => void {
  const q = query(col(uid), orderBy('cvssScore', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreNetworkCve)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreNetworkCve)
          .sort((a, b) => b.cvssScore - a.cvssScore)
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

export function listenToNetworkCvesByScan(
  uid: string,
  scanId: string,
  callback: (cves: FirestoreNetworkCve[]) => void,
): () => void {
  const q = query(col(uid), where('scanId', '==', scanId))
  return onSnapshot(q, (snap) => {
    const sorted = snap.docs
      .map((d) => d.data() as FirestoreNetworkCve)
      .sort((a, b) => b.cvssScore - a.cvssScore)
    callback(sorted)
  })
}
