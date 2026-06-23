import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  where,
  updateDoc,
} from 'firebase/firestore'
import { db } from './firebase'

// ── Types ─────────────────────────────────────────────────────────────

export interface FirestoreCve {
  id: string            // `${cveId}_${assetId}`
  cveId: string         // e.g. "CVE-2021-41773"
  technology: string    // e.g. "Apache"
  version: string       // e.g. "2.4.49"
  severity: string      // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
  cvssScore: number
  description: string
  references: string[]
  exploitAvailable: boolean
  assetId: string
  assetUrl: string
  discoveryId: string
  published: string     // ISO date string from NVD
  createdAt: string
}

// ── Collection helpers ────────────────────────────────────────────────

function cvesCol(uid: string) {
  return collection(db, 'users', uid, 'cves')
}

function cveDoc(uid: string, id: string) {
  return doc(db, 'users', uid, 'cves', id)
}

// ── Write / Delete ────────────────────────────────────────────────────

export async function writeCve(uid: string, cve: FirestoreCve): Promise<void> {
  await setDoc(cveDoc(uid, cve.id), cve)
}

export async function deleteFirestoreCve(uid: string, id: string): Promise<void> {
  await deleteDoc(cveDoc(uid, id))
}

/** Mark asset as CVE-correlated so CveSyncContext won't re-process it. */
export async function markAssetCveCorrelated(uid: string, assetId: string): Promise<void> {
  try {
    await updateDoc(doc(db, 'users', uid, 'assets', assetId), {
      cveCorrelated: true,
    })
  } catch {
    // asset doc might not exist yet — ignore
  }
}

// ── Listeners ─────────────────────────────────────────────────────────

export function listenToCves(
  uid: string,
  callback: (cves: FirestoreCve[]) => void,
): () => void {
  const q = query(cvesCol(uid), orderBy('cvssScore', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreCve)),
    () => {
      // Index not ready — fallback to unordered, client-sort
      const fallback = onSnapshot(cvesCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreCve)
          .sort((a, b) => b.cvssScore - a.cvssScore)
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

/** All CVE docs that match a given CVE ID (one per affected asset). */
export function listenToCvesByVulnId(
  uid: string,
  cveId: string,
  callback: (cves: FirestoreCve[]) => void,
): () => void {
  const q = query(cvesCol(uid), where('cveId', '==', cveId))
  return onSnapshot(q, (snap) =>
    callback(snap.docs.map((d) => d.data() as FirestoreCve)),
  )
}

/** All CVEs for a specific asset. */
export function listenToCvesByAsset(
  uid: string,
  assetId: string,
  callback: (cves: FirestoreCve[]) => void,
): () => void {
  const q = query(cvesCol(uid), where('assetId', '==', assetId))
  return onSnapshot(q, (snap) =>
    callback(snap.docs.map((d) => d.data() as FirestoreCve)),
  )
}
