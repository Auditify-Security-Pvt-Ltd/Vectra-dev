import {
  collection,
  doc,
  onSnapshot,
  query,
  orderBy,
  where,
  writeBatch,
  deleteDoc,
  getDocs,
} from 'firebase/firestore'
import { db } from './firebase'

// ── Types ─────────────────────────────────────────────────────────────

export type SastFindingCategory = 'secret' | 'owasp' | 'dependency'

export interface FirestoreSastFinding {
  findingId:       string
  scanId:          string
  projectName:     string
  category:        SastFindingCategory
  type:            string
  severity:        string
  title:           string
  description:     string
  file:            string
  line:            number
  code:            string
  cweId:           string
  cweName:         string
  cweDescription:  string
  owaspCategory:   string
  recommendation:  string
  // dependency-specific
  dependencyName?:    string
  dependencyVersion?: string
  cveId?:             string
  cvssScore?:         number
  createdAt:       string
}

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

// ── Helpers ───────────────────────────────────────────────────────────

function col(uid: string) {
  return collection(db, 'users', uid, 'sast_findings')
}

function findingDoc(uid: string, findingId: string) {
  return doc(db, 'users', uid, 'sast_findings', findingId)
}

// ── Write ─────────────────────────────────────────────────────────────

export async function writeSastFindings(
  uid: string,
  findings: FirestoreSastFinding[],
): Promise<void> {
  if (findings.length === 0) return
  const now = new Date().toISOString()
  const CHUNK = 400
  for (let i = 0; i < findings.length; i += CHUNK) {
    const batch = writeBatch(db)
    for (const f of findings.slice(i, i + CHUNK)) {
      batch.set(findingDoc(uid, f.findingId), { ...f, createdAt: f.createdAt || now })
    }
    await batch.commit()
  }
}

export async function deleteSastFindingsByScan(uid: string, scanId: string): Promise<void> {
  const q = query(col(uid), where('scanId', '==', scanId))
  const snap = await getDocs(q)
  const CHUNK = 400
  const docs = snap.docs
  for (let i = 0; i < docs.length; i += CHUNK) {
    const batch = writeBatch(db)
    docs.slice(i, i + CHUNK).forEach((d) => batch.delete(d.ref))
    await batch.commit()
  }
}

export async function deleteSastFinding(uid: string, findingId: string): Promise<void> {
  await deleteDoc(findingDoc(uid, findingId))
}

// ── Listeners ─────────────────────────────────────────────────────────

export function listenToSastFindings(
  uid: string,
  callback: (findings: FirestoreSastFinding[]) => void,
): () => void {
  const q = query(col(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreSastFinding)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreSastFinding)
          .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

export function listenToSastFindingsByScan(
  uid: string,
  scanId: string,
  callback: (findings: FirestoreSastFinding[]) => void,
): () => void {
  const q = query(col(uid), where('scanId', '==', scanId))
  return onSnapshot(q, (snap) => {
    const sorted = snap.docs
      .map((d) => d.data() as FirestoreSastFinding)
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
    callback(sorted)
  })
}
