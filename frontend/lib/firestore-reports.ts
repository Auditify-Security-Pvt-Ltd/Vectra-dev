import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
} from 'firebase/firestore'
import { db } from './firebase'

export interface FirestoreReport {
  reportId: string
  target: string
  scanId: string
  module: string
  format: string[]
  generatedAt: string
  generatedBy: string
  findingsCount: number
  cveCount: number
  assetsCount: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
}

function reportsCol(uid: string) {
  return collection(db, 'users', uid, 'reports')
}

export async function createFirestoreReport(uid: string, report: FirestoreReport): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'reports', report.reportId), report)
}

export async function deleteFirestoreReport(uid: string, reportId: string): Promise<void> {
  await deleteDoc(doc(db, 'users', uid, 'reports', reportId))
}

export function listenToReports(
  uid: string,
  callback: (reports: FirestoreReport[]) => void,
): () => void {
  const q = query(reportsCol(uid), orderBy('generatedAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreReport)),
    () => {
      const fallback = onSnapshot(reportsCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreReport)
          .sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}
