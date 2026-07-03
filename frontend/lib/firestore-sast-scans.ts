import {
  collection,
  doc,
  setDoc,
  updateDoc,
  getDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
} from 'firebase/firestore'
import { db } from './firebase'

// ── Types ─────────────────────────────────────────────────────────────

export type SastStageStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface SastStages {
  language_detection:  SastStageStatus
  secret_detection:    SastStageStatus
  dependency_analysis: SastStageStatus
  owasp_analysis:      SastStageStatus
  cwe_mapping:         SastStageStatus
  cve_correlation:     SastStageStatus
}

export interface FirestoreSastScan {
  scanId:           string
  projectName:      string
  uploadMethod:     'zip' | 'directory' | 'github' | 'gitlab'
  language:         string
  userId:           string
  status:           'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress:         number
  currentStep:      string
  totalFiles:       number
  scannedFiles:     number
  totalFindings:    number
  criticalFindings: number
  highFindings:     number
  mediumFindings:   number
  lowFindings:      number
  secretFindings:   number
  dependencyVulns:  number
  stages:           SastStages
  duration:         string | null
  error:            string | null
  createdAt:        string
  completedAt:      string | null
  // Repository scan fields (GitHub / GitLab)
  repoProvider?:       'github' | 'gitlab'
  repoOwner?:          string
  repoName?:           string
  repoBranch?:         string
  repoCommitSha?:      string
  repoCommitAuthor?:   string
  repoCommitDate?:     string
  repoCommitMessage?:  string
}

export const SAST_ACTIVE_STATUSES = new Set(['queued', 'running'])

// ── Helpers ───────────────────────────────────────────────────────────

function col(uid: string) {
  return collection(db, 'users', uid, 'sast_scans')
}

function scanDoc(uid: string, scanId: string) {
  return doc(db, 'users', uid, 'sast_scans', scanId)
}

// ── CRUD ──────────────────────────────────────────────────────────────

export async function createSastScan(uid: string, scan: FirestoreSastScan): Promise<void> {
  await setDoc(scanDoc(uid, scan.scanId), scan)
}

export async function updateSastScan(
  uid: string,
  scanId: string,
  updates: Partial<FirestoreSastScan>,
): Promise<void> {
  try {
    await updateDoc(scanDoc(uid, scanId), updates as Record<string, unknown>)
  } catch {
    // doc may not exist on first write
  }
}

export async function getSastScan(uid: string, scanId: string): Promise<FirestoreSastScan | null> {
  const snap = await getDoc(scanDoc(uid, scanId))
  return snap.exists() ? (snap.data() as FirestoreSastScan) : null
}

export async function deleteSastScan(uid: string, scanId: string): Promise<void> {
  await deleteDoc(scanDoc(uid, scanId))
}

// ── Listeners ─────────────────────────────────────────────────────────

export function listenToSastScan(
  uid: string,
  scanId: string,
  callback: (scan: FirestoreSastScan | null) => void,
): () => void {
  return onSnapshot(scanDoc(uid, scanId), (snap) => {
    callback(snap.exists() ? (snap.data() as FirestoreSastScan) : null)
  })
}

export function listenToSastScans(
  uid: string,
  callback: (scans: FirestoreSastScan[]) => void,
): () => void {
  const q = query(col(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreSastScan)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreSastScan)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}
