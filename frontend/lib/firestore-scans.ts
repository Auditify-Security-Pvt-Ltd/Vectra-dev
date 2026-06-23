import {
  collection,
  doc,
  setDoc,
  updateDoc,
  onSnapshot,
  query,
  orderBy,
  getDoc,
  deleteDoc,
} from 'firebase/firestore'
import { db } from './firebase'
import type { ApiFinding, ApiScanLog, ScanProfile } from './api'

export interface EngineState {
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped' | 'cancelled'
  findingCount: number
}

export interface FirestoreScan {
  scanId: string
  target: string
  scanType: 'DAST' | 'SAST'
  scanProfile?: ScanProfile
  status: string
  progress: number
  currentStep: string
  logs: ApiScanLog[]
  findings: ApiFinding[]
  totalFindings: number
  templatesExecuted?: number
  // Full Scan extras
  totalAssets?: number
  liveAssetsCount?: number
  totalCves?: number
  duration?: string
  createdAt: string
  completedAt?: string
  error?: string
  // Per-engine tracking
  engines?: {
    nuclei?: EngineState
    vectra_checks?: EngineState
    wpscan?: EngineState
    cve_analysis?: EngineState
  }
}

export const ACTIVE_STATUSES = new Set([
  // Quick Scan
  'queued',
  'initializing',
  'running',
  'processing',
  'saving',
  // Full Scan pipeline
  'discovering_assets',
  'validating_assets',
  'scanning_assets',
])

function scansCol(uid: string) {
  return collection(db, 'users', uid, 'scans')
}

function scanDoc(uid: string, scanId: string) {
  return doc(db, 'users', uid, 'scans', scanId)
}

export async function createFirestoreScan(uid: string, scan: FirestoreScan): Promise<void> {
  await setDoc(scanDoc(uid, scan.scanId), scan)
}

export async function updateFirestoreScan(
  uid: string,
  scanId: string,
  updates: Partial<FirestoreScan>,
): Promise<void> {
  try {
    await updateDoc(scanDoc(uid, scanId), updates as Record<string, unknown>)
  } catch {
    // doc may not exist yet (race condition on first write)
  }
}

export async function getFirestoreScan(uid: string, scanId: string): Promise<FirestoreScan | null> {
  const snap = await getDoc(scanDoc(uid, scanId))
  return snap.exists() ? (snap.data() as FirestoreScan) : null
}

export async function deleteFirestoreScan(uid: string, scanId: string): Promise<void> {
  await deleteDoc(scanDoc(uid, scanId))
}

export function listenToScan(
  uid: string,
  scanId: string,
  callback: (scan: FirestoreScan | null) => void,
): () => void {
  return onSnapshot(scanDoc(uid, scanId), (snap) => {
    callback(snap.exists() ? (snap.data() as FirestoreScan) : null)
  })
}

export function listenToScans(
  uid: string,
  callback: (scans: FirestoreScan[]) => void,
): () => void {
  const q = query(scansCol(uid), orderBy('createdAt', 'desc'))
  const unsubscribe = onSnapshot(
    q,
    (snap) => {
      callback(snap.docs.map((d) => d.data() as FirestoreScan))
    },
    () => {
      // index not ready or permission error — fall back to unordered
      const fallback = onSnapshot(scansCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreScan)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsubscribe()
      return fallback
    },
  )
  return unsubscribe
}
