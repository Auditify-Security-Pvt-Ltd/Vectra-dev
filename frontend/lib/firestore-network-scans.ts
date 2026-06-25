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

export interface NetworkEngineState {
  status: 'pending' | 'running' | 'completed' | 'completed_partial' | 'failed' | 'skipped' | 'cancelled'
  count: number
}

export interface NetworkScanLog {
  timestamp: string
  message: string
}

export interface FirestoreNetworkScan {
  scanId: string
  target: string
  scanProfile: 'QUICK_SCAN' | 'FULL_SCAN'
  status: string
  progress: number
  currentStep: string
  logs: NetworkScanLog[]
  totalHosts: number
  liveHosts: number
  totalFindings: number
  totalCves: number
  duration?: string
  error?: string
  createdAt: string
  completedAt?: string
  engines?: {
    host_discovery?: NetworkEngineState
    port_scan?: NetworkEngineState
    cve_analysis?: NetworkEngineState
    nuclei?: NetworkEngineState
    network_checks?: NetworkEngineState
  }
}

export const NETWORK_ACTIVE_STATUSES = new Set([
  'queued', 'host_discovery', 'port_scan', 'parallel_analysis',
])

// ── Helpers ───────────────────────────────────────────────────────────

function col(uid: string) {
  return collection(db, 'users', uid, 'network_scans')
}

function scanDoc(uid: string, scanId: string) {
  return doc(db, 'users', uid, 'network_scans', scanId)
}

// ── CRUD ──────────────────────────────────────────────────────────────

export async function createNetworkScan(uid: string, scan: FirestoreNetworkScan): Promise<void> {
  await setDoc(scanDoc(uid, scan.scanId), scan)
}

export async function updateNetworkScan(
  uid: string,
  scanId: string,
  updates: Partial<FirestoreNetworkScan>,
): Promise<void> {
  try {
    await updateDoc(scanDoc(uid, scanId), updates as Record<string, unknown>)
  } catch {
    // doc may not exist yet on first write
  }
}

export async function getNetworkScan(uid: string, scanId: string): Promise<FirestoreNetworkScan | null> {
  const snap = await getDoc(scanDoc(uid, scanId))
  return snap.exists() ? (snap.data() as FirestoreNetworkScan) : null
}

export async function deleteNetworkScan(uid: string, scanId: string): Promise<void> {
  await deleteDoc(scanDoc(uid, scanId))
}

export function listenToNetworkScan(
  uid: string,
  scanId: string,
  callback: (scan: FirestoreNetworkScan | null) => void,
): () => void {
  return onSnapshot(scanDoc(uid, scanId), (snap) => {
    callback(snap.exists() ? (snap.data() as FirestoreNetworkScan) : null)
  })
}

export function listenToNetworkScans(
  uid: string,
  callback: (scans: FirestoreNetworkScan[]) => void,
): () => void {
  const q = query(col(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreNetworkScan)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreNetworkScan)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}
