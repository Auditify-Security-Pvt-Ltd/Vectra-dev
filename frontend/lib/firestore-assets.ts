import {
  collection,
  doc,
  setDoc,
  getDoc,
  updateDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  where,
} from 'firebase/firestore'
import { db } from './firebase'

// ── Types ─────────────────────────────────────────────────────────────

export interface FirestoreDiscovery {
  discoveryId: string
  domain: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  currentStep: string
  subdomainsFound: number
  liveAssets: number
  logs: Array<{ timestamp: string; message: string }>
  createdAt: string
  completedAt?: string
  error?: string
}

export interface FirestoreAsset {
  assetId: string
  discoveryId: string
  domain: string
  subdomain: string
  alive: boolean
  statusCode?: number
  title?: string
  server?: string
  ip?: string
  contentType?: string
  technologies?: string[]
  url?: string
  createdAt: string
  cveCorrelated?: boolean  // set to true after CVE correlation completes
}

export const ACTIVE_DISCOVERY_STATUSES = new Set(['queued', 'running'])

// ── Helpers ───────────────────────────────────────────────────────────

function discCol(uid: string) {
  return collection(db, 'users', uid, 'discoveries')
}

function assetsCol(uid: string) {
  return collection(db, 'users', uid, 'assets')
}

// ── Discoveries ───────────────────────────────────────────────────────

export async function createFirestoreDiscovery(
  uid: string,
  disc: FirestoreDiscovery,
): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'discoveries', disc.discoveryId), disc)
}

export async function updateFirestoreDiscovery(
  uid: string,
  discoveryId: string,
  updates: Partial<FirestoreDiscovery>,
): Promise<void> {
  await updateDoc(
    doc(db, 'users', uid, 'discoveries', discoveryId),
    updates as Record<string, unknown>,
  )
}

export async function getFirestoreDiscovery(
  uid: string,
  discoveryId: string,
): Promise<FirestoreDiscovery | null> {
  const snap = await getDoc(doc(db, 'users', uid, 'discoveries', discoveryId))
  return snap.exists() ? (snap.data() as FirestoreDiscovery) : null
}

export function listenToDiscoveries(
  uid: string,
  callback: (discoveries: FirestoreDiscovery[]) => void,
): () => void {
  const q = query(discCol(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreDiscovery)),
    () => {
      // Firestore index not ready — fallback to unordered with client sort
      const fallback = onSnapshot(discCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreDiscovery)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

// ── Assets ────────────────────────────────────────────────────────────

export async function writeAsset(uid: string, asset: FirestoreAsset): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'assets', asset.assetId), asset)
}

export async function deleteFirestoreAsset(uid: string, assetId: string): Promise<void> {
  await deleteDoc(doc(db, 'users', uid, 'assets', assetId))
}

export function listenToAssets(
  uid: string,
  callback: (assets: FirestoreAsset[]) => void,
): () => void {
  const q = query(assetsCol(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreAsset)),
    () => {
      const fallback = onSnapshot(assetsCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreAsset)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

export function listenToAssetsByDiscovery(
  uid: string,
  discoveryId: string,
  callback: (assets: FirestoreAsset[]) => void,
): () => void {
  const q = query(assetsCol(uid), where('discoveryId', '==', discoveryId))
  return onSnapshot(q, (snap) => {
    const sorted = snap.docs
      .map((d) => d.data() as FirestoreAsset)
      .sort((a, b) => {
        // Alive first, then by status code
        if (a.alive !== b.alive) return a.alive ? -1 : 1
        return (a.statusCode ?? 999) - (b.statusCode ?? 999)
      })
    callback(sorted)
  })
}
