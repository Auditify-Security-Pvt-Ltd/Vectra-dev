import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  where,
} from 'firebase/firestore'
import { db } from './firebase'

export interface NetworkPort {
  port: number
  protocol: string
  service: string
  version: string
  state: string
}

export interface FirestoreNetworkHost {
  hostId: string
  scanId: string
  ip: string
  hostname?: string | null
  status: 'up' | 'down'
  ports: NetworkPort[]
  isWebService: boolean
  webPorts: number[]
  technologies: string[]
  createdAt: string
}

function col(uid: string) {
  return collection(db, 'users', uid, 'network_assets')
}

export async function writeNetworkHost(uid: string, host: FirestoreNetworkHost): Promise<void> {
  await setDoc(doc(db, 'users', uid, 'network_assets', host.hostId), host)
}

export async function deleteNetworkHost(uid: string, hostId: string): Promise<void> {
  await deleteDoc(doc(db, 'users', uid, 'network_assets', hostId))
}

export function listenToNetworkHosts(
  uid: string,
  callback: (hosts: FirestoreNetworkHost[]) => void,
): () => void {
  const q = query(col(uid), orderBy('createdAt', 'desc'))
  const unsub = onSnapshot(
    q,
    (snap) => callback(snap.docs.map((d) => d.data() as FirestoreNetworkHost)),
    () => {
      const fallback = onSnapshot(col(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreNetworkHost)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsub()
      return fallback
    },
  )
  return unsub
}

export function listenToNetworkHostsByScan(
  uid: string,
  scanId: string,
  callback: (hosts: FirestoreNetworkHost[]) => void,
): () => void {
  const q = query(col(uid), where('scanId', '==', scanId))
  return onSnapshot(q, (snap) => {
    callback(snap.docs.map((d) => d.data() as FirestoreNetworkHost))
  })
}
