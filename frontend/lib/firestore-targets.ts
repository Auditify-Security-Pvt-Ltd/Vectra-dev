import {
  collection,
  doc,
  setDoc,
  updateDoc,
  onSnapshot,
  query,
  orderBy,
  deleteDoc,
} from 'firebase/firestore'
import { db } from './firebase'

export interface FirestoreTarget {
  id: string
  name: string
  url: string
  description: string
  tags: string[]
  createdAt: string
}

function targetsCol(uid: string) {
  return collection(db, 'users', uid, 'targets')
}

function targetDoc(uid: string, id: string) {
  return doc(db, 'users', uid, 'targets', id)
}

export async function createTarget(
  uid: string,
  data: Omit<FirestoreTarget, 'id' | 'createdAt'>,
): Promise<string> {
  const id = `target_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`
  await setDoc(targetDoc(uid, id), {
    ...data,
    id,
    createdAt: new Date().toISOString(),
  })
  return id
}

export async function updateTarget(
  uid: string,
  id: string,
  updates: Partial<Omit<FirestoreTarget, 'id' | 'createdAt'>>,
): Promise<void> {
  await updateDoc(targetDoc(uid, id), updates as Record<string, unknown>)
}

export async function deleteTarget(uid: string, id: string): Promise<void> {
  await deleteDoc(targetDoc(uid, id))
}

export function listenToTargets(
  uid: string,
  callback: (targets: FirestoreTarget[]) => void,
): () => void {
  const q = query(targetsCol(uid), orderBy('createdAt', 'desc'))
  const unsubscribe = onSnapshot(
    q,
    (snap) => {
      callback(snap.docs.map((d) => d.data() as FirestoreTarget))
    },
    () => {
      const fallback = onSnapshot(targetsCol(uid), (snap) => {
        const sorted = snap.docs
          .map((d) => d.data() as FirestoreTarget)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        callback(sorted)
      })
      unsubscribe()
      return fallback
    },
  )
  return unsubscribe
}
