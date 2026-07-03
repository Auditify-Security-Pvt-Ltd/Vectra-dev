import { collection, doc, onSnapshot, setDoc } from 'firebase/firestore'
import { db } from './firebase'
import type { CveStatus } from './firestore-cve-tracking'

// FindingStatus shares the same 6 values as CveStatus
export type FindingStatus = CveStatus

export interface FindingAssignee {
  id:   string
  name: string
}

export interface FindingComment {
  id:        string
  userId:    string
  userName:  string
  text:      string
  createdAt: string
}

export interface FindingTimelineEvent {
  id:        string
  action:    'created' | 'status_changed' | 'comment_added' | 'marked_fixed' | 'reopened' | 'assigned' | 'unassigned'
  userId?:   string
  userName?: string
  createdAt: string
  details?:  string
}

export interface FindingTracking {
  findingDocId:   string
  status:         FindingStatus
  assigneeId:     string | null
  assigneeName:   string | null
  assigneeEmail?: string | null
  assigneeRole?:  string | null
  assignedBy?:    string | null
  assignedByName?: string | null
  assignedAt?:    string | null
  comments:       FindingComment[]
  timeline:       FindingTimelineEvent[]
  updatedAt:      string
}

export function genFindingId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7)
}

export function defaultFindingTracking(findingDocId: string): FindingTracking {
  return {
    findingDocId,
    status:       'open',
    assigneeId:   null,
    assigneeName: null,
    comments:     [],
    timeline: [{
      id:        genFindingId(),
      action:    'created',
      createdAt: new Date().toISOString(),
    }],
    updatedAt: new Date().toISOString(),
  }
}

export async function upsertFindingTracking(uid: string, data: FindingTracking): Promise<void> {
  await setDoc(
    doc(db, 'users', uid, 'finding_tracking', data.findingDocId),
    data,
    { merge: true },
  )
}

export function listenToFindingTracking(
  uid: string,
  callback: (tracking: Record<string, FindingTracking>) => void,
): () => void {
  return onSnapshot(collection(db, 'users', uid, 'finding_tracking'), (snap) => {
    const result: Record<string, FindingTracking> = {}
    snap.docs.forEach((d) => { result[d.id] = d.data() as FindingTracking })
    callback(result)
  })
}
