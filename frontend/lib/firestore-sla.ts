import { doc, getDoc, onSnapshot, setDoc } from 'firebase/firestore'
import { db } from './firebase'

// ── Types ──────────────────────────────────────────────────────────────

export interface SlaPolicy {
  critical: number | null   // days; null = no SLA enforced
  high:     number | null
  medium:   number | null
  low:      number | null
  info:     number | null
  warnDays: number          // show "Due Soon" badge N days before deadline
}

export const DEFAULT_SLA: SlaPolicy = {
  critical: 10,
  high:     20,
  medium:   45,
  low:      90,
  info:     null,
  warnDays: 3,
}

export type SlaStatus = 'within_sla' | 'due_soon' | 'breached' | 'no_sla' | 'fixed'

export interface SlaResult {
  status:        SlaStatus
  daysRemaining: number | null   // negative = overdue
  dueDate:       Date | null
}

// ── Core computation ───────────────────────────────────────────────────

export function computeSlaStatus(
  severity:  string,
  createdAt: string,
  policy:    SlaPolicy,
  isFixed:   boolean,
): SlaResult {
  if (isFixed) return { status: 'fixed', daysRemaining: null, dueDate: null }

  const sev   = severity.toLowerCase() as keyof Pick<SlaPolicy, 'critical' | 'high' | 'medium' | 'low' | 'info'>
  const days  = policy[sev]
  if (days == null) return { status: 'no_sla', daysRemaining: null, dueDate: null }

  const discovery = new Date(createdAt)
  const dueDate   = new Date(discovery.getTime() + days * 86_400_000)
  const now       = new Date()
  const msLeft    = dueDate.getTime() - now.getTime()
  const daysLeft  = msLeft / 86_400_000   // fractional

  let status: SlaStatus
  if (daysLeft < 0)                 status = 'breached'
  else if (daysLeft <= policy.warnDays) status = 'due_soon'
  else                              status = 'within_sla'

  return { status, daysRemaining: Math.ceil(daysLeft), dueDate }
}

// ── Firestore R/W ──────────────────────────────────────────────────────

const SLA_DOC = (uid: string) => doc(db, 'users', uid, 'settings', 'sla_policy')

export async function saveSlaPolicy(uid: string, policy: SlaPolicy): Promise<void> {
  await setDoc(SLA_DOC(uid), policy)
}

export async function loadSlaPolicy(uid: string): Promise<SlaPolicy> {
  const snap = await getDoc(SLA_DOC(uid))
  if (!snap.exists()) return DEFAULT_SLA
  return { ...DEFAULT_SLA, ...snap.data() as Partial<SlaPolicy> }
}

export function listenToSlaPolicy(
  uid:      string,
  callback: (policy: SlaPolicy) => void,
): () => void {
  return onSnapshot(SLA_DOC(uid), (snap) => {
    callback(snap.exists() ? { ...DEFAULT_SLA, ...(snap.data() as Partial<SlaPolicy>) } : DEFAULT_SLA)
  })
}
