import { API_BASE } from './api'

export type ScheduleInterval = 'once' | 'daily' | 'weekly' | 'monthly'

export interface NetworkSchedule {
  scheduleId: string
  userId: string
  target: string
  profile: 'QUICK_SCAN' | 'FULL_SCAN'
  interval: ScheduleInterval
  enabled: boolean
  label: string
  createdAt: string
  lastRun: string | null
  lastScanId: string | null
  nextRun: string | null
}

export interface ScheduleCreateBody {
  userId: string
  target: string
  profile?: 'QUICK_SCAN' | 'FULL_SCAN'
  interval: ScheduleInterval
  enabled?: boolean
  label?: string
}

export interface ScheduleUpdateBody {
  target?: string
  profile?: 'QUICK_SCAN' | 'FULL_SCAN'
  interval?: ScheduleInterval
  enabled?: boolean
  label?: string
}

const SCHED_BASE = `${API_BASE}/network/schedules`

export async function listSchedules(userId: string): Promise<NetworkSchedule[]> {
  const res = await fetch(`${SCHED_BASE}?userId=${encodeURIComponent(userId)}`)
  if (!res.ok) throw new Error(`Failed to list schedules: ${res.status}`)
  return res.json()
}

export async function createSchedule(body: ScheduleCreateBody): Promise<NetworkSchedule> {
  const res = await fetch(SCHED_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as any).detail || `Create schedule failed: ${res.status}`)
  }
  return res.json()
}

export async function updateSchedule(
  scheduleId: string,
  body: ScheduleUpdateBody,
): Promise<NetworkSchedule> {
  const res = await fetch(`${SCHED_BASE}/${scheduleId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`Update schedule failed: ${res.status}`)
  return res.json()
}

export async function deleteSchedule(scheduleId: string): Promise<void> {
  const res = await fetch(`${SCHED_BASE}/${scheduleId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`Delete schedule failed: ${res.status}`)
}

export async function triggerSchedule(scheduleId: string): Promise<{ success: boolean; scanId: string }> {
  const res = await fetch(`${SCHED_BASE}/${scheduleId}/trigger`, { method: 'POST' })
  if (!res.ok) throw new Error(`Trigger schedule failed: ${res.status}`)
  return res.json()
}
