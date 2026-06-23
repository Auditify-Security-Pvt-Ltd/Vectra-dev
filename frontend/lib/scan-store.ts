import type { ApiFinding } from './api'

export type ScanStatus =
  | 'queued'
  | 'initializing'
  | 'running'
  | 'processing'
  | 'saving'
  | 'completed'
  | 'failed'
  | 'cancelled'

export interface ScanRecord {
  scanId: string
  target: string
  scanType: 'DAST' | 'SAST'
  status: ScanStatus
  progress: number
  findings: ApiFinding[]
  totalFindings: number
  createdAt: string
  completedAt?: string
  error?: string
  logs: string[]
}

const STORAGE_KEY = 'vectra_scans'

function read(): ScanRecord[] {
  if (typeof window === 'undefined') return []
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') as ScanRecord[]
  } catch {
    return []
  }
}

function write(scans: ScanRecord[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(scans))
}

export function getScanHistory(): ScanRecord[] {
  return read().sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  )
}

export function getScan(scanId: string): ScanRecord | null {
  return read().find((s) => s.scanId === scanId) ?? null
}

export function addScan(scan: ScanRecord): void {
  write([scan, ...read()])
}

export function updateScan(scanId: string, updates: Partial<ScanRecord>): void {
  const scans = read()
  const idx = scans.findIndex((s) => s.scanId === scanId)
  if (idx !== -1) {
    scans[idx] = { ...scans[idx], ...updates }
    write(scans)
  }
}

export function getAllFindings(): (ApiFinding & {
  scanId: string
  target: string
  createdAt: string
})[] {
  return read().flatMap((scan) =>
    scan.findings.map((f) => ({
      ...f,
      scanId: scan.scanId,
      target: scan.target,
      createdAt: scan.createdAt,
    })),
  )
}

export function getScanStats() {
  const scans = read()
  const active: ScanStatus[] = ['queued', 'initializing', 'running', 'processing', 'saving']
  return {
    totalScans: scans.length,
    activeScans: scans.filter((s) => active.includes(s.status)).length,
    completedScans: scans.filter((s) => s.status === 'completed').length,
    failedScans: scans.filter((s) => s.status === 'failed').length,
    totalFindings: scans.reduce((sum, s) => sum + s.totalFindings, 0),
    criticalFindings: scans
      .flatMap((s) => s.findings)
      .filter((f) => f.severity === 'critical').length,
  }
}
