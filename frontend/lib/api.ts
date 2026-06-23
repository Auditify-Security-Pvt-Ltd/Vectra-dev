export const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export interface ApiFinding {
  source?: string       // nuclei | vectra | wpscan
  severity: string
  title: string
  template: string
  host?: string | null
  matched_at?: string | null
  description?: string | null
}

export interface ApiScanLog {
  timestamp: string
  message: string
}

export type ScanProfile = 'QUICK_SCAN' | 'FULL_SCAN'

export interface ApiScanStartResponse {
  scanId: string
  status: string
  scanProfile?: ScanProfile
}

export interface ApiScanStatus {
  scanId: string
  target: string
  scanProfile?: ScanProfile
  status: string
  progress: number
  currentStep: string
  logs: ApiScanLog[]
  findings: ApiFinding[]
  total_findings: number
  templatesExecuted?: number
  duration?: string | null
  error?: string | null
}

export async function startScan(
  target: string,
  scanProfile: ScanProfile = 'FULL_SCAN',
): Promise<ApiScanStartResponse> {
  const res = await fetch(`${API_BASE}/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, scanProfile }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as any).detail || `Scan failed with status ${res.status}`)
  }
  return res.json()
}

export async function getScanStatus(scanId: string): Promise<ApiScanStatus> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`)
  if (!res.ok) throw new Error(`GET /scan/${scanId} failed with ${res.status}`)
  return res.json()
}

export async function cancelScan(scanId: string): Promise<{ scanId: string; status: string }> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(`Cancel failed with ${res.status}`)
  return res.json()
}

export async function restartScan(
  scanId: string,
): Promise<ApiScanStartResponse & { originalScanId?: string }> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/restart`, { method: 'POST' })
  if (!res.ok) throw new Error(`Restart failed with ${res.status}`)
  return res.json()
}

export async function checkHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/health`)
  if (!res.ok) throw new Error('Backend unreachable')
  return res.json()
}
