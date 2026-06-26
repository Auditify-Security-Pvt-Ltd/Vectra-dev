// Strip any trailing slash so ${API_BASE}/path never produces a double-slash URL
export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || 'https://plots-stylus-papua-probe.trycloudflare.com').replace(/\/$/, '')

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
  userId: string = 'anonymous',
): Promise<ApiScanStartResponse> {
  const res = await fetch(`${API_BASE}/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, scanProfile, userId }),
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

export interface CancelScanResult {
  success: boolean
  reason?: string   // populated when success is false
  scanId?: string
  status?: string
}

export async function cancelScan(scanId: string): Promise<CancelScanResult> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(`Cancel request failed: ${res.status}`)
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
