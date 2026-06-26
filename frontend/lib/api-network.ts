import { API_BASE } from './api'

export type NetworkScanProfile = 'QUICK_SCAN' | 'FULL_SCAN'

export interface NetworkScanStartResponse {
  scanId: string
  status: string
  scanProfile: NetworkScanProfile
}

export interface NetworkEngineStates {
  host_discovery?: { status: string; count: number }
  port_scan?: { status: string; count: number }
  cve_analysis?: { status: string; count: number }
  nuclei?: { status: string; count: number }
}

export interface NetworkScanStreamPayload {
  status: string
  progress: number
  currentStep: string
  logs: Array<{ timestamp: string; message: string }>
  hosts: any[]
  total_hosts: number
  live_hosts: number
  findings: any[]
  total_findings: number
  cves: any[]
  total_cves: number
  duration?: string | null
  error?: string | null
  engines: NetworkEngineStates
  done?: boolean
}

export async function startNetworkScan(
  target: string,
  scanProfile: NetworkScanProfile = 'QUICK_SCAN',
  userId: string = 'anonymous',
): Promise<NetworkScanStartResponse> {
  const res = await fetch(`${API_BASE}/network/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, scanProfile, userId }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as any).detail || `Start scan failed: ${res.status}`)
  }
  return res.json()
}

export interface CancelNetworkScanResult {
  success: boolean
  reason?: string
  scanId?: string
  status?: string
}

export async function cancelNetworkScan(scanId: string): Promise<CancelNetworkScanResult> {
  const res = await fetch(`${API_BASE}/network/scan/${scanId}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(`Cancel request failed: ${res.status}`)
  return res.json()
}

export async function getNetworkScanStatus(scanId: string): Promise<NetworkScanStreamPayload> {
  const res = await fetch(`${API_BASE}/network/scan/${scanId}`)
  if (!res.ok) throw new Error(`GET scan failed: ${res.status}`)
  return res.json()
}

export function openNetworkScanStream(
  scanId: string,
  onEvent: (payload: NetworkScanStreamPayload) => void,
  onDone: () => void,
  onError?: (err: Error) => void,
): () => void {
  const url = `${API_BASE}/network/scan/${scanId}/stream`
  const es  = new EventSource(url)

  es.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data) as NetworkScanStreamPayload
      if (payload.done) {
        es.close()
        onDone()
      } else {
        onEvent(payload)
      }
    } catch {
      // ignore parse errors
    }
  }

  es.onerror = () => {
    es.close()
    onError?.(new Error('SSE connection lost'))
  }

  return () => es.close()
}
