import { API_BASE } from './api'

export interface ApiDiscoveryStart {
  discoveryId: string
  status: string
  domain: string
}

export interface ApiDiscovery {
  discoveryId: string
  domain: string
  status: string
  currentStep: string
  subdomainsFound: number
  liveAssets: number
  logs: Array<{ timestamp: string; message: string }>
  assets: ApiAsset[]
  createdAt: string
  completedAt?: string
  error?: string
}

export interface ApiAsset {
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
}

export async function startDiscovery(target: string): Promise<ApiDiscoveryStart> {
  const res = await fetch(`${API_BASE}/assets/discover`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<ApiDiscoveryStart>
}

export async function getDiscovery(id: string): Promise<ApiDiscovery> {
  const res = await fetch(`${API_BASE}/assets/discovery/${id}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<ApiDiscovery>
}

export async function cancelDiscovery(id: string): Promise<void> {
  await fetch(`${API_BASE}/assets/discovery/${id}/cancel`, { method: 'POST' })
}

export async function deleteBackendAsset(assetId: string): Promise<void> {
  await fetch(`${API_BASE}/assets/${assetId}`, { method: 'DELETE' })
}

export function discoveryStreamUrl(id: string): string {
  return `${API_BASE}/assets/discovery/${id}/stream`
}
