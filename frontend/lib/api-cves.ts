const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'https://plots-stylus-papua-probe.trycloudflare.com'

export interface ApiCorrelationStart {
  correlationId: string
  status: string
}

export async function startCorrelation(req: {
  assetId: string
  assetUrl: string
  technologies: string[]
  discoveryId: string
}): Promise<ApiCorrelationStart> {
  const resp = await fetch(`${API_BASE}/cves/correlate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!resp.ok) throw new Error(`Correlation failed: ${resp.statusText}`)
  return resp.json() as Promise<ApiCorrelationStart>
}

export function correlationStreamUrl(correlationId: string): string {
  return `${API_BASE}/cves/correlation/${correlationId}/stream`
}
