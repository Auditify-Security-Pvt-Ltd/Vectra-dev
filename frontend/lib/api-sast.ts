import { authedFetch, idempotencyHeaders } from './api-auth'
import { API_BASE } from './api'

// ── Types ─────────────────────────────────────────────────────────────

export interface SastUploadResponse {
  scanId: string
  status: string
}

export interface SastStreamPayload {
  scanId:           string
  projectName:      string
  language:         string
  status:           string
  progress:         number
  currentStep:      string
  totalFiles:       number
  totalFindings:    number
  criticalFindings: number
  highFindings:     number
  mediumFindings:   number
  lowFindings:      number
  secretFindings:   number
  dependencyVulns:  number
  stages: {
    language_detection:  string
    secret_detection:    string
    dependency_analysis: string
    owasp_analysis:      string
    cwe_mapping:         string
    cve_correlation:     string
  }
  findings: any[]
  duration: string | null
  error: string | null
  done?: boolean
}

// ── Upload ────────────────────────────────────────────────────────────

export async function uploadSastZip(
  file: File,
  projectName: string,
  userId: string,
): Promise<SastUploadResponse> {
  const form = new FormData()
  form.append('projectName', projectName)
  form.append('userId', userId)
  form.append('uploadMethod', 'zip')
  form.append('file', file, file.name)

  const res = await authedFetch(`${API_BASE}/sast/upload`, { method: 'POST', body: form, headers: idempotencyHeaders() })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as any).detail || `Upload failed: ${res.status}`)
  }
  return res.json()
}

export async function uploadSastDirectory(
  files: FileList | File[],
  projectName: string,
  userId: string,
): Promise<SastUploadResponse> {
  const form = new FormData()
  form.append('projectName', projectName)
  form.append('userId', userId)
  form.append('uploadMethod', 'directory')

  for (const f of Array.from(files)) {
    const path = (f as any).webkitRelativePath || f.name
    form.append('files', f, path)
  }

  const res = await authedFetch(`${API_BASE}/sast/upload`, { method: 'POST', body: form, headers: idempotencyHeaders() })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as any).detail || `Upload failed: ${res.status}`)
  }
  return res.json()
}

// ── SSE stream ────────────────────────────────────────────────────────

export function openSastStream(
  scanId: string,
  onEvent: (payload: SastStreamPayload) => void,
  onDone: (payload: SastStreamPayload) => void,
  onError?: (err: Error) => void,
): () => void {
  const es = new EventSource(`${API_BASE}/sast/scan/${scanId}/stream`)

  es.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data) as SastStreamPayload
      if (payload.done) {
        es.close()
        onDone(payload)
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

// ── Control ───────────────────────────────────────────────────────────

export async function cancelSastScan(scanId: string): Promise<void> {
  await fetch(`${API_BASE}/sast/scan/${scanId}/cancel`, { method: 'POST' })
}

export async function deleteSastScanApi(scanId: string): Promise<void> {
  await fetch(`${API_BASE}/sast/scan/${scanId}`, { method: 'DELETE' })
}

export async function getSastScanStatus(scanId: string): Promise<SastStreamPayload | null> {
  const res = await fetch(`${API_BASE}/sast/scan/${scanId}`)
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`GET scan failed: ${res.status}`)
  return res.json()
}
