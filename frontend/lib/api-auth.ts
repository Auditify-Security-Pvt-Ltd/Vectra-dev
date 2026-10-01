import { auth } from './firebase'

/**
 * Authenticated API access.
 *
 * The backend derives the caller's identity from a verified Firebase ID token
 * rather than a `userId` in the query string, so anything security-relevant
 * (scan quota, admin authorization) must go through here. Sending the token is
 * what makes those checks meaningful — without it the backend cannot tell one
 * caller from another.
 */

/** Current user's ID token, or null when signed out. */
export async function getIdToken(forceRefresh = false): Promise<string | null> {
  const user = auth.currentUser
  if (!user) return null
  try {
    return await user.getIdToken(forceRefresh)
  } catch {
    return null
  }
}

/** Authorization header for the signed-in user, or `{}` when signed out. */
export async function authHeaders(): Promise<Record<string, string>> {
  const token = await getIdToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/** Thrown when the backend refuses a scan because the ORGANIZATION allowance is spent. */
export class ScanLimitReachedError extends Error {
  readonly code = 'SCAN_LIMIT_REACHED'
  readonly quota?: QuotaSnapshot

  constructor(message: string, quota?: QuotaSnapshot) {
    super(message)
    this.name = 'ScanLimitReachedError'
    this.quota = quota
  }
}

/** Refusal with a machine-readable code, e.g. ORGANIZATION_DISABLED or NO_ORGANIZATION. */
export class ScanNotAllowedError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
    this.name = 'ScanNotAllowedError'
  }
}

/** Shared scan quota of the caller's organization (not per user). */
export interface QuotaSnapshot {
  plan:               string
  planAllowance:      number   // -1 = unlimited
  bonusScans:         number   // organization-level extra scans
  effectiveAllowance: number   // -1 = unlimited
  used:               number
  remaining:          number   // -1 = unlimited
  unlimited:          boolean
}

/**
 * Idempotency key for one scan-start action. Reuse the same key when retrying
 * that action so the backend charges the organization only once.
 */
export function newRequestId(): string {
  // randomUUID is unavailable outside secure contexts (plain-http LAN hosts).
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '')
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function idempotencyHeaders(key: string = newRequestId()): Record<string, string> {
  return { 'Idempotency-Key': key }
}

/**
 * `fetch` with the caller's ID token attached, translating the backend's
 * quota refusal into a typed error the UI can present cleanly.
 */
export async function authedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers ?? {})
  const token = await getIdToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)

  const res = await fetch(input, { ...init, headers })

  if ([401, 402, 403, 409, 503].includes(res.status)) {
    // Only structured quota/admission refusals are consumed here; anything else
    // is returned untouched for the caller to read.
    const body = await res.clone().json().catch(() => null)
    const detail = body?.detail
    if (detail && typeof detail === 'object' && typeof detail.code === 'string') {
      if (detail.code === 'SCAN_LIMIT_REACHED') {
        throw new ScanLimitReachedError(
          detail.message ?? 'Your organization has reached its available scan limit.',
          detail.quota,
        )
      }
      if (typeof detail.message === 'string') {
        throw new ScanNotAllowedError(detail.code, detail.message)
      }
    }
  }

  return res
}

/** Human-readable allowance, treating -1 as unlimited. */
export function formatAllowance(value: number): string {
  return value < 0 ? 'Unlimited' : String(value)
}

export interface OrganizationQuota {
  uid:              string
  organizationId:   string | null
  organizationName: string | null
  status:           'active' | 'disabled' | null
  quota:            QuotaSnapshot
  rule:             string
}

/** The caller's organization plan and shared scan usage (read-only). */
export async function getOrganizationQuota(apiBase: string): Promise<OrganizationQuota> {
  const res = await authedFetch(`${apiBase}/quota`)
  if (!res.ok) throw new Error(`Could not load scan usage (${res.status})`)
  return res.json()
}

/** "2 / 3 scans used" style label; handles unlimited plans. */
export function usageLabel(q: QuotaSnapshot): string {
  return q.unlimited ? `${q.used} scans used · unlimited` : `${q.used} / ${q.effectiveAllowance} scans used`
}
