import { authedFetch, idempotencyHeaders } from './api-auth'
// Same-origin proxy path by default (rewritten to the backend by next.config.mjs);
// set NEXT_PUBLIC_API_URL to an absolute URL to bypass the proxy.
const BASE = process.env.NEXT_PUBLIC_API_URL || '/api/backend'

// ── Types ─────────────────────────────────────────────────────────────

export interface OAuthUser {
  login:      string
  name:       string
  avatar_url: string
}

export interface OAuthStatus {
  configured: boolean
  connected:  boolean
  expired?:   boolean
  user?:      OAuthUser
}

export interface OAuthAuthorizeResult {
  configured: boolean
  url?:       string
  error?:     string
  message?:   string
}

export interface Repo {
  id:              number | string
  name:            string
  fullName:        string
  owner:           string
  description:     string
  visibility:      'public' | 'private'
  defaultBranch:   string
  language:        string
  updatedAt:       string
  stargazersCount: number
  url:             string
}

export interface RepoScanPayload {
  userId:      string
  provider:    'github' | 'gitlab'
  owner:       string
  repo:        string
  branch:      string
  projectName: string
}

// ── API helpers ───────────────────────────────────────────────────────

export async function getOAuthUrl(
  provider: 'github' | 'gitlab',
  userId: string,
): Promise<OAuthAuthorizeResult> {
  const res = await fetch(
    `${BASE}/sast/oauth/${provider}/authorize?userId=${encodeURIComponent(userId)}`,
  )
  return res.json()
}

export async function getOAuthStatus(
  provider: 'github' | 'gitlab',
  userId: string,
): Promise<OAuthStatus> {
  const res = await fetch(
    `${BASE}/sast/oauth/${provider}/status?userId=${encodeURIComponent(userId)}`,
  )
  if (!res.ok) return { configured: false, connected: false }
  return res.json()
}

export async function getRepos(
  provider: 'github' | 'gitlab',
  userId: string,
  search = '',
  page   = 1,
): Promise<{ repos: Repo[]; total: number }> {
  const params = new URLSearchParams({
    userId,
    search,
    page: String(page),
  })
  const res = await fetch(`${BASE}/sast/oauth/${provider}/repos?${params}`)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getBranches(
  provider: 'github' | 'gitlab',
  userId:   string,
  owner:    string,
  repo:     string,
): Promise<{ branches: string[]; default: string }> {
  const res = await fetch(
    `${BASE}/sast/oauth/${provider}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/branches?userId=${encodeURIComponent(userId)}`,
  )
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function disconnectOAuth(
  provider: 'github' | 'gitlab',
  userId: string,
): Promise<void> {
  await fetch(
    `${BASE}/sast/oauth/${provider}/disconnect?userId=${encodeURIComponent(userId)}`,
    { method: 'DELETE' },
  )
}

export async function startRepoScan(payload: RepoScanPayload): Promise<{ scanId: string }> {
  const res = await authedFetch(`${BASE}/sast/scan/repo`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', ...idempotencyHeaders() },
    body:    JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().then((d) => d.detail).catch(() => res.statusText)
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return res.json()
}
