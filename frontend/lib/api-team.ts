/**
 * Backend team API client.
 * Email invitations go through the backend (SMTP + secure token generation).
 * Link invitations are managed purely in Firestore by the frontend.
 */

import type { OrgRole } from './rbac'

const BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? `Team API error ${res.status}`)
  }
  return res.json() as Promise<T>
}

async function del<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method:  'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? `Team API error ${res.status}`)
  }
  return res.json() as Promise<T>
}

async function get<T>(path: string, params: Record<string, string> = {}): Promise<T> {
  const qs  = new URLSearchParams(params).toString()
  const res = await fetch(`${BASE}${path}${qs ? `?${qs}` : ''}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? `Team API error ${res.status}`)
  }
  return res.json() as Promise<T>
}

// ── Types ─────────────────────────────────────────────────────────────

export interface EmailInviteResult {
  inviteId:   string
  token:      string
  emailSent:  boolean
  emailError: string | null
}

export interface InviteVerifyResult {
  inviteId:    string
  orgId:       string
  orgName:     string
  inviterName: string
  email:       string
  role:        OrgRole
  type:        'email'
}

export interface AcceptResult {
  inviteId: string
  orgId:    string
  orgName:  string
  role:     OrgRole
}

// ── API calls ─────────────────────────────────────────────────────────

export function registerOrg(orgId: string, adminUid: string, orgName: string): Promise<{ ok: boolean }> {
  return post('/team/org/register', { orgId, adminUid, orgName })
}

/** Send an email invitation — backend generates secure token and sends email. */
export function sendEmailInvite(payload: {
  orgId:       string
  orgName:     string
  inviterUid:  string
  inviterName: string
  email:       string
  role:        OrgRole
  inviteId:    string
}): Promise<EmailInviteResult> {
  return post('/team/invite/email', payload)
}

/** Resend email invite — revokes old token, generates new one, resends. */
export function resendEmailInvite(payload: {
  orgId:       string
  orgName:     string
  inviterUid:  string
  inviterName: string
  inviteId:    string
  email:       string
  role:        OrgRole
}): Promise<EmailInviteResult> {
  return post('/team/invite/email/resend', payload)
}

/** Verify an email invite token — used by landing page for email invites. */
export function verifyEmailToken(token: string): Promise<InviteVerifyResult> {
  return get('/team/invite/verify', { token })
}

/** Consume an email invite token after user accepts. */
export function acceptEmailInvite(payload: {
  token:     string
  userId:    string
  userName:  string
  userEmail: string
}): Promise<AcceptResult> {
  return post('/team/invite/email/accept', payload)
}

/** Reject an email invite token. */
export function rejectEmailInvite(token: string): Promise<{ ok: boolean }> {
  return post('/team/invite/email/reject', { token })
}

/** Change a member's org role. */
export function changeMemberRole(payload: {
  orgId: string; adminUid: string; targetUid: string; newRole: OrgRole
}): Promise<{ ok: boolean }> {
  return post('/team/members/role', payload)
}

export function removeMemberApi(payload: {
  orgId: string; adminUid: string; targetUid: string
}): Promise<{ ok: boolean }> {
  return post('/team/members/remove', payload)
}

export function disableMemberApi(payload: {
  orgId: string; adminUid: string; targetUid: string
}): Promise<{ ok: boolean }> {
  return post('/team/members/disable', payload)
}

export function enableMemberApi(payload: {
  orgId: string; adminUid: string; targetUid: string
}): Promise<{ ok: boolean }> {
  return post('/team/members/enable', payload)
}
