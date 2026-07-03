/**
 * Firestore helpers for organization, team members, invitations, and audit logs.
 *
 * Structure:
 *   organizations/{orgId}                         — org metadata
 *   organizations/{orgId}/members/{uid}           — active members
 *   organizations/{orgId}/invitations/{inviteId}  — all invitations
 *   organizations/{orgId}/auditLogs/{logId}       — audit trail
 *   invitationTokens/{token}                      — top-level token → orgId lookup
 */

import {
  collection,
  doc,
  setDoc,
  getDoc,
  updateDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  serverTimestamp,
  Timestamp,
  limit,
  writeBatch,
} from 'firebase/firestore'
import { db } from './firebase'
import type { OrgRole } from './rbac'

// ── Types ─────────────────────────────────────────────────────────────

export interface OrgDoc {
  orgId:      string
  ownerId:    string
  ownerName:  string
  ownerEmail: string
  name:       string
  createdAt:  Timestamp | string
}

export interface OrgMember {
  userId:    string
  name:      string
  email:     string
  orgRole:   OrgRole
  status:    'active' | 'disabled'
  joinedAt:  Timestamp | string
  lastLogin?: Timestamp | string
}

export type InviteType   = 'email' | 'link'
export type InviteStatus = 'pending' | 'accepted' | 'rejected' | 'expired' | 'cancelled' | 'revoked'

export interface OrgInvitation {
  inviteId:    string
  inviteType:  InviteType
  email?:      string       // email invites only
  orgRole:     OrgRole
  invitedBy:   string
  inviterName: string
  status:      InviteStatus
  // Link invite fields
  linkEnabled: boolean
  maxUses:     number | null  // null = unlimited
  usedCount:   number
  token?:      string         // stored for link invites (needed for copy/regen)
  // Timestamps
  expiresAt:   string
  createdAt:   Timestamp | string
  acceptedAt?: Timestamp | string
}

export interface AuditLog {
  logId:       string
  actorId:     string
  actorName:   string
  action:      string
  targetId?:   string
  targetEmail?: string
  details?:    string
  ip?:         string
  userAgent?:  string
  timestamp:   Timestamp | string
}

/** Top-level token lookup — allows the public invite page to resolve any token */
export interface InviteTokenEntry {
  token:    string
  orgId:    string
  inviteId: string
  type:     InviteType
}

// ── Path helpers ──────────────────────────────────────────────────────

const orgDoc      = (orgId: string) => doc(db, 'organizations', orgId)
const membersCol  = (orgId: string) => collection(db, 'organizations', orgId, 'members')
const memberDoc   = (orgId: string, uid: string) => doc(db, 'organizations', orgId, 'members', uid)
const invitesCol  = (orgId: string) => collection(db, 'organizations', orgId, 'invitations')
const inviteDoc   = (orgId: string, id: string) => doc(db, 'organizations', orgId, 'invitations', id)
const auditCol    = (orgId: string) => collection(db, 'organizations', orgId, 'auditLogs')
const auditDocRef = (orgId: string, id: string) => doc(db, 'organizations', orgId, 'auditLogs', id)
const tokenDoc    = (token: string) => doc(db, 'invitationTokens', token)

// ── Organization ──────────────────────────────────────────────────────

export async function createOrg(org: OrgDoc): Promise<void> {
  await setDoc(orgDoc(org.orgId), { ...org, createdAt: serverTimestamp() })
}

export async function getOrg(orgId: string): Promise<OrgDoc | null> {
  const snap = await getDoc(orgDoc(orgId))
  return snap.exists() ? (snap.data() as OrgDoc) : null
}

export function listenToOrg(orgId: string, cb: (org: OrgDoc | null) => void): () => void {
  return onSnapshot(orgDoc(orgId), (snap) => cb(snap.exists() ? (snap.data() as OrgDoc) : null))
}

// ── Members ───────────────────────────────────────────────────────────

export async function addMember(orgId: string, member: OrgMember): Promise<void> {
  await setDoc(memberDoc(orgId, member.userId), { ...member, joinedAt: serverTimestamp() })
}

export async function getMember(orgId: string, uid: string): Promise<OrgMember | null> {
  const snap = await getDoc(memberDoc(orgId, uid))
  return snap.exists() ? (snap.data() as OrgMember) : null
}

export async function updateMemberRole(orgId: string, uid: string, orgRole: OrgRole): Promise<void> {
  await updateDoc(memberDoc(orgId, uid), { orgRole })
}

export async function updateMemberStatus(orgId: string, uid: string, status: 'active' | 'disabled'): Promise<void> {
  await updateDoc(memberDoc(orgId, uid), { status })
}

export async function removeMember(orgId: string, uid: string): Promise<void> {
  await deleteDoc(memberDoc(orgId, uid))
}

export function listenToMembers(orgId: string, cb: (members: OrgMember[]) => void): () => void {
  return onSnapshot(membersCol(orgId), (snap) => cb(snap.docs.map((d) => d.data() as OrgMember)))
}

// ── Invitations ───────────────────────────────────────────────────────

export async function createInvitation(orgId: string, invite: OrgInvitation): Promise<void> {
  await setDoc(inviteDoc(orgId, invite.inviteId), { ...invite, createdAt: serverTimestamp() })
}

/** Create invitation + write token lookup in a single batch. */
export async function createInvitationWithToken(
  orgId:    string,
  invite:   OrgInvitation,
  token:    string,
): Promise<void> {
  const batch = writeBatch(db)
  batch.set(inviteDoc(orgId, invite.inviteId), { ...invite, createdAt: serverTimestamp() })
  batch.set(tokenDoc(token), { token, orgId, inviteId: invite.inviteId, type: invite.inviteType })
  await batch.commit()
}

export async function updateInvitationStatus(
  orgId:    string,
  inviteId: string,
  status:   InviteStatus,
  extra?:   Partial<OrgInvitation>,
): Promise<void> {
  await updateDoc(inviteDoc(orgId, inviteId), { status, ...extra })
}

export async function updateInvitation(
  orgId:    string,
  inviteId: string,
  updates:  Partial<OrgInvitation>,
): Promise<void> {
  await updateDoc(inviteDoc(orgId, inviteId), updates as Record<string, unknown>)
}

export async function deleteInvitation(orgId: string, inviteId: string): Promise<void> {
  await deleteDoc(inviteDoc(orgId, inviteId))
}

/** Delete invitation + its token lookup atomically. */
export async function deleteInvitationWithToken(
  orgId:    string,
  inviteId: string,
  token:    string,
): Promise<void> {
  const batch = writeBatch(db)
  batch.delete(inviteDoc(orgId, inviteId))
  batch.delete(tokenDoc(token))
  await batch.commit()
}

export function listenToInvitations(orgId: string, cb: (invites: OrgInvitation[]) => void): () => void {
  return onSnapshot(invitesCol(orgId), (snap) => cb(snap.docs.map((d) => d.data() as OrgInvitation)))
}

// ── Token lookup ──────────────────────────────────────────────────────

/** Resolve a token string → { orgId, inviteId, type }.
 *  Used by the public invite landing page without knowing orgId.
 */
export async function resolveInviteToken(token: string): Promise<InviteTokenEntry | null> {
  const snap = await getDoc(tokenDoc(token))
  return snap.exists() ? (snap.data() as InviteTokenEntry) : null
}

/** Fetch the full invite document once we know orgId + inviteId. */
export async function getInvitation(orgId: string, inviteId: string): Promise<OrgInvitation | null> {
  const snap = await getDoc(inviteDoc(orgId, inviteId))
  return snap.exists() ? (snap.data() as OrgInvitation) : null
}

/** Replace the token for a link invite (regenerate). */
export async function regenerateLinkToken(
  orgId:       string,
  inviteId:    string,
  oldToken:    string,
  newToken:    string,
  newExpiresAt: string,
): Promise<void> {
  const batch = writeBatch(db)
  // Remove old token lookup
  batch.delete(tokenDoc(oldToken))
  // Write new token lookup
  batch.set(tokenDoc(newToken), { token: newToken, orgId, inviteId, type: 'link' as InviteType })
  // Update invite doc with new token and expiry
  batch.update(inviteDoc(orgId, inviteId), { token: newToken, expiresAt: newExpiresAt, usedCount: 0 })
  await batch.commit()
}

// ── Audit Logs ────────────────────────────────────────────────────────

export async function addAuditLog(orgId: string, log: Omit<AuditLog, 'timestamp'>): Promise<void> {
  await setDoc(auditDocRef(orgId, log.logId), { ...log, timestamp: serverTimestamp() })
}

export function listenToAuditLogs(orgId: string, cb: (logs: AuditLog[]) => void, maxEntries = 100): () => void {
  const q = query(auditCol(orgId), orderBy('timestamp', 'desc'), limit(maxEntries))
  return onSnapshot(q, (snap) => cb(snap.docs.map((d) => d.data() as AuditLog)))
}

// ── Helpers ───────────────────────────────────────────────────────────

export function makeAuditId(): string {
  return `log_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

export function makeInviteId(): string {
  return `inv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

/** Generate a cryptographically secure invite token (32 bytes → 43 base64url chars). */
export function makeSecureToken(): string {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}
