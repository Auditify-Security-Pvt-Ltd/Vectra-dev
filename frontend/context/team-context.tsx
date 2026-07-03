'use client'

import {
  createContext, useContext, useEffect, useState, useCallback, ReactNode,
} from 'react'
import { toast } from 'sonner'
import { useAuth } from './auth-context'
import type { OrgRole } from '@/lib/rbac'
import { hasPermission } from '@/lib/rbac'
import type { OrgDoc, OrgMember, OrgInvitation, AuditLog } from '@/lib/firestore-team'
import {
  listenToOrg, listenToMembers, listenToInvitations, listenToAuditLogs,
  createInvitationWithToken, updateInvitationStatus, updateInvitation,
  deleteInvitationWithToken, deleteInvitation,
  updateMemberRole, updateMemberStatus, removeMember,
  regenerateLinkToken,
  addAuditLog, makeAuditId, makeInviteId, makeSecureToken,
} from '@/lib/firestore-team'
import {
  sendEmailInvite, resendEmailInvite,
  changeMemberRole, removeMemberApi, disableMemberApi, enableMemberApi,
} from '@/lib/api-team'

// ── Types ─────────────────────────────────────────────────────────────

export interface CreateEmailInviteResult {
  inviteId:   string
  emailSent:  boolean
  emailError: string | null
}

export interface CreateLinkInviteResult {
  inviteId: string
  token:    string
  url:      string
}

interface TeamContextValue {
  org:         OrgDoc | null
  members:     OrgMember[]
  invitations: OrgInvitation[]
  auditLogs:   AuditLog[]
  loadingTeam: boolean
  // Email invitations
  inviteByEmail:    (email: string, role: OrgRole) => Promise<CreateEmailInviteResult>
  resendEmailInvitation: (invite: OrgInvitation) => Promise<void>
  // Link invitations
  createLinkInvite: (role: OrgRole, expiresInHours: number, maxUses: number | null) => Promise<CreateLinkInviteResult>
  regenerateLinkInvite: (invite: OrgInvitation) => Promise<string>
  toggleLinkInvite: (invite: OrgInvitation, enabled: boolean) => Promise<void>
  // Common invitation actions
  revokeInvite:   (invite: OrgInvitation) => Promise<void>
  deleteInvite:   (invite: OrgInvitation) => Promise<void>
  // Member management
  changeMemberRoleAction: (member: OrgMember, newRole: OrgRole) => Promise<void>
  disableMember:          (member: OrgMember) => Promise<void>
  enableMember:           (member: OrgMember) => Promise<void>
  removeMemberAction:     (member: OrgMember) => Promise<void>
}

const TeamContext = createContext<TeamContextValue | null>(null)

// ── Provider ──────────────────────────────────────────────────────────

export function TeamProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()

  const [org,         setOrg]         = useState<OrgDoc | null>(null)
  const [members,     setMembers]     = useState<OrgMember[]>([])
  const [invitations, setInvitations] = useState<OrgInvitation[]>([])
  const [auditLogs,   setAuditLogs]   = useState<AuditLog[]>([])
  const [loadingTeam, setLoadingTeam] = useState(true)

  const orgId = user?.organizationId ?? null

  useEffect(() => {
    if (!orgId) { setLoadingTeam(false); return }
    setLoadingTeam(true)
    const unsubs = [
      listenToOrg(orgId,         (o)  => { setOrg(o); setLoadingTeam(false) }),
      listenToMembers(orgId,     (ms) => setMembers(ms)),
      listenToInvitations(orgId, (is) => setInvitations(is)),
      listenToAuditLogs(orgId,   (ls) => setAuditLogs(ls)),
    ]
    return () => unsubs.forEach((u) => u())
  }, [orgId])

  // ── Audit helper ────────────────────────────────────────────────────

  const audit = useCallback(async (
    action: string,
    targetId?: string,
    targetEmail?: string,
    details?: string,
  ) => {
    if (!user || !orgId) return
    await addAuditLog(orgId, {
      logId:      makeAuditId(),
      actorId:    user.uid,
      actorName:  user.name,
      action,
      targetId,
      targetEmail,
      details,
      userAgent:  typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
    }).catch(() => {})
  }, [user, orgId])

  // ── Email invitations ───────────────────────────────────────────────

  const inviteByEmail = useCallback(async (
    email: string,
    role: OrgRole,
  ): Promise<CreateEmailInviteResult> => {
    if (!user || !orgId || !org) throw new Error('Not authenticated')
    if (!hasPermission(user.orgRole, 'inviteMembers')) throw new Error('Permission denied')

    const inviteId   = makeInviteId()
    const expiresAt  = new Date(Date.now() + 72 * 3600 * 1000).toISOString()

    // 1. Send email + get token from backend
    const result = await sendEmailInvite({
      orgId, orgName: org.name, inviterUid: user.uid, inviterName: user.name,
      email, role, inviteId,
    })

    // 2. Write invitation to Firestore + token lookup entry
    await createInvitationWithToken(orgId, {
      inviteId,
      inviteType:  'email',
      email,
      orgRole:     role,
      invitedBy:   user.uid,
      inviterName: user.name,
      status:      'pending',
      linkEnabled: false,
      maxUses:     1,
      usedCount:   0,
      expiresAt,
      createdAt:   '' as any,
    }, result.token)

    await audit(
      result.emailSent ? `invited ${email} as ${role} (email sent)` : `invited ${email} as ${role} (email failed: ${result.emailError})`,
      undefined, email, `role=${role}`,
    )

    return { inviteId, emailSent: result.emailSent, emailError: result.emailError }
  }, [user, orgId, org, audit])

  const resendEmailInvitation = useCallback(async (invite: OrgInvitation) => {
    if (!user || !orgId || !org || invite.inviteType !== 'email' || !invite.email) return

    const result = await resendEmailInvite({
      orgId, orgName: org.name, inviterUid: user.uid, inviterName: user.name,
      inviteId: invite.inviteId, email: invite.email, role: invite.orgRole,
    })

    const newExpiry = new Date(Date.now() + 72 * 3600 * 1000).toISOString()
    await updateInvitation(orgId, invite.inviteId, { expiresAt: newExpiry, status: 'pending' })

    await audit(
      result.emailSent
        ? `resent invitation to ${invite.email}`
        : `resent invitation to ${invite.email} (email failed: ${result.emailError})`,
      undefined, invite.email,
    )

    if (!result.emailSent) {
      throw new Error(result.emailError ?? 'Email delivery failed')
    }
  }, [user, orgId, org, audit])

  // ── Link invitations ────────────────────────────────────────────────

  const createLinkInvite = useCallback(async (
    role: OrgRole,
    expiresInHours: number,
    maxUses: number | null,
  ): Promise<CreateLinkInviteResult> => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (!hasPermission(user.orgRole, 'inviteMembers')) throw new Error('Permission denied')

    const inviteId  = makeInviteId()
    const token     = makeSecureToken()
    const expiresAt = expiresInHours > 0
      ? new Date(Date.now() + expiresInHours * 3600 * 1000).toISOString()
      : new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString() // 1 year = "never"

    await createInvitationWithToken(orgId, {
      inviteId,
      inviteType:  'link',
      orgRole:     role,
      invitedBy:   user.uid,
      inviterName: user.name,
      status:      'pending',
      linkEnabled: true,
      maxUses,
      usedCount:   0,
      token,
      expiresAt,
      createdAt:   '' as any,
    }, token)

    const url = `${window.location.origin}/invite/${token}`
    await audit(`generated invite link for role=${role}`, undefined, undefined, `maxUses=${maxUses ?? '∞'}`)

    return { inviteId, token, url }
  }, [user, orgId, audit])

  const regenerateLinkInvite = useCallback(async (invite: OrgInvitation): Promise<string> => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (!invite.token) throw new Error('No token to regenerate')

    const newToken    = makeSecureToken()
    const newExpiresAt = new Date(invite.expiresAt).getTime() > Date.now()
      ? invite.expiresAt  // keep same expiry
      : new Date(Date.now() + 72 * 3600 * 1000).toISOString()

    await regenerateLinkToken(orgId, invite.inviteId, invite.token, newToken, newExpiresAt)
    await audit(`regenerated invite link for role=${invite.orgRole}`)

    return `${window.location.origin}/invite/${newToken}`
  }, [user, orgId, audit])

  const toggleLinkInvite = useCallback(async (invite: OrgInvitation, enabled: boolean) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    await updateInvitation(orgId, invite.inviteId, { linkEnabled: enabled })
    await audit(`${enabled ? 'enabled' : 'disabled'} invite link for role=${invite.orgRole}`)
  }, [user, orgId, audit])

  // ── Common invite actions ───────────────────────────────────────────

  const revokeInvite = useCallback(async (invite: OrgInvitation) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    await updateInvitationStatus(orgId, invite.inviteId, 'revoked')
    await audit(`revoked invitation for ${invite.email ?? invite.orgRole + ' link'}`, undefined, invite.email)
  }, [user, orgId, audit])

  const deleteInvite = useCallback(async (invite: OrgInvitation) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (invite.token) {
      await deleteInvitationWithToken(orgId, invite.inviteId, invite.token)
    } else {
      await deleteInvitation(orgId, invite.inviteId)
    }
    await audit(`deleted invitation for ${invite.email ?? invite.orgRole + ' link'}`, undefined, invite.email)
  }, [user, orgId, audit])

  // ── Member management ───────────────────────────────────────────────

  const changeMemberRoleAction = useCallback(async (member: OrgMember, newRole: OrgRole) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (!hasPermission(user.orgRole, 'changeRoles')) throw new Error('Permission denied')
    if (member.userId === user.uid) throw new Error('Cannot change your own role')
    await changeMemberRole({ orgId, adminUid: user.uid, targetUid: member.userId, newRole })
    await updateMemberRole(orgId, member.userId, newRole)
    await audit(`changed ${member.name}'s role to ${newRole}`, member.userId, member.email, `${member.orgRole}→${newRole}`)
  }, [user, orgId, audit])

  const disableMember = useCallback(async (member: OrgMember) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (!hasPermission(user.orgRole, 'disableMembers')) throw new Error('Permission denied')
    if (member.userId === user.uid) throw new Error('Cannot disable yourself')
    await disableMemberApi({ orgId, adminUid: user.uid, targetUid: member.userId })
    await updateMemberStatus(orgId, member.userId, 'disabled')
    await audit(`disabled ${member.name}`, member.userId, member.email)
  }, [user, orgId, audit])

  const enableMember = useCallback(async (member: OrgMember) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    await enableMemberApi({ orgId, adminUid: user.uid, targetUid: member.userId })
    await updateMemberStatus(orgId, member.userId, 'active')
    await audit(`reactivated ${member.name}`, member.userId, member.email)
  }, [user, orgId, audit])

  const removeMemberAction = useCallback(async (member: OrgMember) => {
    if (!user || !orgId) throw new Error('Not authenticated')
    if (!hasPermission(user.orgRole, 'removeMembers')) throw new Error('Permission denied')
    if (member.userId === user.uid) throw new Error('Cannot remove yourself')
    await removeMemberApi({ orgId, adminUid: user.uid, targetUid: member.userId })
    await removeMember(orgId, member.userId)
    await audit(`removed ${member.name} from team`, member.userId, member.email)
  }, [user, orgId, audit])

  return (
    <TeamContext.Provider value={{
      org, members, invitations, auditLogs, loadingTeam,
      inviteByEmail, resendEmailInvitation,
      createLinkInvite, regenerateLinkInvite, toggleLinkInvite,
      revokeInvite, deleteInvite,
      changeMemberRoleAction, disableMember, enableMember, removeMemberAction,
    }}>
      {children}
    </TeamContext.Provider>
  )
}

export function useTeam(): TeamContextValue {
  const ctx = useContext(TeamContext)
  if (!ctx) throw new Error('useTeam must be used within TeamProvider')
  return ctx
}
