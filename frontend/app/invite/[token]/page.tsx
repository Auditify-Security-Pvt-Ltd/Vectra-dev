'use client'

import { useEffect, useState, use, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  Loader2, CheckCircle2, XCircle, Shield, Edit2, Eye,
  Mail, Lock, User, AlertCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useAuth } from '@/context/auth-context'
import type { OrgRole } from '@/lib/rbac'
import {
  resolveInviteToken, getInvitation, getOrg, addMember,
  updateInvitationStatus, updateInvitation, addAuditLog, makeAuditId,
} from '@/lib/firestore-team'
import { acceptEmailInvite } from '@/lib/api-team'
import { updateDoc, doc } from 'firebase/firestore'
import { db } from '@/lib/firebase'

// ── Types ─────────────────────────────────────────────────────────────

interface ResolvedInvite {
  inviteId:    string
  orgId:       string
  orgName:     string
  inviterName: string
  email?:      string
  role:        OrgRole
  type:        'email' | 'link'
  expiresAt:   string
  maxUses:     number | null
  usedCount:   number
}

type Phase = 'loading' | 'ready' | 'error' | 'processing' | 'done'

// ── Role card ─────────────────────────────────────────────────────────

const ROLE_META: Record<OrgRole, { icon: typeof Shield; color: string; desc: string }> = {
  admin:  { icon: Shield, color: 'text-primary',          desc: 'Full access including team management and settings' },
  editor: { icon: Edit2,  color: 'text-blue-400',         desc: 'Start scans, manage findings, generate reports'     },
  viewer: { icon: Eye,    color: 'text-muted-foreground', desc: 'Read-only access to findings and reports'           },
}

function RoleCard({ role }: { role: OrgRole }) {
  const { icon: Icon, color, desc } = ROLE_META[role] ?? ROLE_META.viewer
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-foreground/5 border border-foreground/10">
      <div className="p-1.5 bg-foreground/8 rounded-md shrink-0">
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div>
        <p className={`text-sm font-semibold capitalize ${color}`}>{role}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
      </div>
    </div>
  )
}

// ── Forms ─────────────────────────────────────────────────────────────

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="text-sm font-medium text-foreground">{label}</label>
      {children}
    </div>
  )
}

function RegisterForm({ prefilledEmail, onDone }: { prefilledEmail?: string; onDone: () => void }) {
  const { register } = useAuth()
  const [name,    setName]    = useState('')
  const [email,   setEmail]   = useState(prefilledEmail ?? '')
  const [pass,    setPass]    = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy,    setBusy]    = useState(false)
  const [err,     setErr]     = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault(); setErr('')
    if (pass !== confirm) { setErr('Passwords do not match'); return }
    if (pass.length < 6)  { setErr('Password must be at least 6 characters'); return }
    setBusy(true)
    try {
      // Invited: account only — joining happens on acceptance, no new organization.
      await register(name.trim(), email.trim().toLowerCase(), pass, null)
      onDone()
    } catch (ex: any) {
      const code = ex?.code ?? ''
      setErr(
        code === 'auth/email-already-in-use' ? 'This email already has an account. Sign in instead.' :
        ex?.message ?? 'Registration failed. Please try again.',
      )
    } finally { setBusy(false) }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {err && (
        <div className="flex items-start gap-2 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />{err}
        </div>
      )}
      <FieldRow label="Full Name">
        <div className="relative">
          <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Jane Smith" required className="pl-9 bg-background/50 border-foreground/20" />
        </div>
      </FieldRow>
      <FieldRow label="Email">
        <div className="relative">
          <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            readOnly={!!prefilledEmail} required
            className={`pl-9 bg-background/50 border-foreground/20 ${prefilledEmail ? 'opacity-70' : ''}`} />
        </div>
      </FieldRow>
      <FieldRow label="Password">
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="••••••••" required className="pl-9 bg-background/50 border-foreground/20" />
        </div>
      </FieldRow>
      <FieldRow label="Confirm Password">
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="••••••••" required className="pl-9 bg-background/50 border-foreground/20" />
        </div>
      </FieldRow>
      <Button type="submit" disabled={busy} className="w-full h-11">
        {busy ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
        {busy ? 'Creating account...' : 'Create Account & Join'}
      </Button>
    </form>
  )
}

function SignInForm({ prefilledEmail, onDone }: { prefilledEmail?: string; onDone: () => void }) {
  const { login } = useAuth()
  const [email, setEmail] = useState(prefilledEmail ?? '')
  const [pass,  setPass]  = useState('')
  const [busy,  setBusy]  = useState(false)
  const [err,   setErr]   = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault(); setErr(''); setBusy(true)
    try { await login(email.trim().toLowerCase(), pass); onDone() }
    catch (ex: any) { setErr(ex?.message ?? 'Sign in failed') }
    finally { setBusy(false) }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {err && (
        <div className="flex items-start gap-2 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />{err}
        </div>
      )}
      <FieldRow label="Email">
        <div className="relative">
          <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            readOnly={!!prefilledEmail} required
            className={`pl-9 bg-background/50 border-foreground/20 ${prefilledEmail ? 'opacity-70' : ''}`} />
        </div>
      </FieldRow>
      <FieldRow label="Password">
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="••••••••" required className="pl-9 bg-background/50 border-foreground/20" />
        </div>
      </FieldRow>
      <Button type="submit" disabled={busy} className="w-full h-11">
        {busy ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
        {busy ? 'Signing in...' : 'Sign In & Join'}
      </Button>
      <p className="text-center text-xs text-muted-foreground">
        <Link href="/auth/forgot-password" className="text-primary hover:underline">Forgot password?</Link>
      </p>
    </form>
  )
}

// ── Core page ─────────────────────────────────────────────────────────

function InviteContent({ token }: { token: string }) {
  const router = useRouter()
  const { user, loading: authLoading, logout, refreshUser } = useAuth()

  const [phase,       setPhase]       = useState<Phase>('loading')
  const [invite,      setInvite]      = useState<ResolvedInvite | null>(null)
  const [errMsg,      setErrMsg]      = useState('')
  const [outcome,     setOutcome]     = useState<'accepted' | 'declined' | null>(null)
  const [authDone,    setAuthDone]    = useState(false) // set to true after register/login completes

  // ── 1. Resolve token ──────────────────────────────────────────────

  useEffect(() => {
    if (!token) { setErrMsg('Missing invitation token.'); setPhase('error'); return }

    resolveInviteToken(token).then(async (entry) => {
      if (!entry) throw new Error('This invitation link is invalid or has already been used.')

      const [inv, org] = await Promise.all([
        getInvitation(entry.orgId, entry.inviteId),
        getOrg(entry.orgId),
      ])

      if (!inv || !org)            throw new Error('Invitation not found.')
      if (inv.status === 'accepted')     throw new Error('This invitation has already been accepted.')
      if (inv.status === 'revoked')      throw new Error('This invitation has been revoked.')
      if (inv.status === 'expired' || new Date(inv.expiresAt) < new Date())
                                         throw new Error('This invitation has expired.')
      if (inv.status === 'cancelled')    throw new Error('This invitation was cancelled.')
      if (entry.type === 'link' && !inv.linkEnabled)
                                         throw new Error('This invitation link has been disabled.')
      if (entry.type === 'link' && inv.maxUses !== null && inv.usedCount >= inv.maxUses)
                                         throw new Error('This invitation link has reached its use limit.')

      setInvite({
        inviteId: inv.inviteId, orgId: entry.orgId, orgName: org.name,
        inviterName: inv.inviterName, email: inv.email, role: inv.orgRole,
        type: entry.type, expiresAt: inv.expiresAt,
        maxUses: inv.maxUses, usedCount: inv.usedCount,
      })
      setPhase('ready')
    }).catch((ex) => { setErrMsg(ex?.message ?? 'Failed to load invitation.'); setPhase('error') })
  }, [token])

  // ── 2. Accept after auth completes (register or login) ────────────

  useEffect(() => {
    if (!authDone || !user || !invite) return
    void accept(user.uid, user.name, user.email)
  }, [authDone, user]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── 3. Accept ─────────────────────────────────────────────────────

  const accept = useCallback(async (uid: string, name: string, email: string) => {
    if (!invite) return
    setPhase('processing')
    try {
      // Consume backend token for email invites
      if (invite.type === 'email') {
        await acceptEmailInvite({ token, userId: uid, userName: name, userEmail: email })
      }

      // Add as org member
      await addMember(invite.orgId, {
        userId: uid, name, email, orgRole: invite.role, status: 'active', joinedAt: '' as any,
      })

      // Update user doc
      const platformRole = invite.role === 'admin' ? 'team_admin'
                         : invite.role === 'editor' ? 'analyst' : 'customer'
      await updateDoc(doc(db, 'users', uid), {
        organizationId: invite.orgId,
        role:           platformRole,
      })

      // Update invite status
      if (invite.type === 'email') {
        await updateInvitationStatus(invite.orgId, invite.inviteId, 'accepted', {
          acceptedAt: new Date().toISOString() as any,
        })
      } else {
        const newCount    = invite.usedCount + 1
        const isExhausted = invite.maxUses !== null && newCount >= invite.maxUses
        await updateInvitation(invite.orgId, invite.inviteId, {
          usedCount: newCount,
          ...(isExhausted ? { status: 'accepted' } : {}),
        })
      }

      // Audit
      await addAuditLog(invite.orgId, {
        logId: makeAuditId(), actorId: uid, actorName: name,
        action: `accepted ${invite.type} invitation as ${invite.role}`,
        targetId: uid, targetEmail: email,
      }).catch(() => {})

      await refreshUser()
      setOutcome('accepted')
      setPhase('done')
      setTimeout(() => router.push('/app/dashboard'), 2200)
    } catch (ex: any) {
      setErrMsg(ex?.message ?? 'Failed to accept invitation.')
      setPhase('error')
    }
  }, [invite, token, router, refreshUser])

  // ── Render ────────────────────────────────────────────────────────

  if (authLoading || phase === 'loading') {
    return (
      <div className="flex flex-col items-center gap-3 py-10">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Verifying invitation...</p>
      </div>
    )
  }

  if (phase === 'processing') {
    return (
      <div className="flex flex-col items-center gap-3 py-10">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Joining organization...</p>
      </div>
    )
  }

  if (phase === 'done') {
    return (
      <div className="text-center space-y-4 py-6">
        {outcome === 'accepted' ? (
          <>
            <CheckCircle2 className="w-14 h-14 text-green-400 mx-auto" />
            <div>
              <h2 className="text-xl font-bold text-foreground">Welcome to {invite?.orgName}!</h2>
              <p className="text-sm text-muted-foreground mt-1">
                You've joined as <strong className="text-primary capitalize">{invite?.role}</strong>.
              </p>
              <p className="text-xs text-muted-foreground mt-2">Redirecting to dashboard...</p>
            </div>
          </>
        ) : (
          <>
            <XCircle className="w-12 h-12 text-muted-foreground mx-auto" />
            <h2 className="text-lg font-bold text-foreground">Invitation Declined</h2>
            <Button variant="outline" size="sm" onClick={() => router.push('/')}>Go Home</Button>
          </>
        )}
      </div>
    )
  }

  if (phase === 'error') {
    return (
      <div className="text-center space-y-4 py-6">
        <XCircle className="w-12 h-12 text-destructive mx-auto" />
        <div>
          <h2 className="text-lg font-bold text-foreground">Invitation Unavailable</h2>
          <p className="text-sm text-muted-foreground mt-1 max-w-xs mx-auto">{errMsg}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => router.push('/')}>Go Home</Button>
      </div>
    )
  }

  if (!invite) return null

  return (
    <div className="space-y-5">
      {/* Org info */}
      <div className="text-center space-y-1">
        <p className="text-[11px] font-semibold text-muted-foreground/60 uppercase tracking-widest">
          You're invited to join
        </p>
        <h2 className="text-xl font-bold text-foreground">{invite.orgName}</h2>
        <p className="text-sm text-muted-foreground">
          Invited by <strong className="text-foreground">{invite.inviterName}</strong>
        </p>
      </div>

      <RoleCard role={invite.role} />

      <p className="text-xs text-muted-foreground text-center">
        Expires {new Date(invite.expiresAt).toLocaleDateString('en-US', { dateStyle: 'medium' })}
        {invite.type === 'link' && invite.maxUses !== null && (
          <span> · {invite.maxUses - invite.usedCount} use{invite.maxUses - invite.usedCount !== 1 ? 's' : ''} left</span>
        )}
      </p>

      {/* Already logged in */}
      {user ? (
        <div className="space-y-3">
          <div className="p-3 rounded-lg bg-foreground/5 border border-foreground/10">
            <p className="text-xs text-muted-foreground mb-1">Accepting as</p>
            <p className="text-sm font-medium text-foreground">{user.name}</p>
            <p className="text-xs text-muted-foreground">{user.email}</p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="flex-1"
              onClick={async () => { await logout(); router.refresh() }}
            >
              Wrong account
            </Button>
            <Button className="flex-1" onClick={() => accept(user.uid, user.name, user.email)}>
              Accept & Join
            </Button>
          </div>
        </div>
      ) : (
        <Tabs defaultValue={invite.type === 'link' ? 'register' : 'signin'}>
          <TabsList className="w-full bg-foreground/5 border border-foreground/10">
            <TabsTrigger value="register" className="flex-1 text-xs">New Account</TabsTrigger>
            <TabsTrigger value="signin"   className="flex-1 text-xs">Sign In</TabsTrigger>
          </TabsList>
          <TabsContent value="register" className="mt-4">
            <RegisterForm prefilledEmail={invite.email} onDone={() => setAuthDone(true)} />
          </TabsContent>
          <TabsContent value="signin" className="mt-4">
            <SignInForm prefilledEmail={invite.email} onDone={() => setAuthDone(true)} />
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}

// ── Page export ───────────────────────────────────────────────────────

export default function InviteTokenPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = use(params)

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-6">
          <Link href="/">
            <span className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Vectra
            </span>
          </Link>
          <p className="text-xs text-muted-foreground mt-0.5">Security Platform</p>
        </div>

        <div className="border border-foreground/10 rounded-xl p-7 bg-card shadow-xl">
          <InviteContent token={token} />
        </div>

        <p className="text-center text-xs text-muted-foreground mt-4">
          By accepting, you agree to Vectra's terms of service.
        </p>
      </div>
    </div>
  )
}
