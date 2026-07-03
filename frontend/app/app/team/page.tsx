'use client'

import { useState, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  Plus, MoreHorizontal, Shield, Eye, Edit2, Mail, RefreshCw,
  Trash2, UserX, UserCheck, Clock, Users, AlertCircle, Activity,
  Search, Link2, Copy, ToggleLeft, ToggleRight, Loader2, Check,
} from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useAuth } from '@/context/auth-context'
import { useTeam } from '@/context/team-context'
import type { OrgRole } from '@/lib/rbac'
import { hasPermission } from '@/lib/rbac'
import type { OrgMember, OrgInvitation, AuditLog } from '@/lib/firestore-team'

// ── Helpers ───────────────────────────────────────────────────────────

function fmtDate(val: any): string {
  if (!val) return '—'
  try {
    const d = val?.toDate ? val.toDate() : new Date(val)
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  } catch { return '—' }
}

function fmtDateTime(val: any): string {
  if (!val) return '—'
  try {
    const d = val?.toDate ? val.toDate() : new Date(val)
    return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch { return '—' }
}

async function copyToClipboard(text: string) {
  try { await navigator.clipboard.writeText(text); return true }
  catch { return false }
}

// ── Role badge ─────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: OrgRole }) {
  const map: Record<OrgRole, string> = {
    admin:  'bg-primary/15 text-primary border-primary/20',
    editor: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
    viewer: 'bg-foreground/10 text-muted-foreground border-foreground/15',
  }
  const icons: Record<OrgRole, typeof Shield> = { admin: Shield, editor: Edit2, viewer: Eye }
  const Icon = icons[role]
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border capitalize ${map[role]}`}>
      <Icon className="w-3 h-3" />
      {role}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    'bg-green-500/10 text-green-400 border-green-500/20',
    disabled:  'bg-red-500/10 text-red-400 border-red-500/20',
    pending:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    accepted:  'bg-green-500/10 text-green-400 border-green-500/20',
    cancelled: 'bg-foreground/10 text-muted-foreground border-foreground/15',
    expired:   'bg-foreground/10 text-muted-foreground border-foreground/15',
    revoked:   'bg-red-500/10 text-red-400 border-red-500/20',
  }
  return (
    <span className={`inline-flex items-center text-xs font-medium px-2 py-0.5 rounded border capitalize ${map[status] ?? map.expired}`}>
      {status}
    </span>
  )
}

// ── Role selector (shared) ─────────────────────────────────────────────

function RoleSelect({ value, onChange }: { value: OrgRole; onChange: (r: OrgRole) => void }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as OrgRole)}>
      <SelectTrigger className="bg-background/50 border-foreground/20">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="admin">
          <div><p className="font-medium">Admin</p><p className="text-xs text-muted-foreground">Full access including team management</p></div>
        </SelectItem>
        <SelectItem value="editor">
          <div><p className="font-medium">Editor</p><p className="text-xs text-muted-foreground">Start scans, manage findings, generate reports</p></div>
        </SelectItem>
        <SelectItem value="viewer">
          <div><p className="font-medium">Viewer</p><p className="text-xs text-muted-foreground">Read-only access to findings and reports</p></div>
        </SelectItem>
      </SelectContent>
    </Select>
  )
}

function RoleDesc({ role }: { role: OrgRole }) {
  const desc: Record<OrgRole, string> = {
    admin:  'Admin has full system access: all modules, team management, settings, and all actions.',
    editor: 'Editor can start/stop scans, manage findings, generate and export reports. No team or settings access.',
    viewer: 'Viewer has read-only access to the dashboard, vulnerability management, and reports.',
  }
  return (
    <p className="text-xs text-muted-foreground p-3 bg-foreground/5 rounded-lg">{desc[role]}</p>
  )
}

// ── Invite modal (two tabs) ────────────────────────────────────────────

interface GeneratedLink {
  url:      string
  inviteId: string
}

function EmailInviteTab({ onClose }: { onClose: () => void }) {
  const { inviteByEmail } = useTeam()
  const [email, setEmail] = useState('')
  const [role,  setRole]  = useState<OrgRole>('editor')
  const [busy,  setBusy]  = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true)
    try {
      const { emailSent, emailError } = await inviteByEmail(email.trim().toLowerCase(), role)
      if (emailSent) {
        toast.success(`Invitation sent to ${email}`)
      } else {
        toast.warning(`Invitation created but email failed: ${emailError ?? 'unknown error'}`)
      }
      setEmail(''); setRole('editor'); onClose()
    } catch (err: any) {
      toast.error(err?.message ?? 'Failed to send invitation')
    } finally { setBusy(false) }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <label className="text-sm font-medium text-foreground">Email Address</label>
        <Input
          type="email" placeholder="colleague@company.com"
          value={email} onChange={(e) => setEmail(e.target.value)}
          required className="bg-background/50 border-foreground/20"
        />
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium text-foreground">Role</label>
        <RoleSelect value={role} onChange={setRole} />
      </div>
      <RoleDesc role={role} />
      <div className="flex gap-3 justify-end pt-1">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={busy}>
          {busy ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Sending...</> : <><Mail className="w-4 h-4 mr-2" />Send Invitation</>}
        </Button>
      </div>
    </form>
  )
}

function LinkInviteTab({ onClose }: { onClose: () => void }) {
  const { createLinkInvite } = useTeam()
  const [role,      setRole]      = useState<OrgRole>('editor')
  const [expiry,    setExpiry]    = useState('72')  // hours; '0' = never
  const [maxUses,   setMaxUses]   = useState('0')   // 0 = unlimited
  const [busy,      setBusy]      = useState(false)
  const [generated, setGenerated] = useState<GeneratedLink | null>(null)
  const [copied,    setCopied]    = useState(false)

  async function handleGenerate() {
    setBusy(true)
    try {
      const hours = parseInt(expiry, 10) || 0
      const uses  = parseInt(maxUses, 10) || 0
      const { url, inviteId } = await createLinkInvite(role, hours, uses === 0 ? null : uses)
      setGenerated({ url, inviteId })
      toast.success('Invite link generated')
    } catch (err: any) {
      toast.error(err?.message ?? 'Failed to generate link')
    } finally { setBusy(false) }
  }

  async function handleCopy() {
    if (!generated) return
    const ok = await copyToClipboard(generated.url)
    if (ok) { setCopied(true); setTimeout(() => setCopied(false), 2000) }
    else toast.error('Failed to copy')
  }

  if (generated) {
    return (
      <div className="space-y-4">
        <div className="space-y-1.5">
          <p className="text-sm font-medium text-foreground">Invite Link</p>
          <div className="flex gap-2">
            <Input readOnly value={generated.url} className="bg-background/50 border-foreground/20 font-mono text-xs" />
            <Button type="button" variant="outline" className="shrink-0 w-10 px-0" onClick={handleCopy}>
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            </Button>
          </div>
        </div>
        <p className="text-xs text-muted-foreground p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          Link generated for <strong className="capitalize text-foreground">{role}</strong> role.
          {parseInt(maxUses, 10) > 0 && ` Up to ${maxUses} use${parseInt(maxUses, 10) !== 1 ? 's' : ''}.`}
          {parseInt(expiry, 10) > 0 ? ` Expires in ${expiry}h.` : ' Never expires.'}
        </p>
        <div className="flex gap-3 justify-end pt-1">
          <Button variant="ghost" onClick={() => { setGenerated(null); setRole('editor'); setExpiry('72'); setMaxUses('0') }}>
            Generate Another
          </Button>
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <label className="text-sm font-medium text-foreground">Role</label>
        <RoleSelect value={role} onChange={setRole} />
      </div>
      <RoleDesc role={role} />
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium text-foreground">Expires After</label>
          <Select value={expiry} onValueChange={setExpiry}>
            <SelectTrigger className="bg-background/50 border-foreground/20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24">24 hours</SelectItem>
              <SelectItem value="72">3 days</SelectItem>
              <SelectItem value="168">7 days</SelectItem>
              <SelectItem value="720">30 days</SelectItem>
              <SelectItem value="0">Never</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium text-foreground">Max Uses</label>
          <Select value={maxUses} onValueChange={setMaxUses}>
            <SelectTrigger className="bg-background/50 border-foreground/20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">Unlimited</SelectItem>
              <SelectItem value="1">1 use</SelectItem>
              <SelectItem value="5">5 uses</SelectItem>
              <SelectItem value="10">10 uses</SelectItem>
              <SelectItem value="25">25 uses</SelectItem>
              <SelectItem value="50">50 uses</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="flex gap-3 justify-end pt-1">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={handleGenerate} disabled={busy}>
          {busy ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Generating...</> : <><Link2 className="w-4 h-4 mr-2" />Generate Link</>}
        </Button>
      </div>
    </div>
  )
}

function InviteModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="bg-card border-foreground/10 sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Invite Team Member</DialogTitle>
          <DialogDescription>Send an email invite or generate a shareable link.</DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="email" className="pt-2">
          <TabsList className="w-full bg-foreground/5 border border-foreground/10">
            <TabsTrigger value="email"  className="flex-1 gap-2"><Mail   className="w-3.5 h-3.5" />Invite by Email</TabsTrigger>
            <TabsTrigger value="link"   className="flex-1 gap-2"><Link2  className="w-3.5 h-3.5" />Generate Link</TabsTrigger>
          </TabsList>
          <TabsContent value="email" className="mt-4"><EmailInviteTab onClose={onClose} /></TabsContent>
          <TabsContent value="link"  className="mt-4"><LinkInviteTab  onClose={onClose} /></TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

// ── Change role modal ─────────────────────────────────────────────────

function ChangeRoleModal({
  member, open, onClose,
}: { member: OrgMember | null; open: boolean; onClose: () => void }) {
  const { changeMemberRoleAction } = useTeam()
  const [role, setRole] = useState<OrgRole>(member?.orgRole ?? 'editor')
  const [busy, setBusy] = useState(false)

  async function handleSave() {
    if (!member) return; setBusy(true)
    try {
      await changeMemberRoleAction(member, role)
      toast.success(`${member.name}'s role updated to ${role}`)
      onClose()
    } catch (err: any) { toast.error(err?.message ?? 'Failed to change role') }
    finally { setBusy(false) }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="bg-card border-foreground/10 sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Change Role</DialogTitle>
          <DialogDescription>{member?.name} · {member?.email}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 pt-2">
          <RoleSelect value={role} onChange={setRole} />
          <div className="flex gap-3 justify-end">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button onClick={handleSave} disabled={busy || role === member?.orgRole}>
              {busy ? 'Saving...' : 'Save'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Members table ─────────────────────────────────────────────────────

function MembersTable({
  members, currentUserId, canManage,
}: { members: OrgMember[]; currentUserId: string; canManage: boolean }) {
  const { disableMember, enableMember, removeMemberAction } = useTeam()
  const [roleTarget, setRoleTarget] = useState<OrgMember | null>(null)
  const [search, setSearch]         = useState('')

  const filtered = useMemo(
    () => members.filter((m) =>
      m.name.toLowerCase().includes(search.toLowerCase()) ||
      m.email.toLowerCase().includes(search.toLowerCase()),
    ),
    [members, search],
  )

  async function handleDisable(m: OrgMember) {
    try { await disableMember(m); toast.success(`${m.name} disabled`) }
    catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function handleEnable(m: OrgMember) {
    try { await enableMember(m); toast.success(`${m.name} reactivated`) }
    catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function handleRemove(m: OrgMember) {
    if (!confirm(`Remove ${m.name} from the team? This cannot be undone.`)) return
    try { await removeMemberAction(m); toast.success(`${m.name} removed`) }
    catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  return (
    <>
      <ChangeRoleModal member={roleTarget} open={!!roleTarget} onClose={() => setRoleTarget(null)} />
      <div className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search members..."
            value={search} onChange={(e) => setSearch(e.target.value)}
            className="pl-9 bg-background/50 border-foreground/20"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-foreground/10">
                {['Member', 'Role', 'Status', 'Joined', ...(canManage ? ['Actions'] : [])].map((h) => (
                  <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={canManage ? 5 : 4} className="text-center py-8 text-muted-foreground">No members found</td></tr>
              )}
              {filtered.map((m) => (
                <tr key={m.userId} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-semibold text-primary">
                        {m.name.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">{m.name}</p>
                        <p className="text-xs text-muted-foreground">{m.email}</p>
                      </div>
                      {m.userId === currentUserId && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground border border-foreground/10">you</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4"><RoleBadge role={m.orgRole} /></td>
                  <td className="py-3 px-4"><StatusBadge status={m.status} /></td>
                  <td className="py-3 px-4 text-sm text-muted-foreground">{fmtDate(m.joinedAt)}</td>
                  {canManage && (
                    <td className="py-3 px-4">
                      {m.userId !== currentUserId ? (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreHorizontal className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-44">
                            <DropdownMenuItem onClick={() => setRoleTarget(m)}>
                              <Edit2 className="w-4 h-4 mr-2" />Change Role
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            {m.status === 'active' ? (
                              <DropdownMenuItem onClick={() => handleDisable(m)} className="text-orange-400">
                                <UserX className="w-4 h-4 mr-2" />Disable
                              </DropdownMenuItem>
                            ) : (
                              <DropdownMenuItem onClick={() => handleEnable(m)} className="text-green-400">
                                <UserCheck className="w-4 h-4 mr-2" />Reactivate
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuItem onClick={() => handleRemove(m)} className="text-destructive">
                              <Trash2 className="w-4 h-4 mr-2" />Remove
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      ) : (
                        <span className="text-xs text-muted-foreground px-2">—</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

// ── Invitations table ─────────────────────────────────────────────────

function InvitationsTable({ invites, canManage }: { invites: OrgInvitation[]; canManage: boolean }) {
  const { resendEmailInvitation, revokeInvite, deleteInvite, regenerateLinkInvite, toggleLinkInvite } = useTeam()
  const [copying, setCopying] = useState<string | null>(null)

  async function handleResend(inv: OrgInvitation) {
    try { await resendEmailInvitation(inv); toast.success('Invitation resent') }
    catch (e: any) { toast.error(e?.message ?? 'Failed to resend') }
  }

  async function handleRevoke(inv: OrgInvitation) {
    const label = inv.inviteType === 'email' ? (inv.email ?? 'invite') : `${inv.orgRole} link`
    if (!confirm(`Revoke invitation for ${label}?`)) return
    try { await revokeInvite(inv); toast.success('Invitation revoked') }
    catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function handleDelete(inv: OrgInvitation) {
    const label = inv.inviteType === 'email' ? (inv.email ?? 'invite') : `${inv.orgRole} link`
    if (!confirm(`Delete invitation for ${label}? This cannot be undone.`)) return
    try { await deleteInvite(inv); toast.success('Invitation deleted') }
    catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function handleCopyLink(inv: OrgInvitation) {
    if (!inv.token) { toast.error('No link token found'); return }
    setCopying(inv.inviteId)
    const url = `${window.location.origin}/invite/${inv.token}`
    const ok  = await copyToClipboard(url)
    setCopying(null)
    ok ? toast.success('Link copied to clipboard') : toast.error('Failed to copy')
  }

  async function handleRegenerate(inv: OrgInvitation) {
    try {
      const url = await regenerateLinkInvite(inv)
      await copyToClipboard(url)
      toast.success('Link regenerated and copied to clipboard')
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function handleToggleLink(inv: OrgInvitation) {
    try {
      await toggleLinkInvite(inv, !inv.linkEnabled)
      toast.success(inv.linkEnabled ? 'Link disabled' : 'Link enabled')
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  const pending  = invites.filter((i) => i.status === 'pending')
  const resolved = invites.filter((i) => i.status !== 'pending')

  const TableHead = ({ cols }: { cols: string[] }) => (
    <thead>
      <tr className="border-b border-foreground/10">
        {cols.map((h) => (
          <th key={h} className="text-left py-2 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
        ))}
      </tr>
    </thead>
  )

  function TypeBadge({ inv }: { inv: OrgInvitation }) {
    return inv.inviteType === 'link'
      ? <span className="inline-flex items-center gap-1 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded"><Link2 className="w-3 h-3" />Link</span>
      : <span className="inline-flex items-center gap-1 text-xs text-muted-foreground bg-foreground/8 border border-foreground/15 px-1.5 py-0.5 rounded"><Mail className="w-3 h-3" />Email</span>
  }

  function UsageCell({ inv }: { inv: OrgInvitation }) {
    if (inv.inviteType === 'email') return <span className="text-muted-foreground text-sm">—</span>
    const max = inv.maxUses
    return (
      <span className="text-sm text-foreground">
        {inv.usedCount}<span className="text-muted-foreground">/{max === null ? '∞' : max}</span>
      </span>
    )
  }

  const pendingCols = ['Recipient / Role', 'Type', 'Uses', 'Invited By', 'Expires', ...(canManage ? ['Actions'] : [])]
  const histCols    = ['Recipient / Role', 'Type', 'Status', 'Date', ...(canManage ? ['Actions'] : [])]

  return (
    <div className="space-y-6">
      {/* Pending */}
      <div>
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Clock className="w-4 h-4 text-yellow-400" />
          Pending ({pending.length})
        </h3>
        {pending.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4">No pending invitations</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <TableHead cols={pendingCols} />
              <tbody>
                {pending.map((inv) => (
                  <tr key={inv.inviteId} className="border-b border-foreground/5 hover:bg-foreground/5">
                    <td className="py-3 px-4">
                      {inv.inviteType === 'email'
                        ? <span className="text-sm text-foreground">{inv.email}</span>
                        : <div className="flex items-center gap-2"><RoleBadge role={inv.orgRole} />{!inv.linkEnabled && <span className="text-[10px] text-muted-foreground border border-foreground/20 px-1.5 py-0.5 rounded">disabled</span>}</div>
                      }
                    </td>
                    <td className="py-3 px-4"><TypeBadge inv={inv} /></td>
                    <td className="py-3 px-4"><UsageCell inv={inv} /></td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{inv.inviterName}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{fmtDateTime(inv.expiresAt)}</td>
                    {canManage && (
                      <td className="py-3 px-4">
                        <div className="flex gap-1">
                          {inv.inviteType === 'email' ? (
                            <>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Resend email" onClick={() => handleResend(inv)}>
                                <RefreshCw className="w-3.5 h-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" title="Revoke" onClick={() => handleRevoke(inv)}>
                                <UserX className="w-3.5 h-3.5" />
                              </Button>
                            </>
                          ) : (
                            <>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Copy link" onClick={() => handleCopyLink(inv)}>
                                {copying === inv.inviteId ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Copy className="w-3.5 h-3.5" />}
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title="Regenerate link" onClick={() => handleRegenerate(inv)}>
                                <RefreshCw className="w-3.5 h-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8" title={inv.linkEnabled ? 'Disable link' : 'Enable link'} onClick={() => handleToggleLink(inv)}>
                                {inv.linkEnabled
                                  ? <ToggleRight className="w-3.5 h-3.5 text-green-400" />
                                  : <ToggleLeft  className="w-3.5 h-3.5 text-muted-foreground" />
                                }
                              </Button>
                              <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" title="Revoke" onClick={() => handleRevoke(inv)}>
                                <UserX className="w-3.5 h-3.5" />
                              </Button>
                            </>
                          )}
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-destructive" title="Delete" onClick={() => handleDelete(inv)}>
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* History */}
      {resolved.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-foreground mb-3">History ({resolved.length})</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <TableHead cols={histCols} />
              <tbody>
                {resolved.map((inv) => (
                  <tr key={inv.inviteId} className="border-b border-foreground/5 hover:bg-foreground/5">
                    <td className="py-3 px-4 text-sm text-foreground">
                      {inv.inviteType === 'email' ? inv.email : <RoleBadge role={inv.orgRole} />}
                    </td>
                    <td className="py-3 px-4"><TypeBadge inv={inv} /></td>
                    <td className="py-3 px-4"><StatusBadge status={inv.status} /></td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{fmtDate(inv.acceptedAt ?? inv.createdAt)}</td>
                    {canManage && (
                      <td className="py-3 px-4">
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-destructive" title="Delete" onClick={() => handleDelete(inv)}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Audit log ─────────────────────────────────────────────────────────

function AuditLogTable({ logs }: { logs: AuditLog[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-foreground/10">
            {['Actor', 'Action', 'Target', 'Time'].map((h) => (
              <th key={h} className="text-left py-2 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 && (
            <tr><td colSpan={4} className="text-center py-8 text-muted-foreground">No audit logs yet</td></tr>
          )}
          {logs.map((log) => (
            <tr key={log.logId} className="border-b border-foreground/5 hover:bg-foreground/5">
              <td className="py-3 px-4 text-sm font-medium text-foreground">{log.actorName}</td>
              <td className="py-3 px-4 text-sm text-foreground">{log.action}</td>
              <td className="py-3 px-4 text-sm text-muted-foreground">{log.targetEmail ?? log.targetId ?? '—'}</td>
              <td className="py-3 px-4 text-sm text-muted-foreground">{fmtDateTime(log.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function TeamPage() {
  const router       = useRouter()
  const { user }     = useAuth()
  const { org, members, invitations, auditLogs, loadingTeam } = useTeam()
  const [inviteOpen, setInviteOpen] = useState(false)

  const orgRole   = user?.orgRole ?? 'viewer'
  const canManage = hasPermission(orgRole, 'inviteMembers')
  const canAudit  = hasPermission(orgRole, 'viewAuditLogs')

  if (!loadingTeam && !hasPermission(orgRole, 'viewTeam')) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <AlertCircle className="w-12 h-12 text-destructive" />
        <h2 className="text-xl font-semibold text-foreground">Access Denied</h2>
        <p className="text-muted-foreground">You don't have permission to access Team Management.</p>
        <Button onClick={() => router.push('/app/dashboard')}>Go to Dashboard</Button>
      </div>
    )
  }

  if (loadingTeam) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-8 w-8 border border-primary border-t-transparent" />
      </div>
    )
  }

  const activeMembers  = members.filter((m) => m.status === 'active').length
  const pendingInvites = invitations.filter((i) => i.status === 'pending').length
  const adminCount     = members.filter((m) => m.orgRole === 'admin').length

  return (
    <div className="p-8 space-y-8">
      <InviteModal open={inviteOpen} onClose={() => setInviteOpen(false)} />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Team Management</h1>
          <p className="text-muted-foreground mt-1">
            {org?.name ?? 'Your Workspace'} · Manage members and role-based access
          </p>
        </div>
        {canManage && (
          <Button
            onClick={() => setInviteOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6"
          >
            <Plus className="w-4 h-4 mr-2" />
            Invite Member
          </Button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Members',   value: members.length, icon: Users,     color: 'text-foreground' },
          { label: 'Active',          value: activeMembers,  icon: UserCheck, color: 'text-green-400'  },
          { label: 'Pending Invites', value: pendingInvites, icon: Clock,     color: 'text-yellow-400' },
          { label: 'Admins',          value: adminCount,     icon: Shield,    color: 'text-primary'    },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="bg-card border-foreground/10">
            <CardHeader className="pb-2 flex-row items-center justify-between space-y-0">
              <CardTitle className="text-sm text-muted-foreground">{label}</CardTitle>
              <Icon className={`w-4 h-4 ${color}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="members">
        <TabsList className="bg-foreground/5 border border-foreground/10">
          <TabsTrigger value="members">Members ({members.length})</TabsTrigger>
          <TabsTrigger value="invitations">Invitations ({pendingInvites})</TabsTrigger>
          {canAudit && <TabsTrigger value="audit">Audit Log</TabsTrigger>}
          <TabsTrigger value="roles">Roles & Permissions</TabsTrigger>
        </TabsList>

        <TabsContent value="members" className="mt-6">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <CardTitle>Team Members</CardTitle>
              <CardDescription>All members with access to this workspace</CardDescription>
            </CardHeader>
            <CardContent>
              <MembersTable members={members} currentUserId={user?.uid ?? ''} canManage={canManage} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="invitations" className="mt-6">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <CardTitle>Invitations</CardTitle>
              <CardDescription>Email invitations and shareable links</CardDescription>
            </CardHeader>
            <CardContent>
              <InvitationsTable invites={invitations} canManage={canManage} />
            </CardContent>
          </Card>
        </TabsContent>

        {canAudit && (
          <TabsContent value="audit" className="mt-6">
            <Card className="bg-card border-foreground/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-primary" />
                  Audit Log
                </CardTitle>
                <CardDescription>Team management activity history (last 100 entries)</CardDescription>
              </CardHeader>
              <CardContent>
                <AuditLogTable logs={auditLogs} />
              </CardContent>
            </Card>
          </TabsContent>
        )}

        <TabsContent value="roles" className="mt-6">
          <div className="grid gap-4 md:grid-cols-3">
            {[
              {
                role: 'admin'  as OrgRole, icon: Shield, title: 'Admin',
                desc: 'Full system access. Can manage team, settings, scans, findings, and reports.',
                perms: ['All security modules + Cloud', 'Team management & invitations', 'Settings & SLA configuration', 'Start, stop & delete scans', 'Assign, comment & resolve findings', 'Generate & export reports', 'View audit logs'],
              },
              {
                role: 'editor' as OrgRole, icon: Edit2,  title: 'Editor',
                desc: 'Security analyst role. Can operate scans and manage findings.',
                perms: ['Dashboard, Web, Network, SAST modules', 'Vulnerability management', 'Reports & AI Analysis', 'Start and stop scans', 'Assign, comment & change status', 'Generate & export reports', 'No team or settings access'],
              },
              {
                role: 'viewer' as OrgRole, icon: Eye,    title: 'Viewer',
                desc: 'Read-only access. Cannot modify any data.',
                perms: ['Dashboard (read-only)', 'Vulnerability management (view)', 'Reports (view)', 'No scanning capabilities', 'No finding modifications', 'No team or settings access', 'No exports or report generation'],
              },
            ].map(({ role, icon: Icon, title, desc, perms }) => (
              <Card key={role} className="bg-card border-foreground/10">
                <CardHeader>
                  <div className="flex items-center gap-3 mb-2">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      <Icon className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{title}</CardTitle>
                      <div className="mt-1"><RoleBadge role={role} /></div>
                    </div>
                  </div>
                  <CardDescription>{desc}</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-1.5">
                    {perms.map((p) => (
                      <li key={p} className="flex items-start gap-2 text-xs text-muted-foreground">
                        <span className="text-primary mt-0.5">✓</span>{p}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
