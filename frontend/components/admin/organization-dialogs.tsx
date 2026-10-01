'use client'

/**
 * Organization administration dialogs: detail view, profile/status editor and
 * plan/quota editor. All writes go through the platform-admin API, which
 * re-validates everything server-side.
 */

import { useEffect, useState } from 'react'
import { ExternalLink, Pencil, Gauge, ShieldOff, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { CardSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import {
  getOrganization, updateOrganization,
  type AdminOrganization, type AdminOrganizationDetail,
} from '@/lib/api-admin'
import { cleanOrgName, cleanPhone, cleanWebsite } from '@/lib/org-validation'
import { AdminError, SCAN_TYPE_LABEL, statusClasses, fmtTime } from '@/components/admin/admin-shared'

export const ORG_STATUS_CLS: Record<string, string> = {
  active:   'bg-green-500/10 text-green-500 border-green-500/20',
  disabled: 'bg-red-500/10 text-red-500 border-red-500/20',
}

export function allowanceLabel(n: number): string {
  return n < 0 ? '∞' : String(n)
}

export function countLabel(n: number | null | undefined): string {
  return n == null ? '—' : String(n)
}

export function remainingClass(remaining: number, unlimited: boolean): string {
  if (unlimited) return 'text-green-500'
  if (remaining === 0) return 'text-red-500'
  if (remaining <= 1) return 'text-orange-400'
  return 'text-foreground'
}

function Row({ k, v, strong }: { k: string; v: React.ReactNode; strong?: boolean }) {
  return (
    <div className={`flex justify-between gap-4 text-xs py-1 ${strong ? 'font-semibold text-foreground' : 'text-muted-foreground'}`}>
      <span>{k}</span><span className="font-mono text-right break-all text-foreground">{v}</span>
    </div>
  )
}

function Section({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-foreground/10 p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  )
}

// ── Detail ────────────────────────────────────────────────────────────

export function OrganizationDetailDialog({
  orgId, onClose, onEdit, onQuota, onToggleStatus, statusBusy, reloadKey,
}: {
  orgId: string | null
  onClose: () => void
  onEdit: (org: AdminOrganization) => void
  onQuota: (org: AdminOrganization) => void
  onToggleStatus: (org: AdminOrganization) => void
  statusBusy: boolean
  reloadKey: number
}) {
  return (
    <Dialog open={orgId !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto bg-card border-foreground/10">
        {orgId && (
          <DetailBody
            orgId={orgId} onEdit={onEdit} onQuota={onQuota}
            onToggleStatus={onToggleStatus} statusBusy={statusBusy} reloadKey={reloadKey}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function DetailBody({
  orgId, onEdit, onQuota, onToggleStatus, statusBusy, reloadKey,
}: {
  orgId: string
  onEdit: (org: AdminOrganization) => void
  onQuota: (org: AdminOrganization) => void
  onToggleStatus: (org: AdminOrganization) => void
  statusBusy: boolean
  reloadKey: number
}) {
  const { data: org, loading, error } = useAdminData<AdminOrganizationDetail>(
    () => getOrganization(orgId), { deps: [orgId, reloadKey] },
  )

  if (error) return <AdminError message={error} />
  if (loading && !org) {
    return (
      <div className="space-y-4">
        <DialogHeader><DialogTitle className="text-base">Loading organization…</DialogTitle></DialogHeader>
        <CardSkeleton lines={4} />
        <TableSkeleton rows={3} cols={4} />
      </div>
    )
  }
  if (!org) return null

  const q = org.quota
  return (
    <div className="space-y-4">
      <DialogHeader>
        <div className="flex items-center gap-2 flex-wrap">
          <DialogTitle className="text-lg">{org.name ?? org.orgId}</DialogTitle>
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${ORG_STATUS_CLS[org.status]}`}>
            {org.status}
          </span>
        </div>
        <DialogDescription className="text-xs font-mono">{org.orgId}</DialogDescription>
      </DialogHeader>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" className="border-foreground/20 gap-1.5" onClick={() => onEdit(org)}>
          <Pencil className="w-3.5 h-3.5" /> Edit organization
        </Button>
        <Button size="sm" variant="outline" className="border-foreground/20 gap-1.5" onClick={() => onQuota(org)}>
          <Gauge className="w-3.5 h-3.5" /> Plan &amp; scan allowance
        </Button>
        <Button
          size="sm" variant="outline" loading={statusBusy}
          className={`border-foreground/20 gap-1.5 ${org.status === 'active' ? 'hover:text-destructive' : 'hover:text-green-500'}`}
          onClick={() => onToggleStatus(org)}
        >
          {org.status === 'active'
            ? <><ShieldOff className="w-3.5 h-3.5" /> Disable</>
            : <><ShieldCheck className="w-3.5 h-3.5" /> Enable</>}
        </Button>
      </div>

      <div className="grid md:grid-cols-2 gap-3">
        <Section title="Organization">
          <Row k="Name" v={org.name ?? '—'} />
          <Row k="Website" v={org.website ? (
            <a href={org.website} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">
              {org.website} <ExternalLink className="w-3 h-3" />
            </a>
          ) : '—'} />
          <Row k="Phone" v={org.phone ?? '—'} />
          <Row k="Owner" v={org.ownerEmail ?? org.ownerName ?? org.ownerId ?? '—'} />
          <Row k="Created" v={fmtTime(org.createdAt)} />
        </Section>

        <Section title="Plan & usage">
          <Row k="Plan" v={<span className="capitalize">{q.plan}</span>} />
          <Row k="Plan default allowance" v={allowanceLabel(q.planAllowance)} />
          <Row k="Bonus scans" v={q.bonusScans} />
          <Row k="Effective allowance" v={allowanceLabel(q.effectiveAllowance)} strong />
          <Row k="Used" v={q.used} />
          <Row k="Remaining" v={<span className={remainingClass(q.remaining, q.unlimited)}>{allowanceLabel(q.remaining)}</span>} strong />
        </Section>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          ['Members', org.counts.users], ['Assets', org.counts.assets],
          ['Scans', org.counts.scans], ['Findings', org.counts.findings],
          ['Running', org.activity.running], ['Completed', org.activity.completed],
          ['Failed', org.activity.failed],
        ].map(([label, value]) => (
          <div key={label as string} className="rounded-lg border border-foreground/10 p-3">
            <p className="text-[11px] text-muted-foreground">{label}</p>
            <p className="text-lg font-bold text-foreground">{countLabel(value as number | null)}</p>
          </div>
        ))}
      </div>

      <Section title={`Members (${org.members.length})`}>
        {org.members.length === 0 ? (
          <p className="text-xs text-muted-foreground">No members.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-muted-foreground border-b border-foreground/10">
                  {['Member', 'Org role', 'Platform role', 'Status'].map((h) => (
                    <th key={h} className="text-left py-2 pr-3 font-semibold">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {org.members.map((m) => (
                  <tr key={m.uid} className="border-b border-foreground/5 last:border-0">
                    <td className="py-2 pr-3">
                      <p className="text-foreground">{m.name ?? '—'}</p>
                      <p className="text-[11px] text-muted-foreground font-mono">{m.email ?? m.uid}</p>
                    </td>
                    <td className="py-2 pr-3 capitalize">{m.orgRole ?? '—'}{m.uid === org.ownerId && <span className="ml-1 text-primary">(owner)</span>}</td>
                    <td className="py-2 pr-3 capitalize text-muted-foreground">{m.platformRole?.replace(/_/g, ' ') ?? '—'}</td>
                    <td className="py-2 pr-3 capitalize">
                      {m.memberStatus}
                      {m.accountStatus !== 'active' && <span className="text-red-400"> · account {m.accountStatus}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Recent scans">
        {org.activity.recent.length === 0 && org.activity.live.length === 0 ? (
          <p className="text-xs text-muted-foreground">No scans recorded.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-muted-foreground border-b border-foreground/10">
                  {['Type', 'Target', 'Status', 'Findings', 'Started'].map((h) => (
                    <th key={h} className="text-left py-2 pr-3 font-semibold">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {/* Live tasks first (in-flight on this backend), then persisted history. */}
                {[
                  ...org.activity.live.map((t) => ({ ...t, key: `live-${t.scanId}` })),
                  ...org.activity.recent
                    .filter((r) => !org.activity.live.some((t) => t.scanId === r.scanId))
                    .map((r) => ({ ...r, key: r.scanId })),
                ].map((s) => (
                  <tr key={s.key} className="border-b border-foreground/5 last:border-0">
                    <td className="py-2 pr-3">{SCAN_TYPE_LABEL[s.scanType] ?? s.scanType}</td>
                    <td className="py-2 pr-3 font-mono max-w-[16rem] truncate">{s.target ?? '—'}</td>
                    <td className="py-2 pr-3">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${statusClasses(s.status)}`}>
                        {(s.status ?? 'unknown').replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-2 pr-3">{s.findings}</td>
                    <td className="py-2 pr-3 text-muted-foreground">{fmtTime(s.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  )
}

// ── Edit profile ──────────────────────────────────────────────────────

export function EditOrganizationDialog({
  org, onClose, onSaved,
}: { org: AdminOrganization | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName]       = useState('')
  const [website, setWebsite] = useState('')
  const [phone, setPhone]     = useState('')
  const [errors, setErrors]   = useState<Record<string, string>>({})
  const [saving, setSaving]   = useState(false)

  useEffect(() => {
    if (!org) return
    setName(org.name ?? '')
    setWebsite(org.website ?? '')
    setPhone(org.phone ?? '')
    setErrors({})
  }, [org])

  async function save() {
    if (!org) return
    const changes: Record<string, string> = {}
    const errs: Record<string, string> = {}
    const check = (key: string, value: string, original: string | null, clean: (v: string) => string, optional: boolean) => {
      if (value.trim() === (original ?? '')) return
      if (optional && !value.trim()) { errs[key] = 'Cannot be cleared once set.'; return }
      try { changes[key] = clean(value) } catch (e) { errs[key] = (e as Error).message }
    }
    check('name', name, org.name, cleanOrgName, false)
    check('website', website, org.website, cleanWebsite, true)
    check('phone', phone, org.phone, cleanPhone, true)
    setErrors(errs)
    if (Object.keys(errs).length) return
    if (!Object.keys(changes).length) { onClose(); return }

    setSaving(true)
    try {
      await updateOrganization(org.orgId, changes)
      toast.success('Organization updated')
      onSaved()
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  const field = (label: string, key: string, value: string, set: (v: string) => void, props: React.ComponentProps<typeof Input> = {}) => (
    <div className="space-y-1.5">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Input value={value} onChange={(e) => set(e.target.value)} className="h-9 text-sm" {...props} />
      {errors[key] && <p className="text-[11px] text-red-400">{errors[key]}</p>}
    </div>
  )

  return (
    <Dialog open={org !== null} onOpenChange={(o) => !o && !saving && onClose()}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base">Edit organization</DialogTitle>
          <DialogDescription className="text-xs font-mono">{org?.orgId}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 pt-1">
          {field('Organization name', 'name', name, setName, { maxLength: 100 })}
          {field('Website URL', 'website', website, setWebsite, { type: 'url', placeholder: 'https://example.com', maxLength: 200 })}
          {field('Contact phone', 'phone', phone, setPhone, { type: 'tel', placeholder: '+1 555 123 4567', maxLength: 20 })}
          <p className="text-[11px] text-muted-foreground/70">
            The organization id, owner and recorded scan usage cannot be changed.
          </p>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button onClick={save} loading={saving} loadingText="Saving…">Save changes</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Plan & quota ──────────────────────────────────────────────────────

export function OrganizationQuotaDialog({
  org, plans, planAllowances, onClose, onSaved,
}: {
  org: AdminOrganization | null
  plans: string[]
  planAllowances: Record<string, number> | null
  onClose: () => void
  onSaved: () => void
}) {
  const [plan, setPlan]     = useState('free')
  const [bonus, setBonus]   = useState('0')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!org) return
    setPlan(org.quota.plan)
    setBonus(String(org.quota.bonusScans))
  }, [org])

  if (!org) return null

  // Preview mirrors the backend formula: plan default + bonus − used.
  const planAllowance = planAllowances?.[plan] ?? (plan === org.quota.plan ? org.quota.planAllowance : 0)
  const bonusNum   = Number.parseInt(bonus, 10)
  const bonusValid = /^\d+$/.test(bonus.trim()) && Number.isFinite(bonusNum)
  const effective  = planAllowance < 0 ? -1 : planAllowance + (bonusValid ? bonusNum : 0)
  const remaining  = effective < 0 ? -1 : Math.max(effective - org.quota.used, 0)

  // Convenience: type the total allowance you want; bonus is derived from it.
  function setEffective(raw: string) {
    const target = Number.parseInt(raw, 10)
    if (!Number.isFinite(target) || planAllowance < 0) return
    setBonus(String(Math.max(target - planAllowance, 0)))
  }

  async function save() {
    if (!org) return
    if (!bonusValid) { toast.error('Bonus scans must be a whole number, 0 or more'); return }
    const changes: { plan?: string; bonusScans?: number } = {}
    if (plan !== org.quota.plan) changes.plan = plan
    if (bonusNum !== org.quota.bonusScans) changes.bonusScans = bonusNum
    if (!Object.keys(changes).length) { onClose(); return }

    setSaving(true)
    try {
      await updateOrganization(org.orgId, changes)
      toast.success('Organization plan and allowance updated')
      onSaved()
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !saving && onClose()}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base">Plan &amp; scan allowance</DialogTitle>
          <DialogDescription className="text-xs">
            {org.name ?? org.orgId} — shared by all members across every scan type.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Plan</Label>
            <select
              value={plan}
              onChange={(e) => setPlan(e.target.value)}
              className="w-full h-9 rounded-lg bg-foreground/5 border border-foreground/15 px-3 text-sm text-foreground capitalize"
            >
              {plans.map((p) => (
                <option key={p} value={p} className="bg-card capitalize">
                  {p}{planAllowances ? ` (${allowanceLabel(planAllowances[p] ?? 0)} scans)` : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Bonus scans</Label>
              <Input type="number" min={0} value={bonus} onChange={(e) => setBonus(e.target.value)} className="h-9 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Or set total allowance</Label>
              <Input
                type="number" min={0} disabled={planAllowance < 0}
                value={effective < 0 ? '' : String(effective)}
                placeholder={planAllowance < 0 ? 'Unlimited' : undefined}
                onChange={(e) => setEffective(e.target.value)}
                className="h-9 text-sm"
              />
            </div>
          </div>
          {!bonusValid && <p className="text-[11px] text-red-400">Bonus must be a whole number, 0 or more.</p>}

          <div className="rounded-lg border border-foreground/10 bg-foreground/3 p-3">
            <Row k="Plan default" v={allowanceLabel(planAllowance)} />
            <Row k="Bonus" v={bonusValid ? bonusNum : '—'} />
            <Row k="Effective allowance" v={allowanceLabel(effective)} />
            <Row k="Used (unchanged)" v={org.quota.used} />
            <div className="border-t border-foreground/10 mt-1.5 pt-1.5">
              <Row k="Remaining" v={<span className={remainingClass(remaining, effective < 0)}>{allowanceLabel(remaining)}</span>} strong />
            </div>
          </div>
          <p className="text-[11px] text-muted-foreground/70">
            Changing the plan or allowance never resets the organization&apos;s recorded usage.
          </p>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button onClick={save} loading={saving} loadingText="Saving…" disabled={!bonusValid}>Save changes</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
