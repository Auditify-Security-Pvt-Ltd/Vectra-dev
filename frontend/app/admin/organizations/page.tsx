'use client'

import { useState } from 'react'
import { Search, RefreshCw, Eye, Gauge, ChevronLeft, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { StatCardsSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import {
  getOverview, getQuotaConfig, listOrganizations, updateOrganization, type AdminOrganization,
} from '@/lib/api-admin'
import { AdminError, fmtTime } from '@/components/admin/admin-shared'
import {
  EditOrganizationDialog, OrganizationDetailDialog, OrganizationQuotaDialog,
  ORG_STATUS_CLS, allowanceLabel, countLabel, remainingClass,
} from '@/components/admin/organization-dialogs'

const PAGE_SIZE = 25

/**
 * Organizations — the plan and scan-quota boundary.
 * Every member of an organization shares its allowance across all scan types.
 */
export default function AdminOrganizationsPage() {
  const [search, setSearch]   = useState('')
  const [query, setQuery]     = useState('')
  const [plan, setPlan]       = useState('all')
  const [status, setStatus]   = useState('all')
  const [offset, setOffset]   = useState(0)

  const [viewing, setViewing]   = useState<string | null>(null)
  const [editing, setEditing]   = useState<AdminOrganization | null>(null)
  const [quotaFor, setQuotaFor] = useState<AdminOrganization | null>(null)
  const [statusBusy, setStatusBusy] = useState<string | null>(null)
  const [reloadKey, setReloadKey]   = useState(0)

  const list = useAdminData(
    () => listOrganizations({ search: query, plan, status, limit: PAGE_SIZE, offset }),
    { deps: [query, plan, status, offset] },
  )
  const overview = useAdminData(getOverview)
  const config   = useAdminData(getQuotaConfig)
  const showSkeleton = useDelayedLoading(list.loading && !list.data)

  function refreshAll() {
    list.refresh()
    overview.refresh()
    setReloadKey((k) => k + 1)
  }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault()
    setOffset(0)
    setQuery(search.trim())
  }

  async function toggleStatus(org: AdminOrganization) {
    const next = org.status === 'active' ? 'disabled' : 'active'
    if (next === 'disabled' && !window.confirm(
      `Disable ${org.name ?? org.orgId}?\n\nMembers will not be able to start new scans. ` +
      'Existing scans, findings and reports are kept.',
    )) return

    setStatusBusy(org.orgId)
    try {
      await updateOrganization(org.orgId, { status: next })
      toast.success(next === 'active' ? 'Organization enabled' : 'Organization disabled')
      refreshAll()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setStatusBusy(null)
    }
  }

  const data  = list.data
  const total = data?.total ?? 0
  const page  = Math.floor(offset / PAGE_SIZE) + 1
  const pages = Math.max(Math.ceil(total / PAGE_SIZE), 1)
  const plans = data?.plans ?? (config.data ? Object.keys(config.data.planAllowances).sort() : [])
  const o = overview.data?.organizations

  const selectCls = 'h-9 px-3 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm capitalize'

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Organizations</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Plans and shared scan allowances. Every member draws from their organization&apos;s quota.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refreshAll}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {(list.error || overview.error) && <AdminError message={(list.error || overview.error)!} />}

      {overview.loading && !o ? (
        <StatCardsSkeleton count={4} />
      ) : o ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Organizations',    value: o.total,                  cls: 'text-foreground' },
            { label: 'Active',           value: o.total - o.disabled,     cls: 'text-green-500' },
            { label: 'Free plan',        value: o.free,                   cls: 'text-violet-400' },
            { label: 'Near scan limit',  value: o.nearLimit,              cls: 'text-orange-400' },
          ].map((c) => (
            <Card key={c.label} className="bg-card border-foreground/10">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">{c.label}</p>
                <p className={`text-2xl font-bold mt-1 ${c.cls}`}>{c.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

      <div className="flex items-center gap-2 flex-wrap">
        <form onSubmit={submitSearch} className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search name, website, owner or id…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 h-9 w-72 bg-foreground/5 border-foreground/20 text-sm"
          />
        </form>
        <select value={plan} onChange={(e) => { setOffset(0); setPlan(e.target.value) }} className={selectCls} aria-label="Plan">
          <option value="all" className="bg-card">All plans</option>
          {plans.map((p) => <option key={p} value={p} className="bg-card">{p}</option>)}
        </select>
        <select value={status} onChange={(e) => { setOffset(0); setStatus(e.target.value) }} className={selectCls} aria-label="Status">
          <option value="all" className="bg-card">All statuses</option>
          <option value="active" className="bg-card">Active</option>
          <option value="disabled" className="bg-card">Disabled</option>
        </select>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={6} cols={9} /></div>
          ) : list.loading && !data ? null : !data?.organizations.length ? (
            <div className="text-center py-16">
              <p className="text-sm text-muted-foreground">
                {query || plan !== 'all' || status !== 'all' ? 'No organizations match these filters.' : 'No organizations yet.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Organization', 'Plan', 'Users', 'Assets', 'Scans', 'Findings', 'Allowance', 'Used', 'Remaining', 'Status', 'Created', ''].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.organizations.map((org) => {
                    const q = org.quota
                    return (
                      <tr key={org.orgId} className="border-b border-foreground/5 hover:bg-foreground/3">
                        <td className="py-3 px-4">
                          <button className="text-left" onClick={() => setViewing(org.orgId)}>
                            <p className="text-sm font-medium text-foreground hover:text-primary">{org.name ?? '—'}</p>
                            <p className="text-[11px] text-muted-foreground font-mono">{org.website ?? org.ownerEmail ?? org.orgId}</p>
                          </button>
                        </td>
                        <td className="py-3 px-4 text-xs capitalize text-foreground">{q.plan}</td>
                        <td className="py-3 px-4 text-xs font-mono">{countLabel(org.counts?.users)}</td>
                        <td className="py-3 px-4 text-xs font-mono">{countLabel(org.counts?.assets)}</td>
                        <td className="py-3 px-4 text-xs font-mono">{countLabel(org.counts?.scans)}</td>
                        <td className="py-3 px-4 text-xs font-mono">{countLabel(org.counts?.findings)}</td>
                        <td className="py-3 px-4 text-xs font-mono text-foreground whitespace-nowrap">
                          {allowanceLabel(q.effectiveAllowance)}
                          {q.bonusScans > 0 && !q.unlimited && (
                            <span className="text-[10px] text-violet-400 ml-1">({q.planAllowance}+{q.bonusScans})</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-xs font-mono text-muted-foreground">{q.used}</td>
                        <td className="py-3 px-4 text-xs font-mono">
                          <span className={remainingClass(q.remaining, q.unlimited)}>{allowanceLabel(q.remaining)}</span>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${ORG_STATUS_CLS[org.status]}`}>
                            {org.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">{fmtTime(org.createdAt)}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1 justify-end">
                            <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
                              onClick={() => setViewing(org.orgId)}>
                              <Eye className="w-3 h-3" /> View
                            </Button>
                            <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
                              onClick={() => setQuotaFor(org)}>
                              <Gauge className="w-3 h-3" /> Quota
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset === 0}
              onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
              <ChevronLeft className="w-3.5 h-3.5" /> Previous
            </Button>
            <span className="text-xs text-muted-foreground self-center">Page {page} of {pages}</span>
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}>
              Next <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}

      <OrganizationDetailDialog
        orgId={viewing}
        onClose={() => setViewing(null)}
        onEdit={setEditing}
        onQuota={setQuotaFor}
        onToggleStatus={toggleStatus}
        statusBusy={statusBusy !== null && statusBusy === viewing}
        reloadKey={reloadKey}
      />
      <EditOrganizationDialog org={editing} onClose={() => setEditing(null)} onSaved={refreshAll} />
      <OrganizationQuotaDialog
        org={quotaFor}
        plans={plans}
        planAllowances={config.data?.planAllowances ?? null}
        onClose={() => setQuotaFor(null)}
        onSaved={refreshAll}
      />
    </div>
  )
}
