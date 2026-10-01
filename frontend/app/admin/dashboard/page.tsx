'use client'

import Link from 'next/link'
import {
  Users, Building2, Zap, CheckCircle2, XCircle, Clock,
  ShieldAlert, AlertTriangle, ArrowRight, Loader2, RefreshCw,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { StatCardsSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { getOverview, listTasks, type AdminOverview, type AdminTask } from '@/lib/api-admin'
import {
  AdminError, SCAN_TYPE_LABEL, statusClasses, fmtTime, fmtDuration,
} from '@/components/admin/admin-shared'

// ── Page ──────────────────────────────────────────────────────────────

export default function AdminOverviewPage() {
  const overview = useAdminData<AdminOverview>(getOverview)
  const tasks    = useAdminData<{ total: number; tasks: AdminTask[] }>(
    () => listTasks({ limit: 8 }),
    { pollMs: 15_000 },
  )

  const o = overview.data

  const cards = o ? [
    { label: 'Total Users',     value: o.users.total,          icon: Users,       cls: 'text-foreground', href: '/admin/users' },
    { label: 'Active Users',    value: o.users.active,         icon: CheckCircle2, cls: 'text-green-500',  href: '/admin/users' },
    { label: 'Inactive Users',  value: o.users.inactive,       icon: XCircle,     cls: 'text-muted-foreground', href: '/admin/users' },
    { label: 'Organizations',   value: o.organizations.total,  icon: Building2,   cls: 'text-blue-400',   href: '/admin/organizations' },
    { label: 'Running Scans',   value: o.scans.running,        icon: Loader2,     cls: 'text-blue-400',   href: '/admin/scans' },
    { label: 'Queued Scans',    value: o.scans.queued,         icon: Clock,       cls: 'text-yellow-500', href: '/admin/scans' },
    { label: 'Completed Scans', value: o.scans.completed,      icon: CheckCircle2, cls: 'text-green-500', href: '/admin/scans' },
    { label: 'Failed Scans',    value: o.scans.failed,         icon: XCircle,     cls: 'text-red-500',    href: '/admin/scans' },
    { label: 'Free Plan Orgs',  value: o.organizations.free,      icon: Building2,   cls: 'text-violet-400', href: '/admin/organizations' },
    { label: 'Orgs Near Limit', value: o.organizations.nearLimit, icon: ShieldAlert, cls: 'text-orange-400', href: '/admin/organizations' },
  ] : []

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Platform Overview</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Live platform activity across all organizations.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="border-foreground/20 gap-2"
          onClick={() => { overview.refresh(); tasks.refresh() }}
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {overview.error && <AdminError message={overview.error} />}

      {overview.loading && !o ? (
        <StatCardsSkeleton count={8} />
      ) : o ? (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {cards.map(({ label, value, icon: Icon, cls, href }) => (
            <Link key={label} href={href}>
              <Card className="bg-card border-foreground/10 hover:border-foreground/25 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-1.5">
                    <Icon className={`w-3.5 h-3.5 ${cls}`} />
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                  <p className={`text-2xl font-bold ${cls}`}>{value}</p>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      ) : null}

      {o && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Scan Allowances</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {Object.entries(o.quota.planAllowances).map(([plan, allowance]) => (
                <span
                  key={plan}
                  className="text-xs px-2.5 py-1 rounded-lg border border-foreground/10 bg-foreground/5"
                >
                  <span className="capitalize text-foreground font-medium">{plan}</span>
                  <span className="text-muted-foreground">
                    {' · '}{allowance < 0 ? 'Unlimited' : `${allowance} scans`}
                  </span>
                </span>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground/70">{o.quota.consumptionRule}</p>
          </CardContent>
        </Card>
      )}

      <Card className="bg-card border-foreground/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Recent Activity</CardTitle>
            <Link href="/admin/scans">
              <Button variant="ghost" size="sm" className="h-8 text-xs text-primary gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </Button>
            </Link>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {tasks.loading && !tasks.data ? (
            <div className="p-4"><TableSkeleton rows={5} cols={5} /></div>
          ) : tasks.error ? (
            <div className="p-4"><AdminError message={tasks.error} /></div>
          ) : !tasks.data?.tasks.length ? (
            <div className="text-center py-12">
              <Zap className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No scan activity yet</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Type', 'Target', 'User', 'Status', 'Started', 'Duration'].map((h) => (
                      <th key={h} className="text-left py-2.5 px-4 text-xs font-semibold text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tasks.data.tasks.map((t) => (
                    <tr key={t.scanId} className="border-b border-foreground/5 hover:bg-foreground/3">
                      <td className="py-2.5 px-4 text-xs text-foreground">
                        {SCAN_TYPE_LABEL[t.scanType] ?? t.scanType}
                      </td>
                      <td className="py-2.5 px-4 text-xs font-mono text-foreground truncate max-w-[220px]">
                        {t.target ?? '—'}
                      </td>
                      <td className="py-2.5 px-4 text-xs font-mono text-muted-foreground truncate max-w-[160px]">
                        {t.userId}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${statusClasses(t.status)}`}>
                          {t.status ?? 'unknown'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-xs text-muted-foreground">{fmtTime(t.createdAt)}</td>
                      <td className="py-2.5 px-4 text-xs text-muted-foreground">
                        {fmtDuration(t.createdAt, t.completedAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
