'use client'

import { useState } from 'react'
import Link from 'next/link'
import { CreditCard, Info, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { StatCardsSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import { getQuotaConfig, listOrganizations } from '@/lib/api-admin'
import { AdminError, fmtTime } from '@/components/admin/admin-shared'
import { ORG_STATUS_CLS, allowanceLabel, remainingClass } from '@/components/admin/organization-dialogs'

const PAGE_SIZE = 25

/**
 * Subscriptions.
 *
 * A subscription is an organization's plan. There is no payment provider
 * integrated yet, so this page shows only what is real — plans, allowances and
 * usage per organization — and no revenue figures.
 */
export default function AdminSubscriptionsPage() {
  const [offset, setOffset] = useState(0)

  const config = useAdminData(getQuotaConfig)
  const plans  = config.data ? Object.keys(config.data.planAllowances).sort() : []

  // One cheap request per plan: limit 1 returns the matching total.
  const perPlan = useAdminData(
    async () => {
      const entries = await Promise.all(
        plans.map(async (p) => [p, (await listOrganizations({ plan: p, limit: 1 })).total] as const),
      )
      return Object.fromEntries(entries) as Record<string, number>
    },
    { deps: [plans.join(',')] },
  )
  const list = useAdminData(
    () => listOrganizations({ limit: PAGE_SIZE, offset }),
    { deps: [offset] },
  )
  const showSkeleton = useDelayedLoading(list.loading && !list.data)

  const total = list.data?.total ?? 0
  const error = config.error || list.error || perPlan.error

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Subscriptions</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Each organization&apos;s plan and shared scan usage.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2"
          onClick={() => { config.refresh(); perPlan.refresh(); list.refresh() }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {error && <AdminError message={error} />}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-4 flex items-start gap-3">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <p className="text-xs text-muted-foreground">
            Billing is not connected, so no revenue or payment data is shown. Plans are assigned per
            organization on the <Link href="/admin/organizations" className="text-primary hover:underline">Organizations</Link> page;
            plan defaults are set in <Link href="/admin/quotas" className="text-primary hover:underline">Plans &amp; Quotas</Link>.
          </p>
        </CardContent>
      </Card>

      {config.loading && !config.data ? (
        <StatCardsSkeleton count={3} />
      ) : config.data ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {plans.map((p) => (
            <Card key={p} className="bg-card border-foreground/10">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-1.5">
                  <CreditCard className="w-3.5 h-3.5 text-primary" />
                  <p className="text-xs text-muted-foreground capitalize">{p}</p>
                </div>
                <p className="text-2xl font-bold text-foreground">{perPlan.data?.[p] ?? '—'}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  organizations · {allowanceLabel(config.data!.planAllowances[p])} scans each
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base">Organization plans</CardTitle>
          <CardDescription>{total} organizations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={5} cols={7} /></div>
          ) : !list.data?.organizations.length ? (
            list.loading ? null : <p className="text-sm text-muted-foreground text-center py-12">No organizations yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Organization', 'Plan', 'Members', 'Allowance', 'Used', 'Remaining', 'Status', 'Since'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {list.data.organizations.map((org) => (
                    <tr key={org.orgId} className="border-b border-foreground/5 hover:bg-foreground/3">
                      <td className="py-3 px-4">
                        <p className="text-sm font-medium text-foreground">{org.name ?? '—'}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{org.ownerEmail ?? org.orgId}</p>
                      </td>
                      <td className="py-3 px-4 text-xs capitalize">{org.quota.plan}</td>
                      <td className="py-3 px-4 text-xs font-mono">{org.counts?.users ?? '—'}</td>
                      <td className="py-3 px-4 text-xs font-mono">{allowanceLabel(org.quota.effectiveAllowance)}</td>
                      <td className="py-3 px-4 text-xs font-mono text-muted-foreground">{org.quota.used}</td>
                      <td className="py-3 px-4 text-xs font-mono">
                        <span className={remainingClass(org.quota.remaining, org.quota.unlimited)}>
                          {allowanceLabel(org.quota.remaining)}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${ORG_STATUS_CLS[org.status]}`}>
                          {org.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground">{fmtTime(org.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset === 0}
            onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
            <ChevronLeft className="w-3.5 h-3.5" /> Previous
          </Button>
          <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}>
            Next <ChevronRight className="w-3.5 h-3.5" />
          </Button>
        </div>
      )}
    </div>
  )
}
