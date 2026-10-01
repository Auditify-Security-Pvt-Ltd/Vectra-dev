'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Cloud, Plug, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { StatCardsSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAuth } from '@/context/auth-context'
import { hasPermission } from '@/lib/rbac'
import { getCloudSummary, providerLabel } from '@/lib/api-cloud'
import {
  CloudErrorState, INTEGRATION_STATUS, ProviderBadge, SeverityBadge, StatTile, StatusBadge,
  formatRelative, useCloudData,
} from '@/components/cloud/cloud-shared'

export default function CloudSecurityOverviewPage() {
  const router = useRouter()
  const { orgRole } = useAuth()
  const canManage = !!orgRole && hasPermission(orgRole, 'manageCloudIntegrations')
  const { data, error, loading, reload } = useCloudData(getCloudSummary)

  const header = (
    <div className="flex items-start justify-between gap-4 flex-wrap">
      <div>
        <h1 className="text-xl font-bold text-foreground">Cloud Security</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Security findings from your connected cloud providers.</p>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={reload}>
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </Button>
        <Button size="sm" className="gap-2" onClick={() => router.push('/app/cloud-security/integrations')}>
          <Plug className="w-3.5 h-3.5" /> Integrations
        </Button>
      </div>
    </div>
  )

  if (error && !data) {
    return <div className="p-6 space-y-6">{header}<CloudErrorState error={error} /></div>
  }

  if (loading && !data) {
    return (
      <div className="p-6 space-y-6">
        {header}
        <StatCardsSkeleton count={4} />
        <Card className="bg-card border-foreground/10"><CardContent className="p-4"><TableSkeleton rows={5} cols={6} /></CardContent></Card>
      </div>
    )
  }

  if (!data) return null

  if (data.integrations.length === 0) {
    return (
      <div className="p-6 space-y-6">
        {header}
        <Card className="bg-card border-foreground/10">
          <CardContent className="py-16 text-center max-w-lg mx-auto">
            <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mx-auto mb-4">
              <Cloud className="w-7 h-7 text-blue-400" />
            </div>
            <p className="text-base font-semibold text-foreground">No cloud providers connected</p>
            <p className="text-sm text-muted-foreground mt-1">
              Connect your cloud environment to centralize security findings from AWS Security Hub and Google Security Command Center.
            </p>
            {canManage ? (
              <div className="flex justify-center gap-2 mt-5">
                <Button onClick={() => router.push('/app/cloud-security/integrations')}>Connect AWS</Button>
                <Button variant="outline" className="border-foreground/20" onClick={() => router.push('/app/cloud-security/integrations')}>
                  Connect Google Cloud
                </Button>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground mt-4">An organization admin can connect a cloud provider.</p>
            )}
          </CardContent>
        </Card>
      </div>
    )
  }

  const t = data.totals
  return (
    <div className="p-6 space-y-6">
      {header}
      {error ? <CloudErrorState error={error} title="Could not refresh" /> : null}

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        <StatTile label="Total findings" value={t.findings} />
        <StatTile label="Open" value={t.open} cls={t.open ? 'text-red-400' : 'text-foreground'} />
        <StatTile label="Critical" value={t.critical} cls={t.critical ? 'text-red-400' : 'text-foreground'} sub="open" />
        <StatTile label="High" value={t.high} cls={t.high ? 'text-orange-400' : 'text-foreground'} sub="open" />
        <StatTile label="Medium" value={t.medium} cls={t.medium ? 'text-yellow-500' : 'text-foreground'} sub="open" />
        <StatTile label="Low" value={t.low} cls={t.low ? 'text-blue-400' : 'text-foreground'} sub="open" />
        <StatTile label="Resolved" value={t.resolved} cls="text-green-500" />
        <StatTile label="Suppressed" value={t.suppressed} />
      </div>

      <div className="grid lg:grid-cols-3 gap-3">
        <Card className="bg-card border-foreground/10">
          <CardContent className="p-4 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Cloud assets</h2>
            <p className="text-3xl font-bold text-foreground">{t.assets}</p>
            <div className="space-y-1.5 text-xs">
              {Object.entries(data.byProvider).map(([p, v]) => (
                <div key={p} className="flex justify-between"><span className="text-muted-foreground">{providerLabel(p)} assets</span><span className="font-mono">{v.assets}</span></div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground/70">Resources referenced by imported findings.</p>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardContent className="p-4 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Integration health</h2>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div><p className="text-xl font-bold text-green-500">{data.health.connected}</p><p className="text-[11px] text-muted-foreground">Connected</p></div>
              <div><p className={`text-xl font-bold ${data.health.syncing ? 'text-blue-400' : 'text-foreground'}`}>{data.health.syncing}</p><p className="text-[11px] text-muted-foreground">Syncing</p></div>
              <div><p className={`text-xl font-bold ${data.health.failedLastSync || data.health.error ? 'text-red-400' : 'text-foreground'}`}>{data.health.failedLastSync + data.health.error}</p><p className="text-[11px] text-muted-foreground">Failed</p></div>
            </div>
            <p className="text-xs text-muted-foreground">Last sync: <span className="text-foreground">{formatRelative(data.health.lastSyncAt)}</span></p>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardContent className="p-4 space-y-2">
            <h2 className="text-sm font-semibold text-foreground">Connected providers</h2>
            {data.integrations.map((i) => {
              const s = INTEGRATION_STATUS[i.status] ?? INTEGRATION_STATUS.error
              return (
                <div key={i.integrationId} className="flex items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <ProviderBadge provider={i.provider} />
                    <span className="truncate text-foreground">{i.displayName}</span>
                  </div>
                  <span className={`shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded border ${s.cls}`}>
                    {i.syncStatus !== 'idle' ? 'Syncing' : i.lastSyncStatus === 'failed' ? 'Sync failed' : s.label}
                  </span>
                </div>
              )
            })}
            <Link href="/app/cloud-security/integrations" className="text-xs text-primary hover:underline">Manage integrations</Link>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          <div className="flex items-center justify-between px-4 py-3 border-b border-foreground/8">
            <h2 className="text-sm font-semibold text-foreground">Recent open findings</h2>
            <Link href="/app/cloud-security/findings" className="text-xs text-primary hover:underline">View all</Link>
          </div>
          {data.recentFindings.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-10">
              {data.integrations.some((i) => i.lastSyncAt) ? 'No open findings. Nice work.' : 'Run a sync to import findings.'}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Severity', 'Finding', 'Provider', 'Resource', 'Region', 'Status', 'Last seen'].map((h) => (
                      <th key={h} className="text-left py-2.5 px-4 text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.recentFindings.map((f) => (
                    <tr key={f.fingerprint} className="border-b border-foreground/5 hover:bg-foreground/3 cursor-pointer"
                      onClick={() => router.push(`/app/cloud-security/findings/${f.fingerprint}`)}>
                      <td className="py-2.5 px-4"><SeverityBadge severity={f.severity} /></td>
                      <td className="py-2.5 px-4 max-w-[22rem]"><p className="truncate text-foreground">{f.title}</p></td>
                      <td className="py-2.5 px-4"><ProviderBadge provider={f.provider} /></td>
                      <td className="py-2.5 px-4 max-w-[16rem]"><p className="truncate text-xs font-mono text-muted-foreground">{f.resourceName ?? f.resourceId ?? '—'}</p></td>
                      <td className="py-2.5 px-4 text-xs text-muted-foreground">{f.region ?? '—'}</td>
                      <td className="py-2.5 px-4"><StatusBadge status={f.status} /></td>
                      <td className="py-2.5 px-4 text-xs text-muted-foreground whitespace-nowrap">{formatRelative(f.lastSeenAt)}</td>
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
