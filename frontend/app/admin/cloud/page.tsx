'use client'

import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { StatCardsSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listCloudIntegrations } from '@/lib/api-admin'
import { providerLabel } from '@/lib/api-cloud'
import { AdminError, fmtTime } from '@/components/admin/admin-shared'

const STATUS_CLS: Record<string, string> = {
  connected:    'bg-green-500/10 text-green-500 border-green-500/20',
  error:        'bg-red-500/10 text-red-500 border-red-500/20',
  disconnected: 'bg-muted text-muted-foreground border-border',
}

/**
 * Cloud Security — platform view.
 * Diagnoses integration health across organizations. Credentials are stored
 * encrypted in a separate backend-only document and are never exposed here.
 */
export default function AdminCloudPage() {
  const { data, loading, error, refresh } = useAdminData(listCloudIntegrations, { pollMs: 30_000 })
  const showSkeleton = useDelayedLoading(loading && !data)

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Cloud Security</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Cloud integration health across all organizations.</p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refresh}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {error && <AdminError message={error} />}

      {showSkeleton ? <StatCardsSkeleton count={4} /> : data ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            ['Integrations', data.total, 'text-foreground'],
            ['Connected', data.health.connected, 'text-green-500'],
            ['Needs attention', data.health.error, data.health.error ? 'text-red-500' : 'text-foreground'],
            ['Last sync failed', data.health.failedLastSync, data.health.failedLastSync ? 'text-orange-400' : 'text-foreground'],
          ].map(([label, value, cls]) => (
            <Card key={label as string} className="bg-card border-foreground/10">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className={`text-2xl font-bold mt-1 ${cls}`}>{value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={5} cols={8} /></div>
          ) : !data ? null : data.integrations.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-16">No organization has connected a cloud provider yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Organization', 'Integration', 'Provider', 'Status', 'Last sync', 'Findings', 'Assets', 'Diagnostics'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.integrations.map((i) => (
                    <tr key={`${i.organizationId}/${i.integrationId}`} className="border-b border-foreground/5 hover:bg-foreground/3 align-top">
                      <td className="py-3 px-4">
                        <p className="text-sm text-foreground">{i.organizationName ?? '—'}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{i.organizationId}</p>
                      </td>
                      <td className="py-3 px-4">
                        <p className="text-sm text-foreground">{i.displayName}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{i.accountId ?? '—'}</p>
                      </td>
                      <td className="py-3 px-4 text-xs">{providerLabel(i.provider)}</td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${STATUS_CLS[i.status] ?? STATUS_CLS.disconnected}`}>{i.status}</span>
                        {i.syncStatus !== 'idle' && <p className="text-[11px] text-blue-400 mt-1">{i.syncStatus}</p>}
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        <p className="text-foreground">{fmtTime(i.lastSyncAt)}</p>
                        <p className={i.lastSyncStatus === 'failed' ? 'text-red-400' : i.lastSyncStatus === 'partial' ? 'text-orange-400' : 'text-muted-foreground'}>
                          {i.lastSyncStatus ?? 'never synced'}
                        </p>
                      </td>
                      <td className="py-3 px-4 text-xs font-mono">{i.counts?.open ?? 0} open<br /><span className="text-muted-foreground">{i.counts?.findings ?? 0} total</span></td>
                      <td className="py-3 px-4 text-xs font-mono">{i.counts?.assets ?? 0}</td>
                      <td className="py-3 px-4 text-[11px] text-muted-foreground max-w-[18rem]">
                        {i.lastSyncError ? <span className="text-red-400">{i.lastSyncError.code}: {i.lastSyncError.message}</span>
                          : i.lastSyncStats ? `${i.lastSyncStats.apiCalls} API calls · ${i.lastSyncStats.apiLatencyMs} ms` : '—'}
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
