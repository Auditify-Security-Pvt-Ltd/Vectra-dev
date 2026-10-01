'use client'

import { RefreshCw, ScrollText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listAuditLogs } from '@/lib/api-admin'
import { AdminError, fmtTime } from '@/components/admin/admin-shared'

const ACTION_LABEL: Record<string, string> = {
  'user.update':         'User updated',
  'organization.update': 'Organization updated',
  'quota.config':        'Plan allowance changed',
}

/** Render a before/after value compactly, tolerating any JSON shape. */
function summarise(value: unknown): string {
  if (value == null) return '—'
  if (typeof value !== 'object') return String(value)
  const obj = value as Record<string, unknown>
  const keys = ['name', 'plan', 'effectiveAllowance', 'bonusScans', 'used', 'status']
  const parts = keys.filter((k) => k in obj).map((k) => `${k}=${obj[k]}`)
  return parts.length ? parts.join('  ') : JSON.stringify(obj).slice(0, 120)
}

export default function AdminAuditLogsPage() {
  const { data, loading, error, refresh } = useAdminData(() => listAuditLogs(200))
  const showSkeleton = useDelayedLoading(loading && !data)

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Administrative actions, recorded server-side with the acting administrator.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refresh}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {error && <AdminError message={error} />}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={6} cols={5} /></div>
          ) : loading && !data ? null : !data?.logs.length ? (
            <div className="text-center py-16">
              <ScrollText className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No administrative actions recorded yet</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Time', 'Action', 'Administrator', 'Target', 'Before → After'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.logs.map((log) => (
                    <tr key={log.id} className="border-b border-foreground/5 hover:bg-foreground/3">
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                        {fmtTime(log.timestamp)}
                      </td>
                      <td className="py-3 px-4 text-xs text-foreground">
                        {ACTION_LABEL[log.action] ?? log.action}
                      </td>
                      <td className="py-3 px-4 text-xs font-mono text-muted-foreground truncate max-w-[180px]">
                        {log.actorEmail ?? log.actorUid}
                      </td>
                      <td className="py-3 px-4 text-xs font-mono text-muted-foreground truncate max-w-[180px]">
                        {log.targetUid}
                      </td>
                      <td className="py-3 px-4 text-[11px] font-mono text-muted-foreground">
                        <span className="text-muted-foreground/70">{summarise(log.before)}</span>
                        <span className="mx-1.5 text-foreground">→</span>
                        <span className="text-foreground">{summarise(log.after)}</span>
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
