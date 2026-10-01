'use client'

import Link from 'next/link'
import { Cloud, Plug } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { getCloudSummary, providerLabel } from '@/lib/api-cloud'
import { errorMessage, formatRelative, useCloudData } from '@/components/cloud/cloud-shared'

/** Main-dashboard Cloud Security module tile. Real backend data only. */
export function CloudDashboardCard() {
  const { data, error, loading } = useCloudData(getCloudSummary)

  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <Cloud className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-semibold text-foreground">Cloud Security</h2>
          </div>
          <Link href="/app/cloud-security" className="text-xs text-primary hover:underline">Open</Link>
        </div>

        {loading && !data ? (
          <div className="grid grid-cols-5 gap-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
        ) : error && !data ? (
          <p className="text-xs text-muted-foreground">Cloud Security is unavailable: {errorMessage(error)}</p>
        ) : !data || data.integrations.length === 0 ? (
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <p className="text-sm text-muted-foreground">No cloud providers connected</p>
            <Button asChild size="sm" variant="outline" className="border-foreground/20 gap-1.5">
              <Link href="/app/cloud-security/integrations"><Plug className="w-3.5 h-3.5" /> Connect Cloud Provider</Link>
            </Button>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-5 gap-2">
              {([
                ['Cloud Findings', data.totals.open, 'text-foreground'],
                ['Critical', data.totals.critical, 'text-red-400'],
                ['High', data.totals.high, 'text-orange-400'],
                ['Medium', data.totals.medium, 'text-yellow-500'],
                ['Low', data.totals.low, 'text-blue-400'],
              ] as const).map(([label, value, cls]) => (
                <div key={label} className="rounded-lg border border-foreground/8 p-2.5">
                  <p className="text-[11px] text-muted-foreground">{label}</p>
                  <p className={`text-xl font-bold ${value ? cls : 'text-foreground'}`}>{value}</p>
                </div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground mt-2">
              Open findings across {Object.keys(data.byProvider).map(providerLabel).join(' & ')} ·{' '}
              {data.totals.assets} assets · last sync {formatRelative(data.health.lastSyncAt)}
              {data.health.failedLastSync + data.health.error > 0 && (
                <span className="text-red-400"> · {data.health.failedLastSync + data.health.error} integration(s) need attention</span>
              )}
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}
