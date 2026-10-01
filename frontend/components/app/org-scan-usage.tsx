'use client'

import { useCallback, useEffect, useState } from 'react'
import { Building2, Gauge } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { API_BASE } from '@/lib/api'
import { getOrganizationQuota, usageLabel, type OrganizationQuota } from '@/lib/api-auth'
import { useAuth } from '@/context/auth-context'

/**
 * The caller's ORGANIZATION scan usage, shared by every member.
 * Informational only — the backend enforces the limit on every scan start.
 */
export function useOrganizationQuota(refreshKey: unknown = null) {
  const { user } = useAuth()
  const [data, setData]       = useState<OrganizationQuota | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      setData(await getOrganizationQuota(API_BASE))
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load scan usage')
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => { void load() }, [load, refreshKey])

  return { data, loading, error, refresh: load }
}

function remainingClass(remaining: number, unlimited: boolean): string {
  if (unlimited) return 'text-green-500'
  if (remaining === 0) return 'text-red-500'
  if (remaining <= 1) return 'text-orange-400'
  return 'text-foreground'
}

/** One-line summary for scan-start dialogs. */
export function OrgScanUsageInline({ refreshKey }: { refreshKey?: unknown }) {
  const { data, loading, error } = useOrganizationQuota(refreshKey)

  if (loading && !data) return <Skeleton className="h-4 w-56" />
  if (error || !data) return null

  const q = data.quota
  if (data.status === 'disabled') {
    return <p className="text-xs text-red-400">Your organization is disabled — new scans cannot be started.</p>
  }
  if (!data.organizationId) {
    return <p className="text-xs text-orange-400">Your account is not part of an organization yet.</p>
  }
  return (
    <p className="text-xs text-muted-foreground flex items-center gap-1.5">
      <Gauge className="w-3.5 h-3.5" />
      Organization scan usage: <span className="text-foreground font-medium">{usageLabel(q)}</span>
      {!q.unlimited && (
        <span className={remainingClass(q.remaining, q.unlimited)}>· {q.remaining} remaining</span>
      )}
    </p>
  )
}

/** Dashboard card: organization, plan, shared usage. */
export function OrgScanUsageCard() {
  const { data, loading, error } = useOrganizationQuota()

  if (loading && !data) {
    return (
      <Card className="bg-card border-foreground/10">
        <CardContent className="p-4 space-y-2">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-2 w-full" />
        </CardContent>
      </Card>
    )
  }
  if (error || !data || !data.organizationId) return null

  const q = data.quota
  const pct = q.unlimited || q.effectiveAllowance <= 0 ? 0 : Math.min(100, (q.used / q.effectiveAllowance) * 100)

  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2 min-w-0">
            <Building2 className="w-4 h-4 text-primary shrink-0" />
            <p className="text-sm font-semibold text-foreground truncate">{data.organizationName ?? 'Organization'}</p>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded border capitalize bg-primary/10 text-primary border-primary/20">
              {q.plan}
            </span>
            {data.status === 'disabled' && (
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded border bg-red-500/10 text-red-500 border-red-500/20">
                Disabled
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Organization scans: <span className="text-foreground font-medium">{usageLabel(q)}</span>
            {!q.unlimited && (
              <span className={`ml-1.5 ${remainingClass(q.remaining, q.unlimited)}`}>· {q.remaining} remaining</span>
            )}
          </p>
        </div>
        {!q.unlimited && (
          <div className="mt-3 h-1.5 rounded-full bg-foreground/10 overflow-hidden" role="progressbar"
            aria-valuenow={q.used} aria-valuemin={0} aria-valuemax={q.effectiveAllowance}>
            <div className={`h-full ${q.remaining === 0 ? 'bg-red-500' : 'bg-primary'}`} style={{ width: `${pct}%` }} />
          </div>
        )}
        <p className="text-[11px] text-muted-foreground/70 mt-2">
          Shared by all members across Web Security, Network Security and SAST.
        </p>
      </CardContent>
    </Card>
  )
}
