'use client'

/**
 * Presentation helpers shared across the admin pages.
 *
 * These live here rather than in a page file because App Router pages may only
 * export `default` and a fixed set of route metadata — exporting anything else
 * is a type error and breaks route typing.
 */

import { AlertTriangle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

/** Scan statuses that mean work is still in flight. Mirrors the backend set. */
export const ACTIVE_SCAN_STATUSES = new Set([
  'queued', 'initializing', 'running', 'processing', 'saving',
  'discovering_assets', 'validating_assets', 'scanning_assets',
  'detecting_technologies', 'cve_analysis', 'host_discovery',
  'port_scan', 'service_detection',
])

export const SCAN_TYPE_LABEL: Record<string, string> = {
  web:     'Web Security',
  network: 'Network Security',
  sast:    'SAST',
}

export function statusClasses(status: string | null): string {
  const s = (status ?? '').toLowerCase()
  if (s === 'completed')               return 'bg-green-500/10 text-green-500 border-green-500/20'
  if (s === 'failed' || s === 'error') return 'bg-red-500/10 text-red-500 border-red-500/20'
  if (s === 'cancelled')               return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
  if (s === 'queued')                  return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
  if (ACTIVE_SCAN_STATUSES.has(s))     return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
  return 'bg-muted text-muted-foreground border-border'
}

export function fmtTime(iso: string | null): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

export function fmtDuration(from: string | null, to: string | null): string {
  if (!from) return '—'
  const start = new Date(from).getTime()
  const end   = to ? new Date(to).getTime() : Date.now()
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return '—'
  const secs = Math.floor((end - start) / 1000)
  const m = Math.floor(secs / 60)
  return m > 0 ? `${m}m ${secs % 60}s` : `${secs}s`
}

/** Shown when the admin API refuses a request — states the backend's reason. */
export function AdminError({ message }: { message: string }) {
  return (
    <Card className="border-red-500/20 bg-red-500/5">
      <CardContent className="p-4 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-red-400">Admin API unavailable</p>
          <p className="text-xs text-muted-foreground">{message}</p>
        </div>
      </CardContent>
    </Card>
  )
}
