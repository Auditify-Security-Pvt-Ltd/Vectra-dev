'use client'

/**
 * Presentation helpers and hooks shared by the Cloud Security pages.
 * Kept out of page files because App Router pages may only export `default`.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Cloud, ExternalLink, XCircle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  CloudApiError, getSync, providerLabel,
  type CapabilityInfo, type CloudError, type CloudSync, type GcpCapabilities,
} from '@/lib/api-cloud'

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

export const SEV_CLS: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/25',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/25',
  medium:   'bg-yellow-500/15 text-yellow-500 border-yellow-500/25',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/25',
  info:     'bg-slate-500/15 text-slate-400 border-slate-500/25',
}

export const SEV_TEXT: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-500', low: 'text-blue-400', info: 'text-slate-400',
}

const STATUS_CLS: Record<string, string> = {
  open:       'bg-red-500/10 text-red-400 border-red-500/20',
  resolved:   'bg-green-500/10 text-green-500 border-green-500/20',
  suppressed: 'bg-muted text-muted-foreground border-border',
}

const PROVIDER_CLS: Record<string, string> = {
  aws: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  gcp: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${SEV_CLS[severity] ?? SEV_CLS.info}`}>
      {severity}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-flex text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${STATUS_CLS[status] ?? STATUS_CLS.suppressed}`}>
      {status}
    </span>
  )
}

export function ProviderBadge({ provider }: { provider: string }) {
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border ${PROVIDER_CLS[provider] ?? 'bg-muted text-muted-foreground border-border'}`}>
      <Cloud className="w-3 h-3" /> {providerLabel(provider)}
    </span>
  )
}

export const INTEGRATION_STATUS: Record<string, { label: string; cls: string }> = {
  connected:    { label: 'Healthy',      cls: 'bg-green-500/10 text-green-500 border-green-500/20' },
  error:        { label: 'Needs attention', cls: 'bg-red-500/10 text-red-400 border-red-500/20' },
  disconnected: { label: 'Disconnected', cls: 'bg-muted text-muted-foreground border-border' },
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return 'Never'
  const ms = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(ms)) return '—'
  const mins = Math.floor(ms / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} hour${hrs === 1 ? '' : 's'} ago`
  const days = Math.floor(hrs / 24)
  return `${days} day${days === 1 ? '' : 's'} ago`
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function errorMessage(err: unknown): string {
  if (err instanceof CloudApiError) return err.message
  return err instanceof Error ? err.message : 'Something went wrong'
}

/** Shown when a Cloud Security request fails; states the backend's reason and hint. */
export function CloudErrorState({ error, title = 'Cloud Security is unavailable' }: { error: unknown; title?: string }) {
  const hint = error instanceof CloudApiError ? error.hint : null
  return (
    <Card className="border-red-500/20 bg-red-500/5">
      <CardContent className="p-4 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-red-400">{title}</p>
          <p className="text-xs text-muted-foreground">{errorMessage(error)}</p>
          {hint && <p className="text-xs text-muted-foreground/80">{hint}</p>}
        </div>
      </CardContent>
    </Card>
  )
}

export function SyncErrorDetail({ error }: { error: CloudError | null | undefined }) {
  if (!error) return null
  return (
    <div className="text-xs space-y-1">
      <p className="text-red-400">{error.message}</p>
      {error.hint && <p className="text-muted-foreground">{error.hint}</p>}
      {error.scopes?.map((s) => (
        <p key={s.scope} className="text-muted-foreground">
          <span className="font-mono">{s.scope}</span>: {s.message}
        </p>
      ))}
    </div>
  )
}

/**
 * Load-once data hook with explicit loading/error state for backend reads.
 * `reload()` refetches without clearing existing data, so the UI never blanks.
 */
export function useCloudData<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData]       = useState<T | null>(null)
  const [error, setError]     = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const loadRef = useRef(load)
  loadRef.current = load
  const seq = useRef(0)

  const reload = useCallback(async () => {
    const id = ++seq.current
    setLoading(true)
    try {
      const result = await loadRef.current()
      if (id === seq.current) { setData(result); setError(null) }
    } catch (err) {
      if (id === seq.current) setError(err)
    } finally {
      if (id === seq.current) setLoading(false)
    }
  }, [])

  useEffect(() => { void reload() }, deps) // eslint-disable-line react-hooks/exhaustive-deps

  return { data, error, loading, reload }
}

/**
 * Poll a running sync until it finishes. Calls `onDone` once with the final
 * record. Polling backs off gently and stops when the component unmounts.
 */
export function useSyncPoller(onDone: (sync: CloudSync) => void) {
  const [active, setActive] = useState<Record<string, CloudSync | null>>({})
  const timers = useRef<Record<string, ReturnType<typeof setTimeout>>>({})
  const doneRef = useRef(onDone)
  doneRef.current = onDone

  useEffect(() => () => { Object.values(timers.current).forEach(clearTimeout) }, [])

  const track = useCallback((integrationId: string, syncId: string) => {
    let delay = 1500
    const tick = async () => {
      try {
        const { sync } = await getSync(syncId)
        setActive((a) => ({ ...a, [integrationId]: sync }))
        if (sync.status === 'queued' || sync.status === 'running') {
          delay = Math.min(delay * 1.3, 8000)
          timers.current[integrationId] = setTimeout(tick, delay)
          return
        }
        setActive((a) => { const n = { ...a }; delete n[integrationId]; return n })
        doneRef.current(sync)
      } catch {
        timers.current[integrationId] = setTimeout(tick, 5000)
      }
    }
    setActive((a) => ({ ...a, [integrationId]: null }))
    clearTimeout(timers.current[integrationId])
    timers.current[integrationId] = setTimeout(tick, 800)
  }, [])

  return { active, track }
}

export function StatTile({ label, value, cls = 'text-foreground', sub }: {
  label: string; value: React.ReactNode; cls?: string; sub?: string
}) {
  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className={`text-2xl font-bold mt-1 ${cls}`}>{value}</p>
        {sub && <p className="text-[11px] text-muted-foreground mt-0.5">{sub}</p>}
      </CardContent>
    </Card>
  )
}

// ── Google Cloud capabilities ─────────────────────────────────────────

function CapabilityIcon({ info }: { info: CapabilityInfo | undefined }) {
  if (info?.available && !info.partial) return <CheckCircle2 className="w-3.5 h-3.5 text-green-500 shrink-0 mt-0.5" aria-label="Available" />
  if (info?.available || info?.status === 'unavailable') return <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" aria-label="Limited" />
  return <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" aria-label="Not available" />
}

/**
 * What a Google Cloud connection can do. Security Command Center is optional:
 * when it is unavailable the connection is still usable and says why.
 */
export function GcpCapabilityList({ capabilities, compact = false }: { capabilities: GcpCapabilities; compact?: boolean }) {
  const discovery = capabilities.resource_discovery
  const scc = capabilities.scc
  const categories = Object.values(discovery?.categories ?? {})
  const limited = categories.filter((c) => !c.available || c.partial)
  const sccLabel = scc?.available ? 'Security Command Center'
    : scc?.status === 'error' ? 'Security Command Center temporarily unreachable'
    : 'Security Command Center unavailable'

  const rows: { key: string; label: string; info: CapabilityInfo | undefined; detail?: React.ReactNode }[] = [
    { key: 'auth', label: 'Authentication', info: capabilities.authentication ?? { available: capabilities.authenticated, status: capabilities.authenticated ? 'available' : 'unavailable' } },
    {
      key: 'discovery', label: 'Resource Discovery', info: discovery && { ...discovery, partial: discovery.available && limited.length > 0 },
      detail: discovery && limited.length > 0 && (compact
        ? <span>Limited: {limited.map((c) => c.label).join(', ')}</span>
        : (
          <ul className="space-y-0.5 mt-0.5">
            {limited.map((c) => <li key={c.label}>{c.label}: {c.message}{c.hint ? ` ${c.hint}` : ''}</li>)}
          </ul>
        )),
    },
    { key: 'analysis', label: 'Security Configuration Analysis', info: capabilities.configuration_analysis },
    {
      key: 'scc', label: sccLabel, info: scc,
      detail: scc && !scc.available && (
        <>
          <span>{scc.message}</span>
          {!compact && scc.hint && <span className="block">{scc.hint}</span>}
          {scc.docsUrl && (
            <a href={scc.docsUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline ml-1">
              Learn how to enable SCC <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </>
      ),
    },
  ]

  return (
    <div className="space-y-1.5">
      {capabilities.project_id && (
        <p className="text-xs text-muted-foreground">Project: <span className="font-mono text-foreground">{capabilities.project_id}</span></p>
      )}
      <ul className="space-y-1.5" aria-label="Google Cloud capabilities">
        {rows.map((r) => (
          <li key={r.key} className="flex items-start gap-2 text-xs">
            <CapabilityIcon info={r.info} />
            <div className="min-w-0">
              <span className="text-foreground">{r.label}</span>
              {r.detail && <div className="text-muted-foreground">{r.detail}</div>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function isGcpCapabilities(value: unknown): value is GcpCapabilities {
  return !!value && typeof value === 'object' && 'authenticated' in value
}
