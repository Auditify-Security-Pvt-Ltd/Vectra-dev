'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, CheckCircle2, Clock, XCircle, StopCircle, Zap, Globe,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { NewScanModal } from '@/components/app/new-scan-modal'
import {
  getFirestoreDiscovery,
  listenToAssetsByDiscovery,
  ACTIVE_DISCOVERY_STATUSES,
  type FirestoreDiscovery,
  type FirestoreAsset,
} from '@/lib/firestore-assets'
import { cancelDiscovery, discoveryStreamUrl } from '@/lib/api-assets'
import { useAuth } from '@/context/auth-context'

const PIPELINE_STEPS = [
  { key: 'queued',      label: 'Queued'      },
  { key: 'running',     label: 'Subfinder'   },
  { key: 'running',     label: 'Httpx'       },
  { key: 'completed',   label: 'Completed'   },
]

const STATUS_COLOR: Record<string, string> = {
  queued:    'text-yellow-500',
  running:   'text-blue-400',
  completed: 'text-green-500',
  failed:    'text-red-500',
  cancelled: 'text-gray-400',
}

const STATUS_CODE_COLORS: Record<number, string> = {
  200: 'text-green-500', 301: 'text-blue-400', 302: 'text-blue-400',
  403: 'text-orange-500', 404: 'text-gray-400', 500: 'text-red-500',
}
function codeColor(code?: number) {
  if (!code) return 'text-muted-foreground'
  return STATUS_CODE_COLORS[code] ?? (code < 400 ? 'text-green-500' : code < 500 ? 'text-yellow-500' : 'text-red-500')
}

export default function DiscoveryDetailPage() {
  const { id: discoveryId } = useParams<{ id: string }>()
  const router = useRouter()
  const { user } = useAuth()

  const [discovery, setDiscovery]     = useState<FirestoreDiscovery | null>(null)
  const [assets, setAssets]           = useState<FirestoreAsset[]>([])
  const [notFound, setNotFound]       = useState(false)
  const [cancelling, setCancelling]   = useState(false)
  const [scanModal, setScanModal]     = useState(false)
  const [scanTarget, setScanTarget]   = useState('')

  // Load initial state from Firestore
  useEffect(() => {
    if (!user) return
    getFirestoreDiscovery(user.uid, discoveryId).then((d) => {
      if (d) setDiscovery(d)
      else setNotFound(true)
    })
  }, [user, discoveryId])

  // Realtime assets listener
  useEffect(() => {
    if (!user) return
    return listenToAssetsByDiscovery(user.uid, discoveryId, setAssets)
  }, [user, discoveryId])

  // SSE for real-time discovery state updates (local UI only — AssetSyncProvider writes to Firestore)
  useEffect(() => {
    if (!user || !discovery) return
    if (!ACTIVE_DISCOVERY_STATUSES.has(discovery.status)) return

    const es = new EventSource(discoveryStreamUrl(discoveryId))

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string)
        setDiscovery((prev) =>
          prev
            ? {
                ...prev,
                status:          data.status,
                currentStep:     data.currentStep,
                subdomainsFound: data.subdomainsFound ?? prev.subdomainsFound,
                liveAssets:      data.liveAssets ?? prev.liveAssets,
                logs:            data.logs ?? prev.logs,
                error:           data.error ?? prev.error,
                completedAt:     data.completedAt ?? prev.completedAt,
              }
            : prev,
        )
        if (!ACTIVE_DISCOVERY_STATUSES.has(data.status)) {
          es.close()
        }
      } catch {
        // ignore
      }
    }

    es.onerror = () => es.close()

    return () => es.close()
  }, [user, discoveryId, discovery?.status])

  async function handleCancel() {
    if (!discovery) return
    setCancelling(true)
    try {
      await cancelDiscovery(discoveryId)
      setDiscovery((prev) => prev ? { ...prev, status: 'cancelled', currentStep: 'Cancelled' } : prev)
      toast.success('Discovery cancelled')
    } catch {
      toast.error('Failed to cancel discovery')
    } finally {
      setCancelling(false)
    }
  }

  function handleScan(asset: FirestoreAsset) {
    setScanTarget(asset.url ?? `https://${asset.subdomain}`)
    setScanModal(true)
  }

  if (notFound) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <p className="text-muted-foreground">Discovery not found.</p>
      </div>
    )
  }

  if (!discovery) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
      </div>
    )
  }

  const isActive  = ACTIVE_DISCOVERY_STATUSES.has(discovery.status)
  const isFailed  = discovery.status === 'failed' || discovery.status === 'cancelled'

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost" size="icon"
            onClick={() => router.push('/app/assets')}
            className="rounded-lg"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-foreground font-mono">{discovery.domain}</h1>
            <p className="text-xs text-muted-foreground font-mono mt-0.5">{discoveryId}</p>
          </div>
        </div>
        {isActive && (
          <Button
            variant="outline" size="sm" disabled={cancelling}
            className="rounded-lg border-destructive/30 text-destructive hover:bg-destructive/10 gap-1.5"
            onClick={handleCancel}
          >
            <StopCircle className="w-4 h-4" />
            Stop
          </Button>
        )}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`font-semibold capitalize flex items-center gap-1.5 ${STATUS_COLOR[discovery.status] ?? 'text-foreground'}`}>
              {isActive && <span className="w-2 h-2 rounded-full bg-current animate-pulse" />}
              {discovery.status}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">{discovery.currentStep}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Subdomains Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{discovery.subdomainsFound}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Live Assets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{discovery.liveAssets}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">In Firestore</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{assets.length}</div>
          </CardContent>
        </Card>
      </div>

      {/* Pipeline */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Discovery Pipeline</CardTitle>
            {isActive && <span className="text-xs text-primary animate-pulse">● Live</span>}
            {discovery.completedAt && (
              <span className="text-xs text-muted-foreground">
                Completed {new Date(discovery.completedAt).toLocaleString()}
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-1 flex-wrap">
            {[
              { label: 'Queued',    active: true,                        done: discovery.status !== 'queued'     },
              { label: 'Subfinder', active: isActive,                    done: discovery.subdomainsFound > 0      },
              { label: 'Httpx',     active: isActive && discovery.liveAssets > 0, done: discovery.status === 'completed' },
              { label: 'Completed', active: false,                       done: discovery.status === 'completed'  },
            ].map((step, idx, arr) => (
              <div key={step.label} className="flex items-center gap-1">
                <div
                  className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
                    isFailed && idx === 1
                      ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                      : step.done
                      ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                      : step.active
                      ? 'bg-primary/15 text-primary border border-primary/40 animate-pulse'
                      : 'bg-foreground/5 text-muted-foreground border border-foreground/10'
                  }`}
                >
                  {step.label}
                </div>
                {idx < arr.length - 1 && (
                  <div className={`w-4 h-px ${step.done ? 'bg-green-500/40' : 'bg-foreground/10'}`} />
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Error */}
      {discovery.error && (
        <Card className="bg-orange-500/5 border-orange-500/20">
          <CardContent className="pt-4 pb-4">
            <p className="text-sm text-orange-300 font-mono">{discovery.error}</p>
          </CardContent>
        </Card>
      )}

      {/* Live logs */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Discovery Logs</CardTitle>
            {isActive && <span className="text-xs text-primary animate-pulse">● Live</span>}
          </div>
        </CardHeader>
        <CardContent>
          {discovery.logs.length === 0 ? (
            <p className="text-sm text-muted-foreground">No logs yet…</p>
          ) : (
            <div className="space-y-2 font-mono text-xs max-h-72 overflow-y-auto">
              {discovery.logs.map((log, i) => {
                const isLast = i === discovery.logs.length - 1
                return (
                  <div key={i} className="flex items-start gap-3">
                    {isLast && isActive ? (
                      <Clock className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5 animate-pulse" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-500 shrink-0 mt-0.5" />
                    )}
                    <span className="text-muted-foreground shrink-0">[{log.timestamp}]</span>
                    <span className="text-foreground break-all">{log.message}</span>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Live assets counter */}
      {isActive && assets.length > 0 && (
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-primary animate-pulse">●</span>
              <p className="text-sm text-foreground">
                <span className="font-semibold text-primary">{assets.length}</span> assets saved to Firestore so far
                {' '}·{' '}
                <span className="text-green-500">{assets.filter((a) => a.alive).length} live</span>
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Assets table */}
      {assets.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">
                Discovered Assets ({assets.length})
              </CardTitle>
              {isActive && <span className="text-xs text-primary animate-pulse">● updating</span>}
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Code</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Subdomain</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Title</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Technologies</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Server</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">IP</th>
                    <th className="py-3 px-4 text-xs font-semibold text-muted-foreground text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr
                      key={asset.assetId}
                      className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors"
                    >
                      <td className="py-3 px-4 whitespace-nowrap">
                        {asset.alive ? (
                          <div className="flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-green-500 shrink-0" />
                            <span className={`text-sm font-mono font-semibold ${codeColor(asset.statusCode)}`}>
                              {asset.statusCode ?? '—'}
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <XCircle className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                            <span className="text-xs text-gray-500">offline</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 max-w-[160px]">
                        <a
                          href={asset.url ?? `https://${asset.subdomain}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm font-mono text-foreground hover:text-primary transition-colors truncate block"
                        >
                          {asset.subdomain}
                        </a>
                      </td>
                      <td className="py-3 px-4 max-w-[140px]">
                        <span className="text-sm text-foreground truncate block">
                          {asset.title ?? <span className="text-muted-foreground">—</span>}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-[180px]">
                        {(asset.technologies?.length ?? 0) > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {asset.technologies!.slice(0, 3).map((t) => (
                              <span
                                key={t}
                                className="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 whitespace-nowrap"
                              >
                                {t.split(':')[0]}
                              </span>
                            ))}
                            {asset.technologies!.length > 3 && (
                              <span className="text-xs text-muted-foreground self-center">
                                +{asset.technologies!.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs text-muted-foreground">
                          {asset.server ?? '—'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs font-mono text-muted-foreground">
                          {asset.ip ?? '—'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex justify-end">
                          {asset.alive && (
                            <Button
                              variant="ghost" size="sm"
                              className="h-7 rounded-lg text-primary hover:bg-primary/10 gap-1 text-xs"
                              onClick={() => handleScan(asset)}
                            >
                              <Zap className="w-3.5 h-3.5" />
                              Scan
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      <NewScanModal open={scanModal} onOpenChange={setScanModal} defaultTarget={scanTarget} />
    </div>
  )
}
