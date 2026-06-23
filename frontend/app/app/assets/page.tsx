'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Plus, Search, Trash2, Zap, Globe, Network,
  CheckCircle2, XCircle, RefreshCw, ChevronRight,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { NewScanModal } from '@/components/app/new-scan-modal'
import { StartDiscoveryModal } from '@/components/app/start-discovery-modal'
import {
  listenToAssets,
  listenToDiscoveries,
  deleteFirestoreAsset,
  ACTIVE_DISCOVERY_STATUSES,
  type FirestoreAsset,
  type FirestoreDiscovery,
} from '@/lib/firestore-assets'
import { deleteBackendAsset } from '@/lib/api-assets'
import { useAuth } from '@/context/auth-context'

const STATUS_CODE_COLORS: Record<number, string> = {
  200: 'text-green-500', 201: 'text-green-500', 204: 'text-green-500',
  301: 'text-blue-400',  302: 'text-blue-400',  304: 'text-blue-400',
  400: 'text-yellow-500', 401: 'text-yellow-500', 403: 'text-orange-500',
  404: 'text-gray-400',  405: 'text-yellow-500',
  500: 'text-red-500',   502: 'text-red-500',   503: 'text-red-500',
}

function codeColor(code?: number) {
  if (!code) return 'text-muted-foreground'
  if (STATUS_CODE_COLORS[code]) return STATUS_CODE_COLORS[code]
  if (code < 400) return 'text-green-500'
  if (code < 500) return 'text-yellow-500'
  return 'text-red-500'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

const DISC_PILL: Record<string, string> = {
  queued:    'bg-yellow-500/10 text-yellow-500',
  running:   'bg-blue-500/10 text-blue-400',
  completed: 'bg-green-500/10 text-green-500',
  failed:    'bg-red-500/10 text-red-500',
  cancelled: 'bg-gray-500/10 text-gray-400',
}

export default function AssetsPage() {
  const router = useRouter()
  const { user } = useAuth()

  const [assets, setAssets]             = useState<FirestoreAsset[]>([])
  const [discoveries, setDiscoveries]   = useState<FirestoreDiscovery[]>([])
  const [search, setSearch]             = useState('')
  const [aliveOnly, setAliveOnly]       = useState(false)
  const [discoveryModal, setDiscoveryModal] = useState(false)
  const [scanModal, setScanModal]           = useState(false)
  const [scanTarget, setScanTarget]         = useState('')
  const [deletingId, setDeletingId]         = useState<string | null>(null)

  useEffect(() => {
    if (!user) return
    const u1 = listenToAssets(user.uid, setAssets)
    const u2 = listenToDiscoveries(user.uid, setDiscoveries)
    return () => { u1(); u2() }
  }, [user])

  const filtered = useMemo(
    () =>
      assets.filter((a) => {
        const matchSearch =
          a.subdomain.toLowerCase().includes(search.toLowerCase()) ||
          (a.title ?? '').toLowerCase().includes(search.toLowerCase()) ||
          (a.ip ?? '').includes(search) ||
          (a.server ?? '').toLowerCase().includes(search.toLowerCase())
        return matchSearch && (!aliveOnly || a.alive)
      }),
    [assets, search, aliveOnly],
  )

  const liveCount  = useMemo(() => assets.filter((a) => a.alive).length, [assets])
  const todayCount = useMemo(() => {
    const today = new Date().toDateString()
    return assets.filter((a) => new Date(a.createdAt).toDateString() === today).length
  }, [assets])
  const activeDiscoveries = discoveries.filter((d) => ACTIVE_DISCOVERY_STATUSES.has(d.status))

  async function handleDelete(asset: FirestoreAsset) {
    if (!user) return
    setDeletingId(asset.assetId)
    try {
      await deleteFirestoreAsset(user.uid, asset.assetId)
      deleteBackendAsset(asset.assetId).catch(() => {})
      toast.success(`Deleted ${asset.subdomain}`)
    } catch {
      toast.error('Failed to delete asset')
    } finally {
      setDeletingId(null)
    }
  }

  function handleScan(asset: FirestoreAsset) {
    setScanTarget(asset.url ?? `https://${asset.subdomain}`)
    setScanModal(true)
  }

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Assets</h1>
          <p className="text-muted-foreground mt-1">Discovered attack surface — subdomains &amp; live hosts</p>
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6 gap-2"
          onClick={() => setDiscoveryModal(true)}
        >
          <Plus className="w-4 h-4" />
          New Discovery
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Assets',       value: assets.length,             icon: Globe,         color: 'text-foreground' },
          { label: 'Live Assets',        value: liveCount,                 icon: CheckCircle2,  color: 'text-green-500'  },
          { label: 'Discovered Today',   value: todayCount,                icon: Network,       color: 'text-blue-400'   },
          { label: 'Active Discoveries', value: activeDiscoveries.length,  icon: RefreshCw,     color: 'text-primary'    },
        ].map((s) => {
          const Icon = s.icon
          return (
            <Card key={s.label} className="bg-card border-foreground/10">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${s.color}`} />
                  {s.label}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Active discovery banner */}
      {activeDiscoveries.length > 0 && (
        <div className="flex items-center gap-4 p-4 bg-primary/5 border border-primary/20 rounded-lg">
          <span className="text-xs text-primary animate-pulse">●</span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-foreground">
              {activeDiscoveries.length} discovery{activeDiscoveries.length > 1 ? ' sessions' : ''} running
            </p>
            <p className="text-xs text-muted-foreground truncate">
              {activeDiscoveries.map((d) => d.domain).join(', ')}
            </p>
          </div>
          <Button
            variant="outline" size="sm"
            className="rounded-lg border-primary/30 text-primary hover:bg-primary/10 shrink-0"
            onClick={() => router.push(`/app/assets/discovery/${activeDiscoveries[0].discoveryId}`)}
          >
            View Progress →
          </Button>
        </div>
      )}

      {/* Discovery history */}
      {discoveries.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Discovery History</CardTitle>
                <CardDescription>
                  {discoveries.length} session{discoveries.length !== 1 ? 's' : ''}
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-foreground/5">
              {discoveries.slice(0, 6).map((d) => (
                <div
                  key={d.discoveryId}
                  className="flex items-center gap-4 px-6 py-3 hover:bg-foreground/5 transition-colors cursor-pointer"
                  onClick={() => router.push(`/app/assets/discovery/${d.discoveryId}`)}
                >
                  <Globe className="w-4 h-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground font-mono">{d.domain}</p>
                    <p className="text-xs text-muted-foreground">{formatDate(d.createdAt)}</p>
                  </div>
                  <div className="hidden md:flex items-center gap-4 text-xs text-muted-foreground">
                    <span>{d.subdomainsFound} subdomains</span>
                    <span className="text-green-500">{d.liveAssets} live</span>
                  </div>
                  <span
                    className={`text-xs font-medium px-2 py-0.5 rounded capitalize flex items-center gap-1 ${
                      DISC_PILL[d.status] ?? ''
                    }`}
                  >
                    {ACTIVE_DISCOVERY_STATUSES.has(d.status) && (
                      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
                    )}
                    {d.status}
                  </span>
                  <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Asset table */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <CardTitle>Asset Inventory</CardTitle>
              <CardDescription>
                {filtered.length} asset{filtered.length !== 1 ? 's' : ''}
                {aliveOnly ? ' (live only)' : ''}
              </CardDescription>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setAliveOnly(!aliveOnly)}
                className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                  aliveOnly
                    ? 'border-green-500/40 bg-green-500/10 text-green-500'
                    : 'border-foreground/10 text-muted-foreground hover:border-foreground/30'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Live only
              </button>
              <div className="relative w-60">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search assets…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-9"
                />
              </div>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {assets.length === 0 ? (
            <div className="text-center py-20 text-muted-foreground">
              <Globe className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm font-medium">No assets yet</p>
              <p className="text-xs mt-1">Run a discovery to find subdomains and live hosts.</p>
              <Button
                variant="outline" size="sm"
                className="mt-4 border-foreground/20"
                onClick={() => setDiscoveryModal(true)}
              >
                <Plus className="w-3.5 h-3.5 mr-1.5" />
                Start Discovery
              </Button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <p className="text-sm">No assets match your filters.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Code</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Subdomain</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">URL</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Title</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Technologies</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Server</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">IP</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Last Seen</th>
                    <th className="py-3 px-4 text-xs font-semibold text-muted-foreground text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((asset) => (
                    <tr
                      key={asset.assetId}
                      className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors"
                    >
                      {/* Status code */}
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

                      {/* Subdomain */}
                      <td className="py-3 px-4 max-w-[160px]">
                        <span className="text-sm font-mono text-foreground truncate block">
                          {asset.subdomain}
                        </span>
                      </td>

                      {/* URL */}
                      <td className="py-3 px-4 max-w-[180px]">
                        {asset.url ? (
                          <a
                            href={asset.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs font-mono text-primary hover:underline truncate block"
                          >
                            {asset.url}
                          </a>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>

                      {/* Title */}
                      <td className="py-3 px-4 max-w-[140px]">
                        <span className="text-sm text-foreground truncate block">
                          {asset.title ?? <span className="text-muted-foreground">—</span>}
                        </span>
                      </td>

                      {/* Technologies */}
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

                      {/* Server */}
                      <td className="py-3 px-4">
                        <span className="text-xs text-muted-foreground">
                          {asset.server ?? '—'}
                        </span>
                      </td>

                      {/* IP */}
                      <td className="py-3 px-4">
                        <span className="text-xs font-mono text-muted-foreground">
                          {asset.ip ?? '—'}
                        </span>
                      </td>

                      {/* Last seen */}
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(asset.createdAt)}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4">
                        <div className="flex items-center justify-end gap-1">
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
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 w-7 rounded-lg text-destructive hover:bg-destructive/10"
                            disabled={deletingId === asset.assetId}
                            onClick={() => handleDelete(asset)}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <StartDiscoveryModal open={discoveryModal} onOpenChange={setDiscoveryModal} />
      <NewScanModal open={scanModal} onOpenChange={setScanModal} defaultTarget={scanTarget} />
    </div>
  )
}
