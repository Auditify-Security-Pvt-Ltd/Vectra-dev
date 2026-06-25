'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Wifi, Plus, Search, StopCircle, Loader2,
  Server, AlertTriangle, Bug, ChevronRight, Radio,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog'
import { useAuth } from '@/context/auth-context'
import {
  listenToNetworkScans,
  createNetworkScan,
  updateNetworkScan,
  NETWORK_ACTIVE_STATUSES,
  type FirestoreNetworkScan,
} from '@/lib/firestore-network-scans'
import {
  startNetworkScan, cancelNetworkScan,
  type NetworkScanProfile,
} from '@/lib/api-network'

// ── Status maps ───────────────────────────────────────────────────────

const STATUS_BADGE: Record<string, string> = {
  queued:            'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  host_discovery:    'bg-violet-500/10 text-violet-400 border-violet-500/20',
  port_scan:         'bg-blue-500/10 text-blue-400 border-blue-500/20',
  parallel_analysis: 'bg-primary/10 text-primary border-primary/20',
  completed:         'bg-green-500/10 text-green-500 border-green-500/20',
  failed:            'bg-red-500/10 text-red-500 border-red-500/20',
  cancelled:         'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const STATUS_LABEL: Record<string, string> = {
  queued:            'Queued',
  host_discovery:    'Host Discovery',
  port_scan:         'Port Scan',
  parallel_analysis: 'Analyzing',
  completed:         'Completed',
  failed:            'Failed',
  cancelled:         'Cancelled',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

// ── New Scan Modal ────────────────────────────────────────────────────

function NewNetworkScanModal({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const router      = useRouter()
  const { user }    = useAuth()
  const [target,    setTarget]   = useState('')
  const [profile,   setProfile]  = useState<NetworkScanProfile>('QUICK_SCAN')
  const [starting,  setStarting] = useState(false)
  const [errMsg,    setErrMsg]   = useState<string | null>(null)

  function reset() { setTarget(''); setProfile('QUICK_SCAN'); setErrMsg(null) }

  async function handleStart() {
    if (!user || !target.trim()) return
    setStarting(true); setErrMsg(null)
    try {
      const resp   = await startNetworkScan(target.trim(), profile)
      const scanId = resp.scanId
      const now    = new Date().toISOString()

      await createNetworkScan(user.uid, {
        scanId, target: target.trim(), scanProfile: profile,
        status: 'queued', progress: 0, currentStep: 'Queued',
        logs: [{ timestamp: now, message: `Network scan queued (${profile})` }],
        totalHosts: 0, liveHosts: 0, totalFindings: 0, totalCves: 0,
        createdAt: now,
        engines: {
          host_discovery: { status: 'pending', count: 0 },
          port_scan:      { status: 'pending', count: 0 },
          cve_analysis:   { status: 'pending', count: 0 },
          nuclei:         { status: 'pending', count: 0 },
        },
      })

      reset(); onClose()
      // Navigate to detail page — the detail page owns the SSE consumer
      router.push(`/app/network-security/scans/${scanId}`)
    } catch (err: any) {
      setErrMsg(err?.message ?? 'Failed to start scan')
    } finally {
      setStarting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { reset(); onClose() } }}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold flex items-center gap-2">
            <Wifi className="w-4 h-4 text-primary" /> New Network Scan
          </DialogTitle>
          <DialogDescription className="sr-only">Configure and launch a network scan</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Target</label>
            <Input
              placeholder="192.168.1.0/24  ·  10.0.0.5  ·  192.168.1.1-20"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleStart()}
              className="font-mono text-sm bg-background border-foreground/20 h-10"
              autoFocus
            />
            <p className="text-[11px] text-muted-foreground">Single IP, CIDR (192.168.1.0/24), or dash range (192.168.1.1-20)</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Scan Profile</label>
            <div className="grid grid-cols-2 gap-2">
              {([
                { id: 'QUICK_SCAN', label: 'Quick Scan',  desc: 'Top 1000 ports' },
                { id: 'FULL_SCAN',  label: 'Full Scan',   desc: 'All 65535 ports' },
              ] as { id: NetworkScanProfile; label: string; desc: string }[]).map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`p-3 rounded-lg border text-left transition-colors ${
                    profile === p.id ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'
                  }`}
                >
                  <p className="text-sm font-medium text-foreground">{p.label}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{p.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {errMsg && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">{errMsg}</div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" onClick={() => { reset(); onClose() }} className="h-9 text-sm rounded-lg">
              Cancel
            </Button>
            <Button
              onClick={handleStart}
              disabled={starting || !target.trim()}
              className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-5 text-sm gap-2 disabled:opacity-40"
            >
              {starting
                ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Starting…</>
                : <><Radio className="w-3.5 h-3.5" /> Start Scan</>
              }
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function NetworkSecurityPage() {
  const router      = useRouter()
  const { user }    = useAuth()
  const [scans,     setScans]     = useState<FirestoreNetworkScan[]>([])
  const [search,    setSearch]    = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [stopping,  setStopping]  = useState<string | null>(null)

  useEffect(() => {
    if (!user) return
    return listenToNetworkScans(user.uid, setScans)
  }, [user])

  async function handleStop(scanId: string) {
    setStopping(scanId)
    try {
      await cancelNetworkScan(scanId)
      if (user) await updateNetworkScan(user.uid, scanId, { status: 'cancelled', currentStep: 'Cancelled' })
      toast.success('Scan stopped')
    } catch {
      toast.error('Failed to stop scan')
    } finally {
      setStopping(null)
    }
  }

  const filtered = scans.filter((s) =>
    s.target.toLowerCase().includes(search.toLowerCase()) ||
    s.status.toLowerCase().includes(search.toLowerCase()),
  )

  const activeCount    = scans.filter((s) => NETWORK_ACTIVE_STATUSES.has(s.status)).length
  const completedCount = scans.filter((s) => s.status === 'completed').length
  const totalFindings  = scans.reduce((n, s) => n + (s.totalFindings ?? 0), 0)

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <div className="w-11 h-11 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
            <Wifi className="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Network Security</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Host discovery, port scanning, service detection &amp; CVE correlation
            </p>
          </div>
        </div>
        <Button
          onClick={() => setModalOpen(true)}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5 text-sm gap-2"
        >
          <Plus className="w-4 h-4" /> New Scan
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Active Scans',    value: activeCount,    cls: 'text-blue-400'   },
          { label: 'Completed Scans', value: completedCount, cls: 'text-green-500'  },
          { label: 'Total Findings',  value: totalFindings,  cls: 'text-orange-500' },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by target or status…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-background border-foreground/15 h-10"
        />
      </div>

      {/* Scan list */}
      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="text-center py-16 space-y-3">
              <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
                <Wifi className="w-6 h-6 text-muted-foreground" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">
                {search ? 'No scans match your search' : 'No network scans yet'}
              </p>
              {!search && (
                <Button
                  onClick={() => setModalOpen(true)}
                  variant="outline"
                  className="rounded-lg border-foreground/20 h-9 text-sm mt-2"
                >
                  <Plus className="w-3.5 h-3.5 mr-1.5" /> Start First Scan
                </Button>
              )}
            </div>
          ) : (
            <div className="divide-y divide-foreground/5">
              {filtered.map((scan) => {
                const isActive = NETWORK_ACTIVE_STATUSES.has(scan.status)
                return (
                  <div
                    key={scan.scanId}
                    className="flex items-center gap-4 px-5 py-4 hover:bg-foreground/2 transition-colors cursor-pointer group"
                    onClick={() => router.push(`/app/network-security/scans/${scan.scanId}`)}
                  >
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                      scan.status === 'completed' ? 'bg-green-500/10' :
                      scan.status === 'failed'    ? 'bg-red-500/10'   :
                      isActive                    ? 'bg-blue-500/10'  : 'bg-foreground/5'
                    }`}>
                      {isActive
                        ? <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                        : <Server className="w-4 h-4 text-muted-foreground" />
                      }
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold text-foreground font-mono">{scan.target}</p>
                        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${STATUS_BADGE[scan.status] ?? 'bg-gray-500/10 text-gray-400 border-gray-500/20'}`}>
                          {STATUS_LABEL[scan.status] ?? scan.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        <span className="text-xs text-muted-foreground">{formatDate(scan.createdAt)}</span>
                        {scan.liveHosts > 0 && (
                          <span className="text-xs text-muted-foreground">
                            <Server className="w-3 h-3 inline mr-0.5" />{scan.liveHosts} hosts
                          </span>
                        )}
                        {(scan.totalFindings ?? 0) > 0 && (
                          <span className="text-xs text-orange-400">
                            <AlertTriangle className="w-3 h-3 inline mr-0.5" />{scan.totalFindings} findings
                          </span>
                        )}
                        {(scan.totalCves ?? 0) > 0 && (
                          <span className="text-xs text-violet-400">
                            <Bug className="w-3 h-3 inline mr-0.5" />{scan.totalCves} CVEs
                          </span>
                        )}
                      </div>
                      {isActive && (
                        <div className="mt-2 flex items-center gap-2">
                          <div className="h-1 w-40 rounded-full bg-foreground/10 overflow-hidden">
                            <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${scan.progress}%` }} />
                          </div>
                          <span className="text-[11px] text-muted-foreground">{scan.currentStep}</span>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                      {isActive && (
                        <Button
                          variant="ghost" size="sm"
                          onClick={() => handleStop(scan.scanId)}
                          disabled={stopping === scan.scanId}
                          className="h-8 rounded-lg text-xs text-muted-foreground hover:text-destructive hover:bg-destructive/10 gap-1.5"
                        >
                          {stopping === scan.scanId
                            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            : <StopCircle className="w-3.5 h-3.5" />
                          }
                          Stop
                        </Button>
                      )}
                      <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground" />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <NewNetworkScanModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
      />
    </div>
  )
}
