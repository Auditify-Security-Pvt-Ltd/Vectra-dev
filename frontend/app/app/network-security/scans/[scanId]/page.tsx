'use client'

import { useEffect, useRef, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, Server, AlertTriangle, Bug, Wifi,
  CheckCircle2, Loader2, StopCircle, Radio, Network,
  ShieldAlert, Cpu, GitBranch,
} from 'lucide-react'
import { doc, updateDoc } from 'firebase/firestore'
import { db } from '@/lib/firebase'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAuth } from '@/context/auth-context'
import {
  listenToNetworkScan,
  updateNetworkScan,
  NETWORK_ACTIVE_STATUSES,
  type FirestoreNetworkScan,
} from '@/lib/firestore-network-scans'
import {
  listenToNetworkHostsByScan,
  type FirestoreNetworkHost,
} from '@/lib/firestore-network-assets'
import {
  listenToNetworkFindingsByScan,
  type FirestoreNetworkFinding,
} from '@/lib/firestore-network-findings'
import {
  listenToNetworkCvesByScan,
  type FirestoreNetworkCve,
} from '@/lib/firestore-network-cves'
import {
  cancelNetworkScan,
  openNetworkScanStream,
  type NetworkScanStreamPayload,
} from '@/lib/api-network'
import { writeNetworkHost } from '@/lib/firestore-network-assets'
import { writeNetworkFinding } from '@/lib/firestore-network-findings'
import { writeNetworkCve } from '@/lib/firestore-network-cves'
import { API_BASE } from '@/lib/api'

// ── Severity badge ────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info:     'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const STATUS_COLOR: Record<string, string> = {
  queued:            'text-yellow-500',
  host_discovery:    'text-violet-400',
  port_scan:         'text-blue-400',
  parallel_analysis: 'text-primary',
  completed:         'text-green-500',
  failed:            'text-red-500',
  cancelled:         'text-gray-400',
}

const STATUS_LABEL: Record<string, string> = {
  queued:            'Queued',
  host_discovery:    'Host Discovery',
  port_scan:         'Port Scan',
  parallel_analysis: 'Parallel Analysis',
  completed:         'Completed',
  failed:            'Failed',
  cancelled:         'Cancelled',
}

// ── Pipeline ──────────────────────────────────────────────────────────

const STAGE_ORDER = ['host_discovery', 'port_scan', 'parallel_analysis', 'completed']

type StepState = 'done' | 'active' | 'pending' | 'skipped' | 'failed' | 'partial'

function getEngineState(engineKey: string, scan: FirestoreNetworkScan): StepState {
  const eng = scan.engines?.[engineKey as keyof typeof scan.engines]
  if (!eng) return 'pending'
  switch (eng.status) {
    case 'completed':         return 'done'
    case 'completed_partial': return 'partial'
    case 'running':           return 'active'
    case 'skipped':           return 'skipped'
    case 'failed':            return 'failed'
    default:                  return 'pending'
  }
}

function getStepState(stepKey: string, engineKey: string | null, scan: FirestoreNetworkScan): StepState {
  const currentIdx = STAGE_ORDER.indexOf(scan.status)
  const stepIdx    = STAGE_ORDER.indexOf(stepKey)
  if (scan.status === 'completed' && stepKey === 'completed') return 'done'
  if (stepIdx >= 0 && stepIdx < currentIdx) return 'done'
  if (stepKey === scan.status) return 'active'
  if (engineKey) return getEngineState(engineKey, scan)
  return 'pending'
}

function stepBg(state: StepState) {
  if (state === 'active')  return 'border-primary/30 bg-primary/5'
  if (state === 'done')    return 'border-green-500/20 bg-green-500/5'
  if (state === 'partial') return 'border-yellow-500/20 bg-yellow-500/5'
  if (state === 'skipped') return 'border-foreground/8 bg-foreground/2 opacity-50'
  if (state === 'failed')  return 'border-red-500/20 bg-red-500/5'
  return 'border-foreground/8 bg-foreground/2 opacity-40'
}
function iconBg(state: StepState) {
  if (state === 'active')  return 'bg-primary/15 text-primary'
  if (state === 'done')    return 'bg-green-500/15 text-green-500'
  if (state === 'partial') return 'bg-yellow-500/15 text-yellow-500'
  if (state === 'failed')  return 'bg-red-500/15 text-red-500'
  return 'bg-foreground/8 text-muted-foreground'
}
function labelColor(state: StepState) {
  if (state === 'active')  return 'text-primary'
  if (state === 'done')    return 'text-green-500'
  if (state === 'partial') return 'text-yellow-500'
  return 'text-muted-foreground'
}

function StepIcon({ state, Icon }: { state: StepState; Icon: React.ComponentType<{ className?: string }> }) {
  const cls = 'w-3.5 h-3.5'
  if (state === 'active')               return <Loader2 className={`${cls} animate-spin`} />
  if (state === 'done' || state === 'partial') return <CheckCircle2 className={cls} />
  return <Icon className={cls} />
}

function PipelineStep({ label, Icon, state, count }: {
  label: string
  Icon: React.ComponentType<{ className?: string }>
  state: StepState
  count?: number
}) {
  return (
    <div className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${stepBg(state)}`}>
      <div className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 ${iconBg(state)}`}>
        <StepIcon state={state} Icon={Icon} />
      </div>
      <div className="flex-1 min-w-0">
        <p className={`text-xs font-medium ${labelColor(state)}`}>{label}</p>
        {state === 'skipped' && <p className="text-[10px] text-muted-foreground/60">Skipped</p>}
        {state === 'partial' && <p className="text-[10px] text-yellow-500/80">Partial (timeout)</p>}
      </div>
      {count !== undefined && count > 0 && (
        <span className="text-[10px] font-bold text-muted-foreground bg-foreground/8 px-1.5 py-0.5 rounded">
          {count}
        </span>
      )}
    </div>
  )
}

function ParallelBlock({ scan }: { scan: FirestoreNetworkScan }) {
  const blockState = getStepState('parallel_analysis', null, scan)
  const isActive   = scan.status === 'parallel_analysis'
  const isDone     = ['completed', 'failed', 'cancelled'].includes(scan.status)

  const engines = [
    { key: 'cve_analysis',   label: 'CVE Correlation', Icon: ShieldAlert },
    { key: 'nuclei',         label: 'Nuclei',           Icon: Bug         },
    { key: 'network_checks', label: 'Network Checks',   Icon: Cpu         },
  ]

  return (
    <div className={`rounded-lg border transition-colors ${stepBg(blockState)}`}>
      <div className="flex items-center gap-3 p-3">
        <div className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 ${iconBg(blockState)}`}>
          <StepIcon state={blockState} Icon={GitBranch} />
        </div>
        <div className="flex-1">
          <p className={`text-xs font-medium ${labelColor(blockState)}`}>Parallel Analysis</p>
          {isActive && <p className="text-[10px] text-muted-foreground/70">All 3 engines running simultaneously</p>}
        </div>
      </div>
      {(isActive || isDone) && (
        <div className="px-3 pb-3 space-y-1.5">
          {engines.map(({ key, label, Icon }) => {
            const s   = getEngineState(key, scan)
            const eng = scan.engines?.[key as keyof typeof scan.engines]
            return (
              <div key={key} className={`flex items-center gap-2.5 px-2.5 py-2 rounded-md border transition-colors ${stepBg(s)}`}>
                <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 ${iconBg(s)}`}>
                  <StepIcon state={s} Icon={Icon} />
                </div>
                <p className={`text-[11px] font-medium flex-1 ${labelColor(s)}`}>{label}</p>
                {s === 'partial' && (
                  <span className="text-[9px] font-bold px-1 py-0.5 rounded border bg-yellow-500/10 text-yellow-500 border-yellow-500/20">PARTIAL</span>
                )}
                {s === 'skipped' && <span className="text-[9px] text-muted-foreground/60">Skipped</span>}
                {eng?.count !== undefined && eng.count > 0 && (
                  <span className="text-[10px] font-bold text-muted-foreground bg-foreground/8 px-1.5 py-0.5 rounded">{eng.count}</span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── SSE consumer — persists stream events into Firestore sub-collections ──

function useScanStream(uid: string, scanId: string, isActive: boolean) {
  const streamRef       = useRef<(() => void) | null>(null)
  const savedHostIds    = useRef(new Set<string>())
  const savedFindingIds = useRef(new Set<string>())
  const savedCveIds     = useRef(new Set<string>())

  useEffect(() => {
    if (!uid || !scanId || !isActive) return
    if (streamRef.current) return  // already consuming

    streamRef.current = openNetworkScanStream(
      scanId,
      async (payload: NetworkScanStreamPayload) => {
        // Update scan document
        try {
          await updateNetworkScan(uid, scanId, {
            status:        payload.status,
            progress:      payload.progress,
            currentStep:   payload.currentStep,
            logs:          payload.logs,
            totalHosts:    payload.live_hosts,
            liveHosts:     payload.live_hosts,
            totalFindings: payload.total_findings,
            totalCves:     payload.total_cves,
            engines:       payload.engines as any,
            ...(payload.error ? { error: payload.error } : {}),
          })
        } catch {}

        // Persist newly discovered hosts
        for (const h of payload.hosts ?? []) {
          if (!savedHostIds.current.has(h.hostId)) {
            savedHostIds.current.add(h.hostId)
            try { await writeNetworkHost(uid, h as FirestoreNetworkHost) } catch {}
          } else if ((h.ports ?? []).length > 0) {
            try {
              await updateDoc(doc(db, 'users', uid, 'network_assets', h.hostId), {
                ports: h.ports, isWebService: h.isWebService,
                webPorts: h.webPorts, technologies: h.technologies,
              })
            } catch {}
          }
        }

        // Persist new findings
        for (const f of payload.findings ?? []) {
          if (!savedFindingIds.current.has(f.findingId)) {
            savedFindingIds.current.add(f.findingId)
            try { await writeNetworkFinding(uid, f) } catch {}
          }
        }

        // Persist new CVEs
        for (const c of payload.cves ?? []) {
          if (!savedCveIds.current.has(c.id)) {
            savedCveIds.current.add(c.id)
            try { await writeNetworkCve(uid, c) } catch {}
          }
        }
      },
      async () => {
        // Final snapshot on completion
        try {
          const res = await fetch(`${API_BASE}/network/scan/${scanId}`)
          if (res.ok) {
            const data = await res.json()
            await updateNetworkScan(uid, scanId, {
              status: data.status, progress: 100,
              currentStep: data.currentStep, logs: data.logs,
              totalHosts: data.live_hosts, liveHosts: data.live_hosts,
              totalFindings: data.total_findings, totalCves: data.total_cves,
              duration: data.duration, engines: data.engines,
              completedAt: new Date().toISOString(),
            })
          }
        } catch {}
        streamRef.current = null
      },
      () => { streamRef.current = null },
    )

    return () => {
      streamRef.current?.()
      streamRef.current = null
    }
  }, [uid, scanId, isActive])
}

// ── Main page ─────────────────────────────────────────────────────────

export default function NetworkScanDetailPage() {
  const params   = useParams()
  const router   = useRouter()
  const { user } = useAuth()
  const scanId   = params.scanId as string

  const [scan,        setScan]       = useState<FirestoreNetworkScan | null>(null)
  const [loading,     setLoading]    = useState(true)
  const [stopping,    setStopping]   = useState(false)
  const [liveHosts,   setLiveHosts]  = useState<FirestoreNetworkHost[]>([])
  const [allFindings, setFindings]   = useState<FirestoreNetworkFinding[]>([])
  const [allCves,     setCves]       = useState<FirestoreNetworkCve[]>([])

  const isActive = scan ? NETWORK_ACTIVE_STATUSES.has(scan.status) : false

  // Firestore scan document listener (status, progress, logs, engines)
  useEffect(() => {
    if (!user) return
    return listenToNetworkScan(user.uid, scanId, (s) => {
      setScan(s); setLoading(false)
    })
  }, [user, scanId])

  // Sub-collection listeners — real data lives here, not in the scan doc
  useEffect(() => {
    if (!user) return
    return listenToNetworkHostsByScan(user.uid, scanId, setLiveHosts)
  }, [user, scanId])

  useEffect(() => {
    if (!user) return
    return listenToNetworkFindingsByScan(user.uid, scanId, setFindings)
  }, [user, scanId])

  useEffect(() => {
    if (!user) return
    return listenToNetworkCvesByScan(user.uid, scanId, setCves)
  }, [user, scanId])

  // SSE consumer — starts when scan is active, persists data to Firestore
  useScanStream(user?.uid ?? '', scanId, isActive)

  async function handleStop() {
    setStopping(true)
    try {
      const result = await cancelNetworkScan(scanId)

      if (!result.success) {
        toast.info(result.reason ?? 'Scan is no longer active')
        if (user) {
          await updateNetworkScan(user.uid, scanId, {
            status: 'cancelled',
            currentStep: result.reason ?? 'Cancelled',
          }).catch(() => {})
        }
        return
      }

      if (user) await updateNetworkScan(user.uid, scanId, { status: 'cancelled', currentStep: 'Cancelled' })
      toast.success('Scan stopped')
    } catch {
      toast.error('Failed to stop scan')
    } finally {
      setStopping(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="p-8 text-center">
        <p className="text-muted-foreground">Scan not found</p>
        <Button variant="ghost" onClick={() => router.push('/app/network-security')} className="mt-3">
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
      </div>
    )
  }

  const hdEng = scan.engines?.host_discovery
  const psEng = scan.engines?.port_scan

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      {/* Header */}
      <div className="flex items-start justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/app/network-security')}
          className="h-8 rounded-lg text-muted-foreground hover:text-foreground -ml-2">
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        {isActive && (
          <Button variant="outline" size="sm" onClick={handleStop} disabled={stopping}
            className="h-9 rounded-lg border-red-500/20 text-red-400 hover:bg-red-500/10 hover:text-red-400 gap-1.5">
            {stopping ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <StopCircle className="w-3.5 h-3.5" />}
            Stop Scan
          </Button>
        )}
      </div>

      {/* Scan summary */}
      <Card className="bg-card border-foreground/10">
        <CardContent className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
                <Wifi className="w-5 h-5 text-violet-400" />
              </div>
              <div>
                <p className="text-lg font-bold text-foreground font-mono">{scan.target}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className={`text-xs font-semibold ${STATUS_COLOR[scan.status] ?? 'text-muted-foreground'}`}>
                    {STATUS_LABEL[scan.status] ?? scan.status}
                  </span>
                  {scan.duration && <span className="text-xs text-muted-foreground">· {scan.duration}</span>}
                  <span className="text-xs text-muted-foreground">· {scan.scanProfile}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-5 shrink-0">
              <div className="text-right">
                <p className="text-xl font-bold text-foreground">{liveHosts.length}</p>
                <p className="text-[11px] text-muted-foreground">Live Hosts</p>
              </div>
              <div className="text-right">
                <p className="text-xl font-bold text-orange-400">{allFindings.length}</p>
                <p className="text-[11px] text-muted-foreground">Findings</p>
              </div>
              <div className="text-right">
                <p className="text-xl font-bold text-violet-400">{allCves.length}</p>
                <p className="text-[11px] text-muted-foreground">CVEs</p>
              </div>
            </div>
          </div>

          {isActive && (
            <div className="mt-4">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-muted-foreground">{scan.currentStep}</span>
                <span className="text-muted-foreground">{scan.progress}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-foreground/10 overflow-hidden">
                <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${scan.progress}%` }} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-3 gap-5">

        {/* Pipeline */}
        <div className="col-span-1">
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm font-semibold text-foreground">Pipeline</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              <PipelineStep label="Host Discovery"       Icon={Radio}         state={getStepState('host_discovery', 'host_discovery', scan)} count={hdEng?.count} />
              <PipelineStep label="Port Scan & Services" Icon={Network}        state={getStepState('port_scan', 'port_scan', scan)}           count={psEng?.count} />
              <ParallelBlock scan={scan} />
              <PipelineStep label="Completed"            Icon={CheckCircle2}  state={getStepState('completed', null, scan)} />
            </CardContent>
          </Card>
        </div>

        {/* Scan log */}
        <div className="col-span-2">
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm font-semibold text-foreground">Scan Log</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="bg-foreground/3 rounded-lg p-3 h-72 overflow-y-auto font-mono text-[11px] space-y-0.5">
                {(scan.logs ?? []).slice().reverse().map((log, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-muted-foreground/50 shrink-0 select-none">{log.timestamp}</span>
                    <span className="text-foreground/80 break-all">{log.message}</span>
                  </div>
                ))}
                {isActive && (
                  <div className="flex gap-2 text-primary/60">
                    <span className="text-muted-foreground/50 shrink-0">●</span>
                    <span className="animate-pulse">Scanning…</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Live Hosts — from network_assets sub-collection */}
      {liveHosts.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Server className="w-4 h-4 text-muted-foreground" />
              Live Hosts
              <span className="text-xs font-normal text-muted-foreground ml-1">({liveHosts.length})</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4 space-y-2">
            {liveHosts.map((host) => (
              <div key={host.hostId} className="flex items-start justify-between p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-mono font-semibold text-foreground">{host.ip}</span>
                    {host.hostname && <span className="text-xs text-muted-foreground">({host.hostname})</span>}
                    {host.isWebService && (
                      <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-blue-500/10 text-blue-400 border-blue-500/20">Web</span>
                    )}
                  </div>
                  {host.ports.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {host.ports.slice(0, 12).map((p) => (
                        <span key={p.port} className="text-[10px] px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground border border-foreground/10">
                          {p.port}/{p.service}
                        </span>
                      ))}
                      {host.ports.length > 12 && <span className="text-[10px] text-muted-foreground">+{host.ports.length - 12}</span>}
                    </div>
                  )}
                  {host.technologies.length > 0 && (
                    <p className="text-[11px] text-muted-foreground mt-1">{host.technologies.join(', ')}</p>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Findings — from network_findings sub-collection, live */}
      {allFindings.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Findings
              <span className="text-xs font-normal text-muted-foreground ml-1">({allFindings.length})</span>
              {isActive && (
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-primary/10 text-primary border-primary/20 ml-1">LIVE</span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4 space-y-2">
            {allFindings.slice(0, 25).map((f) => (
              <div key={f.findingId} className="flex items-start gap-3 p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${SEV_BADGE[f.severity] ?? SEV_BADGE.info}`}>
                  {(f.severity ?? 'info').toUpperCase()}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">{f.title}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs text-muted-foreground font-mono">{f.ip}</span>
                    {f.port && <span className="text-xs text-muted-foreground">:{f.port}</span>}
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground">{f.source}</span>
                  </div>
                  {f.description && (
                    <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2">{f.description}</p>
                  )}
                </div>
              </div>
            ))}
            {allFindings.length > 25 && (
              <p className="text-xs text-muted-foreground text-center pt-1">
                +{allFindings.length - 25} more — view all on the Findings page
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* CVEs — from network_cves sub-collection, live */}
      {allCves.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Bug className="w-4 h-4 text-violet-400" />
              CVE Intelligence
              <span className="text-xs font-normal text-muted-foreground ml-1">({allCves.length})</span>
              {isActive && (
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-primary/10 text-primary border-primary/20 ml-1">LIVE</span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4 space-y-2">
            {allCves.slice(0, 20).map((c) => (
              <div key={c.id} className="flex items-center gap-3 p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <span className="text-xs font-bold text-violet-400 font-mono shrink-0 w-32 truncate">{c.cveId}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-foreground truncate">{c.technology} {c.version}</p>
                  <p className="text-[11px] text-muted-foreground font-mono">{c.ip}:{c.port}</p>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-sm font-bold text-foreground">{c.cvssScore?.toFixed(1)}</p>
                  <p className="text-[10px] text-muted-foreground">CVSS</p>
                </div>
                {c.exploitAvailable && (
                  <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-red-500/10 text-red-400 border-red-500/20 shrink-0">
                    EXPLOIT
                  </span>
                )}
              </div>
            ))}
            {allCves.length > 20 && (
              <p className="text-xs text-muted-foreground text-center pt-1">
                +{allCves.length - 20} more — view all on the CVEs page
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
