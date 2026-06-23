'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, CheckCircle2, Clock, AlertTriangle, StopCircle, RotateCcw,
  Network, Cpu, Bug, ShieldAlert, Globe, Zap, ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  getFirestoreScan,
  updateFirestoreScan,
  createFirestoreScan,
  ACTIVE_STATUSES,
  type FirestoreScan,
  type EngineState,
} from '@/lib/firestore-scans'
import { getScanStatus, cancelScan, restartScan, API_BASE } from '@/lib/api'
import { useAuth } from '@/context/auth-context'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500',
  high:     'bg-orange-500/10 text-orange-500',
  medium:   'bg-yellow-500/10 text-yellow-500',
  low:      'bg-blue-500/10 text-blue-500',
  info:     'bg-gray-500/10 text-gray-400',
  unknown:  'bg-gray-500/10 text-gray-400',
}

const STATUS_COLOR: Record<string, string> = {
  completed:              'text-green-500',
  failed:                 'text-red-500',
  cancelled:              'text-gray-400',
  queued:                 'text-yellow-500',
  initializing:           'text-blue-400',
  running:                'text-blue-400',
  processing:             'text-purple-400',
  saving:                 'text-teal-400',
  discovering_assets:     'text-violet-400',
  validating_assets:      'text-cyan-400',
  scanning_assets:        'text-blue-400',
  detecting_technologies: 'text-orange-400',
  cve_analysis:           'text-red-400',
}

const STATUS_LABEL: Record<string, string> = {
  discovering_assets:     'Discovering Assets',
  validating_assets:      'Technology Detection',
  scanning_assets:        'Running Engines',
  detecting_technologies: 'Tech Stack Summary',
  cve_analysis:           'CVE Analysis',
  completed:              'Completed',
  failed:                 'Failed',
  cancelled:              'Cancelled',
  queued:                 'Queued',
  initializing:           'Initializing',
  running:                'Running',
  processing:             'Processing',
  saving:                 'Saving',
}

// Quick Scan pipeline steps
const QUICK_STEPS = [
  { key: 'queued',       label: 'Queued' },
  { key: 'initializing', label: 'Initializing' },
  { key: 'running',      label: 'Running' },
  { key: 'processing',   label: 'Processing' },
  { key: 'saving',       label: 'Saving' },
  { key: 'completed',    label: 'Completed' },
]

// Full Scan pipeline — 7 displayed stages
// engineKey identifies which engines object key to consult for state
interface FullStep {
  displayKey:  string   // unique display key
  label:       string
  icon:        React.ComponentType<{ className?: string }>
  stageKey?:   string   // the scan.status value this stage corresponds to
  engineKey?:  string   // scan.engines[engineKey]
  isParallel?: boolean  // visually indented sub-step
}

const FULL_STEPS: FullStep[] = [
  { displayKey: 'discovering_assets',     label: 'Asset Discovery',          icon: Network,     stageKey: 'discovering_assets' },
  { displayKey: 'validating_assets',      label: 'Technology Detection',     icon: Cpu,         stageKey: 'validating_assets' },
  { displayKey: 'engine_nuclei',          label: 'Nuclei Scanner',           icon: Bug,         stageKey: 'scanning_assets', engineKey: 'nuclei',        isParallel: true },
  { displayKey: 'engine_vectra',          label: 'Vectra Security Checks',   icon: ShieldCheck, stageKey: 'scanning_assets', engineKey: 'vectra_checks', isParallel: true },
  { displayKey: 'engine_wpscan',          label: 'WPScan',                   icon: Globe,       stageKey: 'scanning_assets', engineKey: 'wpscan',        isParallel: true },
  { displayKey: 'engine_cve',             label: 'CVE Analysis',             icon: ShieldAlert, stageKey: 'scanning_assets', engineKey: 'cve_analysis',  isParallel: true },
  { displayKey: 'completed',              label: 'Completed',                icon: CheckCircle2, stageKey: 'completed' },
]

// Ordered list of scan statuses for progress computation
const STAGE_ORDER = [
  'discovering_assets', 'validating_assets', 'scanning_assets', 'completed',
]

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const router = useRouter()
  const { user } = useAuth()
  const [scan, setScan] = useState<FirestoreScan | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)

  const isFullScan = scan?.scanProfile === 'FULL_SCAN'

  useEffect(() => {
    if (!user) return
    getFirestoreScan(user.uid, scanId).then((s) => {
      if (s) setScan(s)
      else setNotFound(true)
    })
  }, [user, scanId])

  // SSE — drives local UI state; ScanSyncContext handles Firestore writes
  useEffect(() => {
    if (!user || !scan) return
    if (!ACTIVE_STATUSES.has(scan.status)) return

    const es = new EventSource(`${API_BASE}/scan/${scanId}/stream`)

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string)
        if (data.done && !data.status) { es.close(); return }

        const updates: Partial<FirestoreScan> = {
          status:            data.status,
          progress:          data.progress,
          currentStep:       data.currentStep,
          findings:          data.findings ?? [],
          totalFindings:     data.total_findings ?? 0,
          logs:              data.logs ?? [],
          templatesExecuted: data.templatesExecuted ?? 0,
          duration:          data.duration ?? undefined,
          error:             data.error ?? undefined,
          totalAssets:      data.total_assets ?? undefined,
          liveAssetsCount:  data.live_assets_count ?? undefined,
          totalCves:        data.total_cves ?? undefined,
          engines:          data.engines ?? undefined,
        }
        if (!ACTIVE_STATUSES.has(data.status)) {
          updates.completedAt = new Date().toISOString()
        }
        setScan((prev) => (prev ? { ...prev, ...updates } : prev))
        if (!ACTIVE_STATUSES.has(data.status) || data.done) es.close()
      } catch { /* ignore */ }
    }

    es.onerror = () => {
      es.close()
      getScanStatus(scanId).then((state) => {
        setScan((prev) => prev ? {
          ...prev,
          status: state.status, progress: state.progress,
          currentStep: state.currentStep, findings: state.findings,
          totalFindings: state.total_findings, logs: state.logs,
        } : prev)
      }).catch(() => {})
    }

    return () => es.close()
  }, [user, scanId, scan?.status])

  async function handleStop() {
    if (!user || !scan) return
    setActionLoading(true)
    try {
      await cancelScan(scanId)
      const updates: Partial<FirestoreScan> = { status: 'cancelled', currentStep: 'Cancelled' }
      setScan((prev) => (prev ? { ...prev, ...updates } : prev))
      await updateFirestoreScan(user.uid, scanId, updates)
      toast.success('Scan stopped')
    } catch (err) {
      toast.error('Failed to stop scan', { description: err instanceof Error ? err.message : undefined })
    } finally {
      setActionLoading(false)
    }
  }

  async function handleRestart() {
    if (!user || !scan) return
    setActionLoading(true)
    try {
      const result = await restartScan(scanId)
      await createFirestoreScan(user.uid, {
        scanId:        result.scanId,
        target:        scan.target,
        scanType:      scan.scanType,
        scanProfile:   result.scanProfile ?? scan.scanProfile,
        status:        'queued',
        progress:      0,
        currentStep:   'Queued',
        logs:          [{ timestamp: new Date().toLocaleTimeString(), message: 'Scan Created (Restarted)' }],
        findings:      [],
        totalFindings: 0,
        createdAt:     new Date().toISOString(),
      })
      toast.success('Scan restarted')
      router.push(`/app/scans/${result.scanId}`)
    } catch (err) {
      toast.error('Failed to restart scan', { description: err instanceof Error ? err.message : undefined })
    } finally {
      setActionLoading(false)
    }
  }

  // ── Stage state computation ──────────────────────────────────────────

  function stageState(step: FullStep): 'done' | 'active' | 'failed' | 'cancelled' | 'pending' | 'skipped' {
    if (!scan) return 'pending'
    const scanStatus = scan.status

    // Handle engine sub-steps
    if (step.engineKey) {
      const engine = scan.engines?.[step.engineKey as keyof typeof scan.engines] as EngineState | undefined
      const scanIdx  = STAGE_ORDER.indexOf(scanStatus)
      const scanningIdx = STAGE_ORDER.indexOf('scanning_assets')

      if (engine) {
        const es = engine.status
        if (es === 'completed') return 'done'
        if (es === 'running')   return 'active'
        if (es === 'failed')    return 'failed'
        if (es === 'cancelled') return 'cancelled'
        if (es === 'skipped')   return 'skipped'
      }
      // No engine state yet
      if (scanStatus === 'completed') return 'done'
      if (scanIdx > scanningIdx) return 'done'
      if (scanIdx === scanningIdx) return 'pending'
      return 'pending'
    }

    // Regular stage step
    const stageKey = step.stageKey!
    if (scanStatus === 'completed') return 'done'
    if (scanStatus === 'failed') {
      if (stageKey === 'completed') return 'failed'
      return 'pending'
    }
    if (scanStatus === 'cancelled') {
      if (stageKey === 'completed') return 'cancelled'
      return 'pending'
    }
    const scanIdx  = STAGE_ORDER.indexOf(scanStatus)
    const stepIdx  = STAGE_ORDER.indexOf(stageKey)
    if (stepIdx < 0) return 'pending'
    if (scanIdx > stepIdx) return 'done'
    if (scanIdx === stepIdx) return 'active'
    return 'pending'
  }

  // ── Quick Scan state ─────────────────────────────────────────────────

  const quickOrder = QUICK_STEPS.map((s) => s.key)
  const quickIdx   = scan ? quickOrder.indexOf(scan.status) : -1

  function quickStepState(key: string): 'done' | 'active' | 'failed' | 'cancelled' | 'pending' {
    if (!scan) return 'pending'
    if (scan.status === 'completed') return 'done'
    const idx = quickOrder.indexOf(key)
    if (idx < 0) return 'pending'
    if (idx < quickIdx) return 'done'
    if (idx === quickIdx && ACTIVE_STATUSES.has(scan.status)) return 'active'
    if (scan.status === 'failed' && key === 'completed') return 'failed'
    if (scan.status === 'cancelled' && key === 'completed') return 'cancelled'
    return 'pending'
  }

  if (notFound) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <p className="text-muted-foreground">Scan not found.</p>
      </div>
    )
  }
  if (!scan) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
      </div>
    )
  }

  const isActive    = ACTIVE_STATUSES.has(scan.status)
  const isCancelled = scan.status === 'cancelled' || scan.status === 'failed'
  const statusLabel = STATUS_LABEL[scan.status] ?? scan.status.replace(/_/g, ' ')

  const severityCounts = scan.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="p-8 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.push('/app/scans')} className="rounded-lg">
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Scan Details</h1>
            <p className="text-muted-foreground text-xs font-mono mt-0.5">{scan.scanId}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {isActive && (
            <Button
              variant="outline" size="sm" disabled={actionLoading}
              className="rounded-lg border-destructive/30 text-destructive hover:bg-destructive/10 gap-1.5"
              onClick={handleStop}
            >
              <StopCircle className="w-4 h-4" />Stop
            </Button>
          )}
          {isCancelled && (
            <Button
              variant="outline" size="sm" disabled={actionLoading}
              className="rounded-lg border-blue-500/30 text-blue-400 hover:bg-blue-500/10 gap-1.5"
              onClick={handleRestart}
            >
              <RotateCcw className="w-4 h-4" />Restart
            </Button>
          )}
        </div>
      </div>

      {/* Summary cards */}
      {isFullScan ? (
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
          <Card className="bg-card border-foreground/10 sm:col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Target Domain</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="font-mono text-sm text-foreground break-all">{scan.target}</div>
              <div className="text-xs text-muted-foreground mt-1">Full Scan — Security Orchestration</div>
            </CardContent>
          </Card>
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`font-semibold text-sm ${STATUS_COLOR[scan.status] ?? 'text-foreground'}`}>
                {statusLabel}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5 truncate">{scan.currentStep}</div>
            </CardContent>
          </Card>
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Assets</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{scan.totalAssets ?? 0}</div>
              {scan.liveAssetsCount != null && (
                <div className="text-xs text-green-500 mt-0.5">{scan.liveAssetsCount} live</div>
              )}
            </CardContent>
          </Card>
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{scan.totalFindings}</div>
              {scan.templatesExecuted != null && scan.templatesExecuted > 0 && (
                <div className="text-xs text-muted-foreground mt-0.5">{scan.templatesExecuted} templates</div>
              )}
            </CardContent>
          </Card>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <Card className="bg-card border-foreground/10 sm:col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Target</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="font-mono text-sm text-foreground break-all">{scan.target}</div>
              <div className="text-xs text-muted-foreground mt-1">Quick Scan — Nuclei</div>
            </CardContent>
          </Card>
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`font-semibold capitalize ${STATUS_COLOR[scan.status] ?? 'text-foreground'}`}>
                {scan.status}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">{scan.currentStep}</div>
            </CardContent>
          </Card>
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{scan.totalFindings}</div>
              {scan.templatesExecuted != null && scan.templatesExecuted > 0 && (
                <div className="text-xs text-muted-foreground mt-0.5">
                  {scan.templatesExecuted} template{scan.templatesExecuted !== 1 ? 's' : ''}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* CVEs card */}
      {isFullScan && (
        (scan.totalCves != null && scan.totalCves > 0) ||
        scan.status === 'scanning_assets' ||
        scan.status === 'completed'
      ) && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2 pt-4 px-6">
            <CardTitle className="text-xs font-medium text-muted-foreground">CVE Intelligence</CardTitle>
          </CardHeader>
          <CardContent className="pb-4 px-6">
            <div className="flex items-center gap-4">
              <div>
                <div className="text-2xl font-bold text-foreground">{scan.totalCves ?? 0}</div>
                <div className="text-xs text-muted-foreground">CVEs correlated</div>
              </div>
              <Button
                variant="ghost" size="sm"
                className="h-8 rounded-lg text-primary hover:bg-primary/10 text-xs ml-auto"
                onClick={() => router.push('/app/cves')}
              >
                View CVEs →
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Pipeline visualization */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">
              {isFullScan ? 'Security Orchestration Pipeline' : 'Scan Pipeline'}
            </CardTitle>
            <div className="flex items-center gap-3">
              {scan.duration && (
                <span className="text-xs text-muted-foreground">Duration: {scan.duration}</span>
              )}
              {isActive && <span className="text-xs text-primary animate-pulse">● Live</span>}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isFullScan ? (
            <div className="space-y-0.5">
              {FULL_STEPS.map((step, idx) => {
                const state   = stageState(step)
                const Icon    = step.icon
                const isLast  = idx === FULL_STEPS.length - 1
                const nextIsParallel = !isLast && FULL_STEPS[idx + 1].isParallel
                const prevIsParallel = idx > 0 && FULL_STEPS[idx - 1].isParallel

                const engine = step.engineKey
                  ? (scan.engines?.[step.engineKey as keyof typeof scan.engines] as EngineState | undefined)
                  : undefined

                // Color scheme per state
                const dotCls =
                  state === 'done'      ? 'bg-green-500/15 border-green-500/40 text-green-400' :
                  state === 'active'    ? 'bg-primary/15 border-primary/40 text-primary animate-pulse' :
                  state === 'failed'    ? 'bg-red-500/15 border-red-500/40 text-red-400' :
                  state === 'cancelled' ? 'bg-gray-500/15 border-gray-500/40 text-gray-400' :
                  state === 'skipped'   ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-600' :
                  'bg-foreground/5 border-foreground/10 text-muted-foreground'

                const labelCls =
                  state === 'done'      ? 'text-green-400' :
                  state === 'active'    ? 'text-primary' :
                  state === 'failed'    ? 'text-red-400' :
                  state === 'skipped'   ? 'text-yellow-600/80' :
                  'text-muted-foreground'

                const lineColor = state === 'done' ? 'bg-green-500/30' : 'bg-foreground/10'

                return (
                  <div key={step.displayKey} className={`flex items-start gap-3 ${step.isParallel ? 'ml-8' : ''}`}>
                    <div className="flex flex-col items-center">
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 border transition-all ${dotCls}`}>
                        {state === 'done' ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : state === 'skipped' ? (
                          <span className="text-[10px] font-bold">–</span>
                        ) : (
                          <Icon className="w-3.5 h-3.5" />
                        )}
                      </div>
                      {!isLast && (
                        <div className={`w-px mt-0.5 ${step.isParallel ? 'h-4' : 'h-5'} ${lineColor}`} />
                      )}
                    </div>
                    <div className="flex-1 pb-1 pt-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-sm font-medium ${labelCls}`}>{step.label}</span>
                        {state === 'active' && !step.engineKey && (
                          <span className="text-xs text-primary/70">{scan.progress}%</span>
                        )}
                        {state === 'skipped' && (
                          <span className="text-[10px] text-muted-foreground border border-foreground/10 rounded px-1.5 py-0.5">skipped</span>
                        )}
                        {engine && state !== 'pending' && state !== 'skipped' && (
                          <span className="text-xs text-muted-foreground">
                            {engine.findingCount > 0 ? `${engine.findingCount} finding${engine.findingCount !== 1 ? 's' : ''}` : ''}
                          </span>
                        )}
                        {step.isParallel && state === 'pending' && scan.status === 'scanning_assets' && (
                          <span className="text-xs text-muted-foreground animate-pulse">starting…</span>
                        )}
                      </div>
                      {state === 'active' && !step.engineKey && scan.progress != null && (
                        <div className="mt-1 h-1 w-44 bg-foreground/10 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary rounded-full transition-all duration-500"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="flex items-center gap-1 flex-wrap">
              {QUICK_STEPS.map((step, idx) => {
                const state = quickStepState(step.key)
                return (
                  <div key={step.key} className="flex items-center gap-1">
                    <div className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
                      state === 'failed'    ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                      state === 'cancelled' ? 'bg-gray-500/15 text-gray-400 border border-gray-500/30' :
                      state === 'done'     ? 'bg-green-500/15 text-green-400 border border-green-500/30' :
                      state === 'active'   ? 'bg-primary/15 text-primary border border-primary/40 animate-pulse' :
                      'bg-foreground/5 text-muted-foreground border border-foreground/10'
                    }`}>
                      {step.label}
                    </div>
                    {idx < QUICK_STEPS.length - 1 && (
                      <div className={`w-4 h-px ${state === 'done' ? 'bg-green-500/40' : 'bg-foreground/10'}`} />
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {scan.completedAt && (
            <p className="text-xs text-muted-foreground mt-4">
              Completed {new Date(scan.completedAt).toLocaleString()}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Engine breakdown — Full Scan only, during or after scanning */}
      {isFullScan && scan.engines && Object.keys(scan.engines).length > 0 && (
        (scan.status === 'scanning_assets' || STAGE_ORDER.indexOf(scan.status) > STAGE_ORDER.indexOf('scanning_assets') || scan.status === 'completed') && (
          <Card className="bg-card border-foreground/10">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Engine Results</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                {[
                  { key: 'nuclei',        label: 'Nuclei',         icon: Bug,         color: 'text-blue-400' },
                  { key: 'vectra_checks', label: 'Vectra Checks',  icon: ShieldCheck, color: 'text-violet-400' },
                  { key: 'wpscan',        label: 'WPScan',         icon: Globe,       color: 'text-green-400' },
                  { key: 'cve_analysis',  label: 'CVE Analysis',   icon: ShieldAlert, color: 'text-orange-400' },
                ].map(({ key, label, icon: Icon, color }) => {
                  const eng = scan.engines?.[key as keyof typeof scan.engines] as EngineState | undefined
                  const st = eng?.status ?? 'pending'
                  const n  = eng?.findingCount ?? 0
                  return (
                    <div key={key} className="p-3 rounded-lg border border-foreground/10 bg-foreground/2">
                      <div className="flex items-center gap-2 mb-2">
                        <Icon className={`w-4 h-4 ${color}`} />
                        <span className="text-sm font-medium text-foreground">{label}</span>
                      </div>
                      <div className={`text-xs font-semibold capitalize ${
                        st === 'completed' ? 'text-green-400' :
                        st === 'running'   ? 'text-primary' :
                        st === 'failed'    ? 'text-red-400' :
                        st === 'skipped'   ? 'text-yellow-500' :
                        'text-muted-foreground'
                      }`}>
                        {st === 'running' ? <span className="animate-pulse">{st}</span> : st}
                      </div>
                      {st !== 'skipped' && st !== 'pending' && (
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {key === 'cve_analysis'
                            ? `${scan.totalCves ?? n} CVE${(scan.totalCves ?? n) !== 1 ? 's' : ''}`
                            : `${n} finding${n !== 1 ? 's' : ''}`}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        )
      )}

      {/* Severity breakdown */}
      {scan.totalFindings > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Findings by Severity</CardTitle>
              <Button
                variant="ghost" size="sm"
                className="h-8 rounded-lg text-primary hover:bg-primary/10 text-xs"
                onClick={() => router.push(`/app/findings/${scanId}`)}
              >
                View All →
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = severityCounts[sev] ?? 0
                if (count === 0) return null
                return (
                  <span
                    key={sev}
                    className={`text-xs font-semibold px-3 py-1.5 rounded-lg ${SEVERITY_COLORS[sev]}`}
                  >
                    {count} {sev}
                  </span>
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live logs */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Scan Logs</CardTitle>
            {isActive && <span className="text-xs text-primary animate-pulse">● Live</span>}
          </div>
        </CardHeader>
        <CardContent>
          {scan.logs.length === 0 ? (
            <p className="text-sm text-muted-foreground">No logs yet…</p>
          ) : (
            <div className="space-y-2.5 font-mono text-xs max-h-80 overflow-y-auto">
              {scan.logs.map((log, i) => {
                const isLast = i === scan.logs.length - 1
                return (
                  <div key={i} className="flex items-start gap-3">
                    {isLast && isActive ? (
                      <Clock className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5 animate-pulse" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-500/70 shrink-0 mt-0.5" />
                    )}
                    <span className="text-muted-foreground shrink-0">[{log.timestamp}]</span>
                    <span className={`${
                      log.message.includes('[CVE]')   ? 'text-orange-400' :
                      log.message.includes('[Nuclei]') ? 'text-blue-400' :
                      log.message.includes('[Vectra]') ? 'text-violet-400' :
                      log.message.includes('[WPScan]') ? 'text-green-400' :
                      log.message.includes('[Engine]') ? 'text-cyan-400' :
                      'text-foreground'
                    }`}>{log.message}</span>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Error banner */}
      {scan.error && (
        <Card className="bg-red-500/5 border-red-500/20">
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <p className="text-sm text-red-400">{scan.error}</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
