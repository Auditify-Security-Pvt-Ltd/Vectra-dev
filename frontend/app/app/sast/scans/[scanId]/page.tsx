'use client'

import { useEffect, useRef, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, Code2, Key, Package, ShieldAlert, FileCode2,
  CheckCircle2, XCircle, Loader2, Clock, AlertTriangle,
  ChevronDown, ChevronRight, ExternalLink, StopCircle,
  RefreshCcw, Shield,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { useAuth } from '@/context/auth-context'
import {
  listenToSastScan, updateSastScan, type FirestoreSastScan, SAST_ACTIVE_STATUSES,
} from '@/lib/firestore-sast-scans'
import {
  listenToSastFindingsByScan, writeSastFindings, type FirestoreSastFinding,
} from '@/lib/firestore-sast-findings'
import { openSastStream, cancelSastScan, type SastStreamPayload } from '@/lib/api-sast'

// ── Severity helpers ──────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-foreground/10 text-muted-foreground border-foreground/15',
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-blue-500',
  info:     'bg-foreground/30',
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border capitalize ${SEV_COLORS[sev] ?? SEV_COLORS.info}`}>
      {sev}
    </span>
  )
}

// ── Category badge ────────────────────────────────────────────────────

function CatBadge({ cat }: { cat: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    secret:     { label: 'Secret',     cls: 'bg-red-500/10 text-red-400 border-red-500/20' },
    owasp:      { label: 'OWASP',      cls: 'bg-violet-500/10 text-violet-400 border-violet-500/20' },
    dependency: { label: 'Dependency', cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' },
  }
  const { label, cls } = map[cat] ?? { label: cat, cls: 'bg-foreground/10 text-muted-foreground border-foreground/15' }
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${cls}`}>
      {label}
    </span>
  )
}

// ── Stage row ─────────────────────────────────────────────────────────

function StageRow({ label, status }: { label: string; status: string }) {
  return (
    <div className="flex items-center gap-2.5 py-1.5">
      {status === 'completed' && <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />}
      {status === 'running'   && <Loader2     className="w-3.5 h-3.5 text-blue-400 animate-spin shrink-0" />}
      {status === 'pending'   && <div className="w-3.5 h-3.5 rounded-full border border-foreground/20 shrink-0" />}
      {status === 'failed'    && <XCircle     className="w-3.5 h-3.5 text-red-400 shrink-0" />}
      <span className={`text-xs ${status === 'completed' ? 'text-foreground' : status === 'running' ? 'text-blue-400' : 'text-muted-foreground'}`}>
        {label}
      </span>
    </div>
  )
}

// ── Finding row ───────────────────────────────────────────────────────

function FindingRow({ f }: { f: FirestoreSastFinding }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <tr
        className="border-b border-foreground/8 hover:bg-foreground/5 transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full shrink-0 ${SEV_DOT[f.severity] ?? 'bg-foreground/30'}`} />
            <SevBadge sev={f.severity} />
          </div>
        </td>
        <td className="px-4 py-3 max-w-xs">
          <p className="text-xs font-medium text-foreground truncate">{f.title}</p>
          <p className="text-[10px] text-muted-foreground truncate mt-0.5">{f.type}</p>
        </td>
        <td className="px-4 py-3">
          <p className="text-[10px] font-mono text-muted-foreground truncate max-w-[200px]">{f.file}</p>
          {f.line > 0 && <p className="text-[10px] text-muted-foreground/60">line {f.line}</p>}
        </td>
        <td className="px-4 py-3"><CatBadge cat={f.category} /></td>
        <td className="px-4 py-3">
          <span className="text-[10px] font-mono text-violet-400">{f.cweId}</span>
        </td>
        <td className="px-4 py-3">
          {f.owaspCategory ? (
            <span className="text-[10px] text-muted-foreground">{f.owaspCategory.split('–')[0].trim()}</span>
          ) : '—'}
        </td>
        <td className="px-4 py-3 text-right">
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground inline" />
            : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground inline" />}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-foreground/8 bg-foreground/[0.02]">
          <td colSpan={7} className="px-4 pb-4 pt-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="space-y-2">
                <div>
                  <p className="text-muted-foreground font-semibold mb-1">Description</p>
                  <p className="text-foreground/80 leading-relaxed">{f.description}</p>
                </div>
                {f.code && (
                  <div>
                    <p className="text-muted-foreground font-semibold mb-1">Code Snippet</p>
                    <pre className="bg-foreground/5 border border-foreground/10 rounded-lg p-3 font-mono text-[10px] text-foreground/80 overflow-x-auto whitespace-pre-wrap break-all">
                      {f.code}
                    </pre>
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <div>
                  <p className="text-muted-foreground font-semibold mb-1">Recommendation</p>
                  <p className="text-foreground/80 leading-relaxed">{f.recommendation}</p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-foreground/5 border border-foreground/10 rounded-lg p-2.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5">CWE</p>
                    <p className="font-mono text-violet-400 font-semibold">{f.cweId}</p>
                    <p className="text-foreground/70 text-[10px] mt-0.5 leading-tight">{f.cweName}</p>
                  </div>
                  {f.owaspCategory && (
                    <div className="bg-foreground/5 border border-foreground/10 rounded-lg p-2.5">
                      <p className="text-muted-foreground text-[10px] mb-0.5">OWASP 2021</p>
                      <p className="text-foreground/70 text-[10px] leading-tight">{f.owaspCategory}</p>
                    </div>
                  )}
                </div>
                {f.category === 'dependency' && f.cveId && (
                  <div className="bg-foreground/5 border border-foreground/10 rounded-lg p-2.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5">CVE / Dependency</p>
                    <p className="font-mono text-red-400 font-semibold text-[10px]">{f.cveId}</p>
                    <p className="text-muted-foreground text-[10px]">
                      {f.dependencyName}@{f.dependencyVersion}
                      {f.cvssScore != null && ` · CVSS ${f.cvssScore.toFixed(1)}`}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Category tab ──────────────────────────────────────────────────────

type TabFilter = 'all' | 'secret' | 'owasp' | 'dependency'

// ── Main page ─────────────────────────────────────────────────────────

export default function SastScanDetailPage() {
  const { scanId }  = useParams<{ scanId: string }>()
  const { user }    = useAuth()
  const router      = useRouter()

  const [scan, setScan]         = useState<FirestoreSastScan | null>(null)
  const [findings, setFindings] = useState<FirestoreSastFinding[]>([])
  const [tab, setTab]           = useState<TabFilter>('all')
  const [streaming, setStreaming] = useState(false)
  const [sseError, setSseError] = useState<string | null>(null)

  const closeRef = useRef<(() => void) | null>(null)
  const wroteRef = useRef(false)

  // Listen to Firestore scan doc
  useEffect(() => {
    if (!user) return
    return listenToSastScan(user.organizationId, scanId, setScan)
  }, [user, scanId])

  // Listen to Firestore findings
  useEffect(() => {
    if (!user) return
    return listenToSastFindingsByScan(user.organizationId, scanId, setFindings)
  }, [user, scanId])

  // Connect to SSE when scan is running or queued
  useEffect(() => {
    if (!user || !scan) return
    if (!SAST_ACTIVE_STATUSES.has(scan.status)) return
    if (streaming) return

    setStreaming(true)
    setSseError(null)
    wroteRef.current = false

    const close = openSastStream(
      scanId,
      // onEvent — update Firestore scan metadata
      async (payload: SastStreamPayload) => {
        await updateSastScan(user.organizationId, scanId, {
          status:           payload.status as any,
          progress:         payload.progress,
          currentStep:      payload.currentStep,
          language:         payload.language,
          totalFiles:       payload.totalFiles,
          totalFindings:    payload.totalFindings,
          criticalFindings: payload.criticalFindings,
          highFindings:     payload.highFindings,
          mediumFindings:   payload.mediumFindings,
          lowFindings:      payload.lowFindings,
          secretFindings:   payload.secretFindings,
          dependencyVulns:  payload.dependencyVulns,
          stages:           payload.stages as any,
          duration:         payload.duration,
          error:            payload.error,
        })
      },
      // onDone — write final state + all findings to Firestore
      async (payload: SastStreamPayload) => {
        if (wroteRef.current) return
        wroteRef.current = true
        setStreaming(false)

        const now = new Date().toISOString()
        const fsList: FirestoreSastFinding[] = (payload.findings || []).map((f: any) => ({
          ...f,
          createdAt: f.createdAt || now,
        }))

        await Promise.all([
          updateSastScan(user.organizationId, scanId, {
            status:           payload.status as any,
            progress:         100,
            currentStep:      payload.currentStep,
            language:         payload.language,
            totalFiles:       payload.totalFiles,
            totalFindings:    payload.totalFindings,
            criticalFindings: payload.criticalFindings,
            highFindings:     payload.highFindings,
            mediumFindings:   payload.mediumFindings,
            lowFindings:      payload.lowFindings,
            secretFindings:   payload.secretFindings,
            dependencyVulns:  payload.dependencyVulns,
            stages:           payload.stages as any,
            duration:         payload.duration,
            error:            payload.error,
            completedAt:      new Date().toISOString(),
          }),
          writeSastFindings(user.organizationId, fsList),
        ])
      },
      // onError
      (err) => {
        setStreaming(false)
        setSseError(err.message)
      },
    )

    closeRef.current = close
    return () => {
      close()
      closeRef.current = null
    }
  }, [user, scan?.status, scanId]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleCancel() {
    if (!user || !scan) return
    try {
      await cancelSastScan(scanId)
      closeRef.current?.()
      await updateSastScan(user.organizationId, scanId, {
        status: 'cancelled', currentStep: 'Scan cancelled', completedAt: new Date().toISOString(),
      })
      toast.success('Scan cancelled')
    } catch {
      toast.error('Failed to cancel scan')
    }
  }

  // ── Tab filter ────────────────────────────────────────────────────

  const visible = tab === 'all' ? findings : findings.filter((f) => f.category === tab)

  const counts = {
    all:        findings.length,
    secret:     findings.filter((f) => f.category === 'secret').length,
    owasp:      findings.filter((f) => f.category === 'owasp').length,
    dependency: findings.filter((f) => f.category === 'dependency').length,
  }

  // ── Loading state ─────────────────────────────────────────────────

  if (!scan) {
    return (
      <div className="flex items-center justify-center h-full py-32">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  const isActive = SAST_ACTIVE_STATUSES.has(scan.status)

  const STAGE_LABELS: Record<string, string> = {
    language_detection:  'Language Detection',
    secret_detection:    'Secret Detection',
    dependency_analysis: 'Dependency Analysis',
    owasp_analysis:      'OWASP Analysis',
    cwe_mapping:         'CWE Mapping',
    cve_correlation:     'CVE Correlation',
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <Button variant="ghost" size="icon" className="h-8 w-8 mt-0.5" onClick={() => router.push('/app/sast')}>
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold text-foreground">{scan.projectName}</h1>
              <span className="text-xs px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-400 border border-violet-500/25 font-medium">
                {scan.language}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                scan.status === 'completed' ? 'bg-green-500/15 text-green-400 border-green-500/30' :
                isActive                   ? 'bg-blue-500/15 text-blue-400 border-blue-500/30' :
                scan.status === 'failed'   ? 'bg-red-500/15 text-red-400 border-red-500/30' :
                                             'bg-foreground/10 text-muted-foreground border-foreground/20'
              } capitalize`}>
                {scan.status}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
              <span>{
                scan.repoProvider && scan.repoOwner && scan.repoName
                  ? `${scan.repoProvider === 'github' ? 'GitHub' : 'GitLab'}: ${scan.repoOwner}/${scan.repoName}`
                  : scan.uploadMethod === 'github'    ? 'GitHub repository'
                  : scan.uploadMethod === 'gitlab'    ? 'GitLab repository'
                  : scan.uploadMethod === 'zip'       ? 'ZIP upload'
                  : scan.uploadMethod === 'directory' ? 'Directory upload'
                  : '—'
              }</span>
              {scan.duration && <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{scan.duration}</span>}
              {scan.totalFiles > 0 && <span>{scan.totalFiles} files</span>}
            </div>
          </div>
        </div>
        {isActive && (
          <Button variant="outline" size="sm" className="gap-2 text-red-400 border-red-500/30 hover:bg-red-500/10" onClick={handleCancel}>
            <StopCircle className="w-3.5 h-3.5" />
            Cancel
          </Button>
        )}
      </div>

      {/* Progress panel */}
      {isActive && (
        <div className="bg-card border border-foreground/10 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Scan Progress</h2>
            <span className="text-sm font-bold text-foreground">{scan.progress}%</span>
          </div>
          <div className="h-2 bg-foreground/10 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-violet-600 to-violet-400 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <p className="text-xs text-muted-foreground flex items-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
            {scan.currentStep}
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-0.5">
            {Object.entries(STAGE_LABELS).map(([key, label]) => (
              <StageRow key={key} label={label} status={(scan.stages as any)[key] ?? 'pending'} />
            ))}
          </div>
          {sseError && (
            <div className="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-2">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              Connection interrupted — results will be persisted when the scan completes
            </div>
          )}
        </div>
      )}

      {/* Error panel */}
      {scan.status === 'failed' && scan.error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
          <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">Scan Failed</p>
            <p className="text-xs text-red-400/80 mt-1">{scan.error}</p>
          </div>
        </div>
      )}

      {/* Stats row */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Critical',     v: scan.criticalFindings, accent: 'text-red-400' },
            { label: 'High',         v: scan.highFindings,     accent: 'text-orange-400' },
            { label: 'Medium',       v: scan.mediumFindings,   accent: 'text-yellow-400' },
            { label: 'Low',          v: scan.lowFindings,      accent: 'text-blue-400' },
            { label: 'Secret Findings',   v: scan.secretFindings,  accent: 'text-red-400' },
            { label: 'Dependency Vulns',  v: scan.dependencyVulns, accent: 'text-yellow-400' },
            { label: 'Total Findings',    v: scan.totalFindings,   accent: 'text-foreground' },
            { label: 'Files Scanned',     v: scan.totalFiles,      accent: 'text-foreground' },
          ].map(({ label, v, accent }) => (
            <div key={label} className="bg-card border border-foreground/10 rounded-xl p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-xl font-bold mt-0.5 ${accent}`}>{v}</p>
            </div>
          ))}
        </div>
      )}

      {/* Findings table */}
      {(scan.status === 'completed' || findings.length > 0) && (
        <div className="bg-card border border-foreground/10 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-foreground/8">
            <h2 className="text-sm font-semibold text-foreground">
              Findings {findings.length > 0 && <span className="text-muted-foreground font-normal">({findings.length})</span>}
            </h2>
            <div className="flex items-center gap-1">
              {(['all', 'secret', 'owasp', 'dependency'] as TabFilter[]).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`text-xs px-2.5 py-1 rounded-lg transition-colors capitalize ${
                    tab === t
                      ? 'bg-foreground/10 text-foreground font-medium'
                      : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5'
                  }`}
                >
                  {t} ({counts[t]})
                </button>
              ))}
            </div>
          </div>

          {visible.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Shield className="w-8 h-8 text-green-400/50 mb-2" />
              <p className="text-sm text-muted-foreground">
                {findings.length === 0 ? 'No findings yet' : 'No findings in this category'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Severity', 'Finding', 'Location', 'Category', 'CWE', 'OWASP', ''].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {visible.map((f) => <FindingRow key={f.findingId} f={f} />)}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
