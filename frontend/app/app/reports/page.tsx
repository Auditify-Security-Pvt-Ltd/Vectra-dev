'use client'

import { useEffect, useState } from 'react'
import {
  FileText, Plus, Download, Trash2, Globe, ShieldAlert, Code2,
  Check, ChevronRight, Loader2, AlertTriangle, ArrowLeft, X, Cloud,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { useAuth } from '@/context/auth-context'
import { ListSkeleton, TableSkeleton } from '@/components/app/loading-states'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listenToReports, createFirestoreReport, deleteFirestoreReport, type FirestoreReport } from '@/lib/firestore-reports'
import { listenToFindings } from '@/lib/firestore-findings'
import {
  getReportableTargets,
  fetchReportDataByTarget,
  generatePdf,
  generateExcel,
  getNetworkReportableTargets,
  fetchNetworkReportData,
  generateNetworkPdf,
  generateNetworkExcel,
  getSastReportableProjects,
  fetchSastReportData,
  generateSastPdf,
  generateSastExcel,
  generateCloudPdf,
  generateCloudExcel,
  triggerDownload,
  type CloudReportData,
  type ReportTarget,
  type NetworkReportTarget,
  type NetworkReportData,
  type SastReportTarget,
  type SastReportData,
} from '@/lib/report-generator'
import { getCloudReportData, listIntegrations, providerLabel } from '@/lib/api-cloud'

// ── Report modules ────────────────────────────────────────────────────

const MODULE_LABEL: Record<string, string> = {
  'web-security':     'Web Security',
  'network-security': 'Network Security',
  'sast':             'SAST',
  'cloud-security':   'Cloud Security',
}

/** A cloud report covers one integration or all of them (id 'all'). */
interface CloudReportTarget {
  id:       string
  label:    string
  detail:   string
  findings: number
  critical: number
  assets:   number
}

/** Fetch org-scoped cloud report data from the backend and shape it for the generator. */
async function loadCloudReport(integrationId: string, reportId: string, generatedBy: string): Promise<CloudReportData> {
  const d = await getCloudReportData(integrationId)
  const scopeLabel = integrationId === 'all'
    ? 'All cloud integrations'
    : d.integrations[0]?.displayName ?? 'Cloud integration'
  return { scopeLabel, integrations: d.integrations, findings: d.findings, assets: d.assets, truncated: d.truncated, reportId, generatedBy }
}

// ── Severity badge ────────────────────────────────────────────────────

function SevBadge({ sev, count }: { sev: string; count: number }) {
  const cls =
    sev === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' :
    sev === 'high'     ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' :
    sev === 'medium'   ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
    sev === 'low'      ? 'bg-blue-400/10 text-blue-400 border-blue-400/20' :
    'bg-gray-500/10 text-gray-400 border-gray-500/20'
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase ${cls}`}>
      {count} {sev}
    </span>
  )
}

// ── Step indicator ────────────────────────────────────────────────────

const STEPS = ['Module', 'Scan', 'Format', 'Generate']

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-1 mb-6">
      {STEPS.map((label, i) => {
        const done   = i < current
        const active = i === current
        return (
          <div key={label} className="flex items-center gap-1">
            <div className="flex flex-col items-center gap-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                done   ? 'bg-primary text-primary-foreground' :
                active ? 'bg-primary/20 text-primary border border-primary' :
                'bg-foreground/10 text-muted-foreground'
              }`}>
                {done ? <Check className="w-3 h-3" /> : i + 1}
              </div>
              <span className={`text-[9px] ${active ? 'text-primary font-semibold' : 'text-muted-foreground'}`}>
                {label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div className={`h-px w-8 mb-4 ${i < current ? 'bg-primary' : 'bg-foreground/10'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Status badge ──────────────────────────────────────────────────────

const ACTIVE_SCAN_STATUSES = new Set([
  'running', 'processing', 'saving',
  'discovering_assets', 'validating_assets', 'scanning_assets',
])

function statusBadge(status: string): { label: string; cls: string } {
  if (status === 'completed')           return { label: 'Completed', cls: 'bg-green-500/10 text-green-500 border-green-500/20' }
  if (ACTIVE_SCAN_STATUSES.has(status)) return { label: 'Running',   cls: 'bg-blue-500/10 text-blue-400 border-blue-500/20' }
  if (status === 'cancelled')           return { label: 'Cancelled', cls: 'bg-orange-500/10 text-orange-400 border-orange-500/20' }
  if (status === 'failed')              return { label: 'Failed',    cls: 'bg-red-500/10 text-red-400 border-red-500/20' }
  if (status === 'unknown')             return { label: 'Unknown',   cls: 'bg-gray-500/10 text-gray-400 border-gray-500/20' }
  return                                       { label: status,      cls: 'bg-gray-500/10 text-gray-400 border-gray-500/20' }
}

// ── Target card (step 2) ──────────────────────────────────────────────

function TargetCard({ rt, selected, onSelect }: { rt: ReportTarget; selected: boolean; onSelect: () => void }) {
  const { label: statusLabel, cls: statusCls } = statusBadge(rt.latestStatus)
  const lastSeen = new Date(rt.latestScanDate).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  })

  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-4 rounded-lg border transition-colors ${
        selected
          ? 'border-primary bg-primary/5'
          : 'border-foreground/10 hover:border-foreground/25 hover:bg-foreground/3'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-foreground font-mono truncate">{rt.target}</p>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${statusCls}`}>
              {statusLabel}
            </span>
            <span className="text-[10px] text-muted-foreground">Last scan {lastSeen}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0 text-right">
          {rt.findingsCount > 0 && (
            <span className="text-xs font-bold text-orange-400">{rt.findingsCount} Findings</span>
          )}
          {rt.cveCount > 0 && (
            <span className="text-xs font-semibold text-violet-400">{rt.cveCount} CVEs</span>
          )}
          {rt.assetCount > 0 && (
            <span className="text-xs text-muted-foreground">{rt.assetCount} Assets</span>
          )}
        </div>
      </div>
    </button>
  )
}

function NetworkTargetCard({ rt, selected, onSelect }: { rt: NetworkReportTarget; selected: boolean; onSelect: () => void }) {
  const { label: statusLabel, cls: statusCls } = statusBadge(rt.latestStatus)
  const lastSeen = new Date(rt.latestScanDate).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  })
  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-4 rounded-lg border transition-colors ${
        selected
          ? 'border-primary bg-primary/5'
          : 'border-foreground/10 hover:border-foreground/25 hover:bg-foreground/3'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-foreground font-mono truncate">{rt.target}</p>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${statusCls}`}>{statusLabel}</span>
            <span className="text-[10px] text-muted-foreground">Last scan {lastSeen}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0 text-right">
          {rt.hostCount > 0 && <span className="text-xs font-bold text-blue-400">{rt.hostCount} Hosts</span>}
          {rt.cveCount > 0 && <span className="text-xs font-semibold text-violet-400">{rt.cveCount} CVEs</span>}
          {rt.findingsCount > 0 && <span className="text-xs text-muted-foreground">{rt.findingsCount} Findings</span>}
        </div>
      </div>
    </button>
  )
}

function SastTargetCard({ rt, selected, onSelect }: { rt: SastReportTarget; selected: boolean; onSelect: () => void }) {
  const { label: statusLabel, cls: statusCls } = statusBadge(rt.latestStatus)
  const lastSeen = new Date(rt.latestScanDate).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  })
  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-4 rounded-lg border transition-colors ${
        selected
          ? 'border-primary bg-primary/5'
          : 'border-foreground/10 hover:border-foreground/25 hover:bg-foreground/3'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-foreground font-mono truncate">{rt.projectName}</p>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${statusCls}`}>{statusLabel}</span>
            {rt.language !== '—' && (
              <span className="text-[10px] text-muted-foreground">{rt.language}</span>
            )}
            <span className="text-[10px] text-muted-foreground">Last scan {lastSeen}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0 text-right">
          {rt.findingsCount > 0 && <span className="text-xs font-bold text-orange-400">{rt.findingsCount} Findings</span>}
          {rt.secretsCount > 0 && <span className="text-xs font-semibold text-violet-400">{rt.secretsCount} Secrets</span>}
          {rt.depVulnCount > 0 && <span className="text-xs text-muted-foreground">{rt.depVulnCount} Dep Vulns</span>}
        </div>
      </div>
    </button>
  )
}

// ── Generate modal ────────────────────────────────────────────────────

function GenerateModal({ open, onClose, onGenerated }: {
  open: boolean
  onClose: () => void
  onGenerated: () => void
}) {
  const { user } = useAuth()
  const [step,              setStep]            = useState(0)
  const [module,            setModule]          = useState<string>('web-security')
  const [reportableTargets, setReportableTargets] = useState<ReportTarget[]>([])
  const [networkTargets,    setNetworkTargets]  = useState<NetworkReportTarget[]>([])
  const [sastTargets,       setSastTargets]     = useState<SastReportTarget[]>([])
  const [cloudTargets,      setCloudTargets]    = useState<CloudReportTarget[]>([])
  const [selectedCloudTarget,   setSelectedCloudTarget]   = useState<CloudReportTarget | null>(null)
  const [targetsLoading,    setTargetsLoading]  = useState(false)
  const [selectedTarget,        setSelectedTarget]        = useState<ReportTarget | null>(null)
  const [selectedNetworkTarget, setSelectedNetworkTarget] = useState<NetworkReportTarget | null>(null)
  const [selectedSastTarget,    setSelectedSastTarget]    = useState<SastReportTarget | null>(null)
  const [formatPdf,      setFormatPdf]      = useState(true)
  const [formatExcel,    setFormatExcel]    = useState(false)
  const [generating,     setGenerating]     = useState(false)
  const [done,           setDone]           = useState(false)
  const [genError,       setGenError]       = useState<string | null>(null)

  function resetModal() {
    setStep(0); setModule('web-security')
    setReportableTargets([]); setNetworkTargets([]); setSastTargets([]); setCloudTargets([])
    setSelectedTarget(null); setSelectedNetworkTarget(null); setSelectedSastTarget(null); setSelectedCloudTarget(null)
    setFormatPdf(true); setFormatExcel(false)
    setGenerating(false); setDone(false); setGenError(null)
  }

  function handleClose() { resetModal(); onClose() }

  // Load reportable targets when entering step 1
  useEffect(() => {
    if (step !== 1 || !user) return
    setTargetsLoading(true)
    setSelectedTarget(null)
    setSelectedNetworkTarget(null)
    setSelectedSastTarget(null)
    setSelectedCloudTarget(null)

    // Ignore a resolved request if the user changed module/step meanwhile, so
    // a slow response can never overwrite the list for another module.
    let cancelled = false

    const loader =
      module === 'network-security' ? getNetworkReportableTargets(user.organizationId).then((r) => { if (!cancelled) setNetworkTargets(r) })
    : module === 'sast'             ? getSastReportableProjects(user.organizationId).then((r) => { if (!cancelled) setSastTargets(r) })
    : module === 'cloud-security'   ? listIntegrations(true).then(({ integrations }) => {
        if (cancelled) return
        const withData = integrations.filter((i) => i.counts.findings > 0)
        const targets: CloudReportTarget[] = withData.map((i) => ({
          id: i.integrationId, label: i.displayName,
          detail: `${providerLabel(i.provider)} · ${i.accountId ?? '—'}${i.status === 'disconnected' ? ' · disconnected' : ''}`,
          findings: i.counts.open + i.counts.suppressed, critical: i.counts.critical, assets: i.counts.assets,
        }))
        if (withData.length > 1) {
          targets.unshift({
            id: 'all', label: 'All cloud integrations', detail: `${withData.length} integrations`,
            findings: targets.reduce((a, t) => a + t.findings, 0),
            critical: targets.reduce((a, t) => a + t.critical, 0),
            assets:   targets.reduce((a, t) => a + t.assets, 0),
          })
        }
        setCloudTargets(targets)
      })
    :                                 getReportableTargets(user.organizationId).then((r) => { if (!cancelled) setReportableTargets(r) })

    loader
      .catch(() => { if (!cancelled) toast.error('Failed to load assessments') })
      .finally(() => { if (!cancelled) setTargetsLoading(false) })

    return () => { cancelled = true }
  }, [step, user, module])

  // Current selection, normalised across modules for display and gating.
  const selectionName =
    module === 'network-security' ? selectedNetworkTarget?.target
  : module === 'sast'             ? selectedSastTarget?.projectName
  : module === 'cloud-security'   ? selectedCloudTarget?.label
  :                                 selectedTarget?.target

  const selectionSummary =
    module === 'network-security'
      ? `${selectedNetworkTarget?.hostCount ?? 0} hosts · ${selectedNetworkTarget?.cveCount ?? 0} CVEs · ${selectedNetworkTarget?.findingsCount ?? 0} findings`
  : module === 'cloud-security'
      ? `${selectedCloudTarget?.findings ?? 0} findings · ${selectedCloudTarget?.critical ?? 0} critical · ${selectedCloudTarget?.assets ?? 0} assets`
  : module === 'sast'
      ? `${selectedSastTarget?.findingsCount ?? 0} findings · ${selectedSastTarget?.secretsCount ?? 0} secrets · ${selectedSastTarget?.depVulnCount ?? 0} dependency vulns`
      : `${selectedTarget?.findingsCount ?? 0} findings · ${selectedTarget?.cveCount ?? 0} CVEs · ${selectedTarget?.assetCount ?? 0} assets`

  async function handleGenerate() {
    if (!user) return
    if (!formatPdf && !formatExcel) { toast.error('Select at least one format'); return }

    const isNetwork = module === 'network-security'
    const isSast    = module === 'sast'
    const isCloud   = module === 'cloud-security'
    if (isNetwork && !selectedNetworkTarget) return
    if (isSast    && !selectedSastTarget) return
    if (isCloud   && !selectedCloudTarget) return
    if (!isNetwork && !isSast && !isCloud && !selectedTarget) return

    setGenerating(true)
    setGenError(null)

    try {
      const reportId = `RPT-${Date.now().toString(36).toUpperCase()}`
      const genAt    = new Date().toISOString()

      if (isCloud && selectedCloudTarget) {
        // Backend-scoped to the caller's organization and the chosen integration.
        const cloudData = await loadCloudReport(selectedCloudTarget.id, reportId, user.email ?? 'unknown')
        const filename = `vectra-cloud-${cloudData.scopeLabel.replace(/[^a-z0-9]/gi, '-')}-${genAt.slice(0, 10)}`
        if (formatPdf)   triggerDownload(await generateCloudPdf(cloudData),   `${filename}.pdf`)
        if (formatExcel) triggerDownload(await generateCloudExcel(cloudData), `${filename}.xlsx`)

        const f = cloudData.findings
        await createFirestoreReport(user.organizationId, {
          reportId,
          target:        cloudData.scopeLabel,
          scanId:        selectedCloudTarget.id,
          module,
          format:        [formatPdf && 'pdf', formatExcel && 'excel'].filter(Boolean) as string[],
          generatedAt:   genAt,
          generatedBy:   user.email ?? 'unknown',
          findingsCount: f.length,
          cveCount:      f.filter((x) => x.cveId).length,
          assetsCount:   cloudData.assets.length,
          criticalCount: f.filter((x) => x.severity === 'critical').length,
          highCount:     f.filter((x) => x.severity === 'high').length,
          mediumCount:   f.filter((x) => x.severity === 'medium').length,
          lowCount:      f.filter((x) => x.severity === 'low').length,
          infoCount:     f.filter((x) => x.severity === 'info').length,
        })
      } else if (isSast && selectedSastTarget) {
        // Reuses the existing SAST scan + findings written by the SAST pipeline.
        const { scan, findings } = await fetchSastReportData(
          user.organizationId, selectedSastTarget.scanId,
        )

        const filename = `vectra-sast-${selectedSastTarget.projectName.replace(/[^a-z0-9]/gi, '-')}-${genAt.slice(0, 10)}`
        const sastData: SastReportData = {
          projectName: selectedSastTarget.projectName,
          scan, findings,
          reportId, generatedBy: user.email ?? 'unknown',
        }

        if (formatPdf)   triggerDownload(await generateSastPdf(sastData),   `${filename}.pdf`)
        if (formatExcel) triggerDownload(await generateSastExcel(sastData), `${filename}.xlsx`)

        const SC = {
          critical: findings.filter((f) => f.severity === 'critical').length,
          high:     findings.filter((f) => f.severity === 'high').length,
          medium:   findings.filter((f) => f.severity === 'medium').length,
          low:      findings.filter((f) => f.severity === 'low').length,
          info:     findings.filter((f) => f.severity === 'info').length,
        }

        await createFirestoreReport(user.organizationId, {
          reportId,
          target:        selectedSastTarget.projectName,
          scanId:        selectedSastTarget.scanId,
          module,
          format:        [formatPdf && 'pdf', formatExcel && 'excel'].filter(Boolean) as string[],
          generatedAt:   genAt,
          generatedBy:   user.email ?? 'unknown',
          findingsCount: findings.length,
          cveCount:      findings.filter((f) => f.cveId).length,
          assetsCount:   scan?.scannedFiles ?? 0,
          criticalCount: SC.critical,
          highCount:     SC.high,
          mediumCount:   SC.medium,
          lowCount:      SC.low,
          infoCount:     SC.info,
        })
      } else if (isNetwork && selectedNetworkTarget) {
        const { hosts, findings, cves, latestScan, timeline } =
          await fetchNetworkReportData(user.organizationId, selectedNetworkTarget.target)

        const filename  = `vectra-network-${selectedNetworkTarget.target.replace(/[^a-z0-9]/gi, '-')}-${genAt.slice(0, 10)}`
        const netData: NetworkReportData = {
          target: selectedNetworkTarget.target,
          scan: latestScan, hosts, findings, cves, timeline,
          reportId, generatedBy: user.email ?? 'unknown',
        }

        if (formatPdf)   triggerDownload(await generateNetworkPdf(netData),   `${filename}.pdf`)
        if (formatExcel) triggerDownload(await generateNetworkExcel(netData),  `${filename}.xlsx`)

        const FC = {
          critical: findings.filter((f) => f.severity === 'critical').length,
          high:     findings.filter((f) => f.severity === 'high').length,
          medium:   findings.filter((f) => f.severity === 'medium').length,
          low:      findings.filter((f) => f.severity === 'low').length,
          info:     findings.filter((f) => f.severity === 'info').length,
        }

        await createFirestoreReport(user.organizationId, {
          reportId,
          target:        selectedNetworkTarget.target,
          scanId:        latestScan?.scanId ?? '',
          module,
          format:        [formatPdf && 'pdf', formatExcel && 'excel'].filter(Boolean) as string[],
          generatedAt:   genAt,
          generatedBy:   user.email ?? 'unknown',
          findingsCount: findings.length,
          cveCount:      cves.length,
          assetsCount:   hosts.length,
          criticalCount: FC.critical,
          highCount:     FC.high,
          mediumCount:   FC.medium,
          lowCount:      FC.low,
          infoCount:     FC.info,
        })
      } else if (selectedTarget) {
        const { findings, cves, assets, latestScan } =
          await fetchReportDataByTarget(user.organizationId, selectedTarget.target)

        const filename  = `vectra-${selectedTarget.target.replace(/[^a-z0-9]/gi, '-')}-${genAt.slice(0, 10)}`
        const webData = {
          target: selectedTarget.target,
          scan: latestScan, findings, cves, assets,
          reportId, generatedBy: user.email ?? 'unknown',
        }

        if (formatPdf)   triggerDownload(await generatePdf(webData),   `${filename}.pdf`)
        if (formatExcel) triggerDownload(await generateExcel(webData),  `${filename}.xlsx`)

        const C = {
          critical: findings.filter((f) => f.severity === 'critical').length,
          high:     findings.filter((f) => f.severity === 'high').length,
          medium:   findings.filter((f) => f.severity === 'medium').length,
          low:      findings.filter((f) => f.severity === 'low').length,
          info:     findings.filter((f) => f.severity === 'info').length,
        }

        await createFirestoreReport(user.organizationId, {
          reportId,
          target:        selectedTarget.target,
          scanId:        latestScan?.scanId ?? '',
          module,
          format:        [formatPdf && 'pdf', formatExcel && 'excel'].filter(Boolean) as string[],
          generatedAt:   genAt,
          generatedBy:   user.email ?? 'unknown',
          findingsCount: findings.length,
          cveCount:      cves.length,
          assetsCount:   assets.length,
          criticalCount: C.critical,
          highCount:     C.high,
          mediumCount:   C.medium,
          lowCount:      C.low,
          infoCount:     C.info,
        })
      }

      setDone(true)
      onGenerated()
      toast.success('Report generated and downloaded')
    } catch (err: any) {
      setGenError(err?.message ?? 'Report generation failed')
      toast.error('Report generation failed')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="sm:max-w-lg bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold">Generate Security Report</DialogTitle>
          <DialogDescription className="sr-only">Generate a security assessment report</DialogDescription>
        </DialogHeader>

        <StepIndicator current={step} />

        {/* ── Step 0: Select Module ── */}
        {step === 0 && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground mb-4">Select the security module for this report.</p>
            <RadioGroup value={module} onValueChange={setModule} className="gap-3">
              <Label className={`flex items-center gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${module === 'web-security' ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}>
                <RadioGroupItem value="web-security" />
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Globe className="w-4 h-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Web Security</p>
                  <p className="text-xs text-muted-foreground">Assets, findings, CVEs from web scans</p>
                </div>
              </Label>
              <Label className={`flex items-center gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${module === 'network-security' ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}>
                <RadioGroupItem value="network-security" />
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <ShieldAlert className="w-4 h-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Network Security</p>
                  <p className="text-xs text-muted-foreground">Hosts, ports, services, SSL/TLS, CVEs from network scans</p>
                </div>
              </Label>
              <Label className={`flex items-center gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${module === 'sast' ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}>
                <RadioGroupItem value="sast" />
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Code2 className="w-4 h-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">SAST</p>
                  <p className="text-xs text-muted-foreground">Source code findings, secrets, CWE/OWASP, dependency CVEs</p>
                </div>
              </Label>
              <Label className={`flex items-center gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${module === 'cloud-security' ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}>
                <RadioGroupItem value="cloud-security" />
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Cloud className="w-4 h-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Cloud Security</p>
                  <p className="text-xs text-muted-foreground">AWS &amp; Google Cloud findings, affected assets, CVEs, remediation</p>
                </div>
              </Label>
            </RadioGroup>
            <div className="flex justify-end pt-2">
              <Button onClick={() => setStep(1)} className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-5 text-sm">
                Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ── Step 1: Select Target ── */}
        {step === 1 && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground mb-2">Available Security Assessments — select one to report on.</p>
            {targetsLoading ? (
              <ListSkeleton rows={3} />
            ) : (module === 'network-security' ? networkTargets : module === 'sast' ? sastTargets : module === 'cloud-security' ? cloudTargets : reportableTargets).length === 0 ? (
              <div className="text-center py-10">
                <AlertTriangle className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No assessments with data found.</p>
                <p className="text-xs text-muted-foreground/70 mt-1">
                  {module === 'cloud-security'
                    ? 'Connect a cloud provider and sync findings before generating a report.'
                    : 'Run a scan and wait for data to be discovered before generating a report.'}
                </p>
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {module === 'cloud-security'
                  ? cloudTargets.map((ct) => (
                      <button
                        key={ct.id} type="button" onClick={() => setSelectedCloudTarget(ct)}
                        className={`w-full text-left p-3.5 rounded-lg border transition-colors ${selectedCloudTarget?.id === ct.id ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}
                      >
                        <p className="text-sm font-semibold text-foreground">{ct.label}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{ct.detail}</p>
                        <p className="text-xs text-muted-foreground mt-1">{ct.findings} findings · {ct.critical} critical · {ct.assets} assets</p>
                      </button>
                    ))
                  : module === 'network-security'
                  ? networkTargets.map((rt) => (
                      <NetworkTargetCard
                        key={rt.target}
                        rt={rt}
                        selected={selectedNetworkTarget?.target === rt.target}
                        onSelect={() => setSelectedNetworkTarget(rt)}
                      />
                    ))
                  : module === 'sast'
                  ? sastTargets.map((rt) => (
                      <SastTargetCard
                        key={rt.scanId}
                        rt={rt}
                        selected={selectedSastTarget?.scanId === rt.scanId}
                        onSelect={() => setSelectedSastTarget(rt)}
                      />
                    ))
                  : reportableTargets.map((rt) => (
                      <TargetCard
                        key={rt.target}
                        rt={rt}
                        selected={selectedTarget?.target === rt.target}
                        onSelect={() => setSelectedTarget(rt)}
                      />
                    ))
                }
              </div>
            )}
            <div className="flex justify-between pt-2">
              <Button variant="ghost" onClick={() => setStep(0)} className="h-9 text-sm rounded-lg">
                <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
              </Button>
              <Button
                onClick={() => setStep(2)}
                disabled={!selectionName}
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-5 text-sm disabled:opacity-40"
              >
                Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ── Step 2: Select Format ── */}
        {step === 2 && (
          <div className="space-y-4">
            <p className="text-xs text-muted-foreground">Choose one or both export formats.</p>

            <div className="space-y-3">
              <label className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${formatPdf ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/20'}`}>
                <Checkbox
                  checked={formatPdf}
                  onCheckedChange={(v) => setFormatPdf(Boolean(v))}
                  className="mt-0.5"
                />
                <div>
                  <p className="text-sm font-medium text-foreground">PDF Report</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Professional pentest-style report with cover page, findings, CVEs, and recommendations
                  </p>
                </div>
              </label>

              <label className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors ${formatExcel ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/20'}`}>
                <Checkbox
                  checked={formatExcel}
                  onCheckedChange={(v) => setFormatExcel(Boolean(v))}
                  className="mt-0.5"
                />
                <div>
                  <p className="text-sm font-medium text-foreground">Excel Workbook</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    5-sheet workbook: Executive Summary, Findings, CVE Intelligence, Assets, Recommendations
                  </p>
                </div>
              </label>
            </div>

            {selectionName && (
              <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">
                  {module === 'sast' ? 'Selected Project' : 'Selected Target'}
                </p>
                <p className="text-sm font-mono font-semibold text-foreground">{selectionName}</p>
                <p className="text-xs text-muted-foreground">{selectionSummary}</p>
              </div>
            )}

            <div className="flex justify-between pt-1">
              <Button variant="ghost" onClick={() => setStep(1)} className="h-9 text-sm rounded-lg">
                <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
              </Button>
              <Button
                onClick={() => setStep(3)}
                disabled={!formatPdf && !formatExcel}
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-5 text-sm disabled:opacity-40"
              >
                Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ── Step 3: Generate ── */}
        {step === 3 && (
          <div className="space-y-5">
            {!done ? (
              <>
                <div className="p-4 rounded-lg bg-foreground/3 border border-foreground/8 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">{module === 'sast' ? 'Project' : 'Target'}</span>
                    <span className="font-mono font-semibold text-foreground">{selectionName}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Module</span>
                    <span className="text-foreground">{MODULE_LABEL[module] ?? module}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Formats</span>
                    <span className="text-foreground">{[formatPdf && 'PDF', formatExcel && 'Excel'].filter(Boolean).join(' + ')}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Data</span>
                    <span className="text-muted-foreground">{selectionSummary}</span>
                  </div>
                </div>

                {genError && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
                    {genError}
                  </div>
                )}

                <div className="flex justify-between pt-1">
                  <Button variant="ghost" onClick={() => setStep(2)} disabled={generating} className="h-9 text-sm rounded-lg">
                    <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
                  </Button>
                  <Button
                    onClick={handleGenerate}
                    disabled={generating}
                    className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-6 text-sm gap-2"
                  >
                    {generating
                      ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating…</>
                      : <><FileText className="w-3.5 h-3.5" /> Generate Report</>
                    }
                  </Button>
                </div>
              </>
            ) : (
              <div className="text-center py-4 space-y-3">
                <div className="w-12 h-12 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto">
                  <Check className="w-6 h-6 text-green-500" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-foreground">Report Generated</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Your {[formatPdf && 'PDF', formatExcel && 'Excel'].filter(Boolean).join(' and ')} report has been downloaded and saved.
                  </p>
                </div>
                <Button onClick={handleClose} className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-6 text-sm">
                  Close
                </Button>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ── Re-download helper ────────────────────────────────────────────────

async function reDownload(uid: string, report: FirestoreReport, format: 'pdf' | 'excel') {
  if (report.module === 'cloud-security') {
    // Regenerated from current data for the same scope (integration or all).
    const cloudData = await loadCloudReport(report.scanId || 'all', report.reportId, report.generatedBy)
    const filename = `vectra-cloud-${report.target.replace(/[^a-z0-9]/gi, '-')}-${report.generatedAt.slice(0, 10)}`
    if (format === 'pdf') triggerDownload(await generateCloudPdf(cloudData), `${filename}.pdf`)
    else triggerDownload(await generateCloudExcel(cloudData), `${filename}.xlsx`)
    return
  }

  if (report.module === 'sast') {
    const { scan, findings } = await fetchSastReportData(uid, report.scanId)
    const sastData: SastReportData = {
      projectName: report.target,
      scan, findings,
      reportId: report.reportId,
      generatedBy: report.generatedBy,
    }
    const filename = `vectra-sast-${report.target.replace(/[^a-z0-9]/gi, '-')}-${report.generatedAt.slice(0, 10)}`
    if (format === 'pdf') {
      triggerDownload(await generateSastPdf(sastData), `${filename}.pdf`)
    } else {
      triggerDownload(await generateSastExcel(sastData), `${filename}.xlsx`)
    }
    return
  }

  if (report.module === 'network-security') {
    const { hosts, findings, cves, latestScan, timeline } = await fetchNetworkReportData(uid, report.target)
    const netData: NetworkReportData = {
      target: report.target,
      scan: latestScan, hosts, findings, cves, timeline,
      reportId: report.reportId,
      generatedBy: report.generatedBy,
    }
    const filename = `vectra-network-${report.target.replace(/[^a-z0-9]/gi, '-')}-${report.generatedAt.slice(0, 10)}`
    if (format === 'pdf') {
      triggerDownload(await generateNetworkPdf(netData), `${filename}.pdf`)
    } else {
      triggerDownload(await generateNetworkExcel(netData), `${filename}.xlsx`)
    }
    return
  }

  const { findings, cves, assets, latestScan } = await fetchReportDataByTarget(uid, report.target)
  const data = {
    target: report.target,
    scan: latestScan,
    findings, cves, assets,
    reportId: report.reportId,
    generatedBy: report.generatedBy,
  }
  const filename = `vectra-${report.target.replace(/[^a-z0-9]/gi, '-')}-${report.generatedAt.slice(0, 10)}`

  if (format === 'pdf') {
    const blob = await generatePdf(data)
    triggerDownload(blob, `${filename}.pdf`)
  } else {
    const blob = await generateExcel(data)
    triggerDownload(blob, `${filename}.xlsx`)
  }
}

// ── Main page ─────────────────────────────────────────────────────────

export default function ReportsPage() {
  const { user } = useAuth()

  const [reports,        setReports]        = useState<FirestoreReport[]>([])
  const [reportsLoading, setReportsLoading] = useState(true)
  const [findingsTotal,  setFindingsTotal]  = useState(0)
  const [findingsReady,  setFindingsReady]  = useState(false)
  const [modalOpen,      setModalOpen]      = useState(false)
  const [downloading,    setDownloading]    = useState<string | null>(null)

  // Avoid flashing a skeleton when the cache answers immediately.
  const showReportsSkeleton = useDelayedLoading(reportsLoading)

  useEffect(() => {
    if (!user) return
    return listenToReports(user.organizationId, (r) => {
      setReports(r)
      setReportsLoading(false)
    })
  }, [user])

  // Live count from findings collection — used for "Total Findings" dashboard counter
  useEffect(() => {
    if (!user) return
    return listenToFindings(user.organizationId, (findings) => {
      setFindingsTotal(findings.length)
      setFindingsReady(true)
    })
  }, [user])

  async function handleDownload(report: FirestoreReport, format: 'pdf' | 'excel') {
    if (!user) return
    const key = `${report.reportId}-${format}`
    setDownloading(key)
    try {
      await reDownload(user.organizationId, report, format)
      toast.success(`${format.toUpperCase()} downloaded`)
    } catch (err: any) {
      toast.error(err?.message ?? 'Download failed')
    } finally {
      setDownloading(null)
    }
  }

  async function handleDelete(reportId: string) {
    if (!user) return
    try {
      await deleteFirestoreReport(user.organizationId, reportId)
      toast.success('Report deleted')
    } catch {
      toast.error('Failed to delete report')
    }
  }

  // Stat counts
  const thisMonth = reports.filter((r) => {
    const d = new Date(r.generatedAt)
    const n = new Date()
    return d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth()
  }).length

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Reports</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Generate and download professional security assessment reports</p>
        </div>
        <Button
          onClick={() => setModalOpen(true)}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5 text-sm gap-2"
        >
          <Plus className="w-4 h-4" />
          Generate Report
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Reports',  value: reportsLoading            ? '—' : String(reports.length), cls: 'text-foreground' },
          { label: 'This Month',     value: reportsLoading            ? '—' : String(thisMonth),       cls: 'text-primary' },
          { label: 'Total Findings', value: !findingsReady            ? '—' : String(findingsTotal),   cls: 'text-orange-500' },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Reports list */}
      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showReportsSkeleton ? (
            <div className="p-4">
              <TableSkeleton rows={5} cols={6} />
            </div>
          ) : reportsLoading ? null : reports.length === 0 ? (
            <div className="text-center py-16 space-y-3">
              <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
                <FileText className="w-6 h-6 text-muted-foreground" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">No reports generated yet</p>
              <p className="text-xs text-muted-foreground/70">Click "Generate Report" to create your first security assessment report.</p>
              <Button
                onClick={() => setModalOpen(true)}
                variant="outline"
                className="rounded-lg border-foreground/20 h-9 text-sm mt-2"
              >
                <Plus className="w-3.5 h-3.5 mr-1.5" /> Generate Report
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Report</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Module</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Severity Distribution</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">CVEs</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Generated</th>
                    <th className="py-3 px-4" />
                  </tr>
                </thead>
                <tbody>
                  {reports.map((report) => {
                    const hasPdf   = report.format.includes('pdf')
                    const hasExcel = report.format.includes('excel')
                    const dl       = (fmt: 'pdf' | 'excel') => `${report.reportId}-${fmt}`

                    return (
                      <tr key={report.reportId} className="border-b border-foreground/5 hover:bg-foreground/3 transition-colors">
                        <td className="py-3.5 px-4">
                          <p className="text-sm font-semibold text-foreground font-mono">{report.target}</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5">{report.reportId}</p>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                            report.module === 'network-security'
                              ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                              : report.module === 'sast'
                              ? 'bg-violet-500/10 text-violet-400 border-violet-500/20'
                              : report.module === 'cloud-security'
                              ? 'bg-sky-500/10 text-sky-400 border-sky-500/20'
                              : 'bg-primary/10 text-primary border-primary/20'
                          }`}>
                            {MODULE_LABEL[report.module] ?? 'Web Security'}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="flex flex-wrap gap-1">
                            {report.criticalCount > 0 && <SevBadge sev="critical" count={report.criticalCount} />}
                            {report.highCount     > 0 && <SevBadge sev="high"     count={report.highCount}     />}
                            {report.mediumCount   > 0 && <SevBadge sev="medium"   count={report.mediumCount}   />}
                            {report.lowCount      > 0 && <SevBadge sev="low"      count={report.lowCount}      />}
                            {report.findingsCount === 0 && (
                              <span className="text-[10px] text-muted-foreground">No findings</span>
                            )}
                          </div>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="text-xs font-semibold text-violet-400">{report.cveCount}</span>
                        </td>
                        <td className="py-3.5 px-4">
                          <p className="text-xs text-muted-foreground">
                            {new Date(report.generatedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                          </p>
                          <p className="text-[10px] text-muted-foreground/60">
                            {new Date(report.generatedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                          </p>
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-1 justify-end">
                            {hasPdf && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDownload(report, 'pdf')}
                                disabled={downloading === dl('pdf')}
                                className="h-7 rounded-lg text-xs text-muted-foreground hover:text-foreground gap-1 px-2"
                              >
                                {downloading === dl('pdf')
                                  ? <Loader2 className="w-3 h-3 animate-spin" />
                                  : <Download className="w-3 h-3" />
                                }PDF
                              </Button>
                            )}
                            {hasExcel && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDownload(report, 'excel')}
                                disabled={downloading === dl('excel')}
                                className="h-7 rounded-lg text-xs text-muted-foreground hover:text-foreground gap-1 px-2"
                              >
                                {downloading === dl('excel')
                                  ? <Loader2 className="w-3 h-3 animate-spin" />
                                  : <Download className="w-3 h-3" />
                                }XLS
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDelete(report.reportId)}
                              className="h-7 w-7 rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <GenerateModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onGenerated={() => {}}
      />
    </div>
  )
}
