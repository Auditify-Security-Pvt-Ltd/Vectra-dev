'use client'

import { useEffect, useState } from 'react'
import {
  FileText, Plus, Download, Trash2, Globe, ShieldAlert,
  Check, ChevronRight, Loader2, AlertTriangle, ArrowLeft, X,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { useAuth } from '@/context/auth-context'
import { listenToReports, createFirestoreReport, deleteFirestoreReport, type FirestoreReport } from '@/lib/firestore-reports'
import { listenToFindings } from '@/lib/firestore-findings'
import {
  getReportableTargets,
  fetchReportDataByTarget,
  generatePdf,
  generateExcel,
  triggerDownload,
  type ReportTarget,
} from '@/lib/report-generator'

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
  const [targetsLoading,    setTargetsLoading]  = useState(false)
  const [selectedTarget, setSelectedTarget] = useState<ReportTarget | null>(null)
  const [formatPdf,      setFormatPdf]      = useState(true)
  const [formatExcel,    setFormatExcel]    = useState(false)
  const [generating,     setGenerating]     = useState(false)
  const [done,           setDone]           = useState(false)
  const [genError,       setGenError]       = useState<string | null>(null)

  function resetModal() {
    setStep(0); setModule('web-security'); setReportableTargets([])
    setSelectedTarget(null); setFormatPdf(true); setFormatExcel(false)
    setGenerating(false); setDone(false); setGenError(null)
  }

  function handleClose() { resetModal(); onClose() }

  // Load reportable targets (built from findings/CVEs/assets collections)
  useEffect(() => {
    if (step !== 1 || !user) return
    setTargetsLoading(true)
    getReportableTargets(user.uid)
      .then(setReportableTargets)
      .catch(() => toast.error('Failed to load assessments'))
      .finally(() => setTargetsLoading(false))
  }, [step, user])

  async function handleGenerate() {
    if (!user || !selectedTarget) return
    if (!formatPdf && !formatExcel) { toast.error('Select at least one format'); return }

    setGenerating(true)
    setGenError(null)

    try {
      const { findings, cves, assets, latestScan } = await fetchReportDataByTarget(user.uid, selectedTarget.target)

      const reportId  = `RPT-${Date.now().toString(36).toUpperCase()}`
      const genAt     = new Date().toISOString()
      const filename  = `vectra-${selectedTarget.target.replace(/[^a-z0-9]/gi, '-')}-${new Date().toISOString().slice(0, 10)}`

      const reportData = {
        target: selectedTarget.target,
        scan: latestScan,
        findings, cves, assets,
        reportId, generatedBy: user.email ?? 'unknown',
      }

      if (formatPdf) {
        const blob = await generatePdf(reportData)
        triggerDownload(blob, `${filename}.pdf`)
      }
      if (formatExcel) {
        const blob = await generateExcel(reportData)
        triggerDownload(blob, `${filename}.xlsx`)
      }

      // Store metadata
      const C = {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high:     findings.filter((f) => f.severity === 'high').length,
        medium:   findings.filter((f) => f.severity === 'medium').length,
        low:      findings.filter((f) => f.severity === 'low').length,
        info:     findings.filter((f) => f.severity === 'info').length,
      }

      await createFirestoreReport(user.uid, {
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
              {[
                { id: 'network-security', icon: ShieldAlert, label: 'Network Security' },
                { id: 'cloud-security',   icon: FileText,    label: 'Cloud Security'   },
              ].map((m) => (
                <div key={m.id} className="flex items-center gap-3 p-3.5 rounded-lg border border-foreground/8 opacity-50 cursor-not-allowed">
                  <div className="w-4 h-4 rounded-full border border-muted-foreground/30 shrink-0" />
                  <div className="w-8 h-8 rounded-lg bg-foreground/5 flex items-center justify-center shrink-0">
                    <m.icon className="w-4 h-4 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{m.label}</p>
                    <p className="text-xs text-muted-foreground/60">Coming soon</p>
                  </div>
                  <span className="ml-auto text-[9px] font-semibold px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground/60 border border-foreground/10">SOON</span>
                </div>
              ))}
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
              <div className="flex items-center justify-center py-10">
                <Loader2 className="w-5 h-5 animate-spin text-primary" />
              </div>
            ) : reportableTargets.length === 0 ? (
              <div className="text-center py-10">
                <AlertTriangle className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No assessments with data found.</p>
                <p className="text-xs text-muted-foreground/70 mt-1">
                  Run a scan and wait for findings or assets to be discovered before generating a report.
                </p>
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {reportableTargets.map((rt) => (
                  <TargetCard
                    key={rt.target}
                    rt={rt}
                    selected={selectedTarget?.target === rt.target}
                    onSelect={() => setSelectedTarget(rt)}
                  />
                ))}
              </div>
            )}
            <div className="flex justify-between pt-2">
              <Button variant="ghost" onClick={() => setStep(0)} className="h-9 text-sm rounded-lg">
                <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
              </Button>
              <Button
                onClick={() => setStep(2)}
                disabled={!selectedTarget}
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

            {selectedTarget && (
              <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Selected Target</p>
                <p className="text-sm font-mono font-semibold text-foreground">{selectedTarget.target}</p>
                <p className="text-xs text-muted-foreground">
                  {selectedTarget.findingsCount} findings · {selectedTarget.cveCount} CVEs · {selectedTarget.assetCount} assets
                </p>
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
                    <span className="text-muted-foreground">Target</span>
                    <span className="font-mono font-semibold text-foreground">{selectedTarget?.target}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Module</span>
                    <span className="text-foreground">Web Security</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Formats</span>
                    <span className="text-foreground">{[formatPdf && 'PDF', formatExcel && 'Excel'].filter(Boolean).join(' + ')}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Data</span>
                    <span className="text-muted-foreground">
                      {selectedTarget?.findingsCount ?? 0} findings · {selectedTarget?.cveCount ?? 0} CVEs · {selectedTarget?.assetCount ?? 0} assets
                    </span>
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

  useEffect(() => {
    if (!user) return
    return listenToReports(user.uid, (r) => {
      setReports(r)
      setReportsLoading(false)
    })
  }, [user])

  // Live count from findings collection — used for "Total Findings" dashboard counter
  useEffect(() => {
    if (!user) return
    return listenToFindings(user.uid, (findings) => {
      setFindingsTotal(findings.length)
      setFindingsReady(true)
    })
  }, [user])

  async function handleDownload(report: FirestoreReport, format: 'pdf' | 'excel') {
    if (!user) return
    const key = `${report.reportId}-${format}`
    setDownloading(key)
    try {
      await reDownload(user.uid, report, format)
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
      await deleteFirestoreReport(user.uid, reportId)
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
          {reportsLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-5 h-5 animate-spin text-primary" />
            </div>
          ) : reports.length === 0 ? (
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
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                            Web Security
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
