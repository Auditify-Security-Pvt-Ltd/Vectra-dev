'use client'

import { useEffect, useState } from 'react'
import {
  CheckCircle2, XCircle, AlertTriangle, RefreshCw, Play, Loader2,
  Network, Server, ShieldAlert, Eye, Cpu,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { API_BASE } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────

interface PipelineStatus {
  tools: {
    subfinder: boolean
    httpx_toolkit: boolean
    nuclei: boolean
    nvd_reachable: boolean | null
  }
  nvdError: string | null
  cveCache: Array<{ technology: string; version: string; cveCount: number; topCves: string[] }>
  activeScans: Array<{
    scanId: string
    target: string
    status: string
    totalAssets: number
    liveAssets: number
    totalCves: number
    detectedTechs: Array<{ technology: string; version: string | null; assetUrl: string }>
    cveDocuments: Array<{ cveId: string; severity: string; cvssScore: number; technology: string; version: string; assetUrl: string }>
  }>
  pipelineStages: string[]
}

interface CveTestResult {
  technology: string
  version: string
  allPass: boolean
  summary: string
  stages: Array<{
    stage: string
    pass: boolean
    input?: string
    result?: Record<string, unknown>
    url?: string
    elapsedSec?: number
    rawCount?: number
    cveCount?: number
    cves?: Array<{ cveId: string; severity: string; cvss: number; exploit: boolean }>
    error?: string | null
  }>
}

interface TechTestResult {
  url: string
  alive: boolean
  statusCode?: number
  server?: string
  title?: string
  ip?: string
  technologies: string[]
  versioned: Array<{ name: string; version: string; raw: string }>
  versionedCount: number
  note: string
  error?: string
}

// ── Helper components ─────────────────────────────────────────────────

function StatusDot({ ok, loading }: { ok: boolean | null; loading?: boolean }) {
  if (loading) return <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
  if (ok === null) return <div className="w-3 h-3 rounded-full bg-gray-500" />
  return ok
    ? <CheckCircle2 className="w-4 h-4 text-green-500" />
    : <XCircle className="w-4 h-4 text-red-500" />
}

function StageBadge({ pass, label }: { pass: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded font-medium ${
      pass ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
    }`}>
      {pass ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
      {label}
    </span>
  )
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-500',
  HIGH:     'text-orange-500',
  MEDIUM:   'text-yellow-500',
  LOW:      'text-blue-400',
  NONE:     'text-gray-400',
}

// ── Page ──────────────────────────────────────────────────────────────

export default function CveDebugPage() {
  const [status, setStatus]       = useState<PipelineStatus | null>(null)
  const [statusLoading, setStatusLoading] = useState(false)

  const [cveTestTech, setCveTestTech]     = useState('Apache')
  const [cveTestVer, setCveTestVer]       = useState('2.4.49')
  const [cveTestResult, setCveTestResult] = useState<CveTestResult | null>(null)
  const [cveTestLoading, setCveTestLoading] = useState(false)

  const [techTestUrl, setTechTestUrl]       = useState('https://nginx.org')
  const [techTestResult, setTechTestResult] = useState<TechTestResult | null>(null)
  const [techTestLoading, setTechTestLoading] = useState(false)

  async function loadStatus() {
    setStatusLoading(true)
    try {
      const res = await fetch(`${API_BASE}/debug/cve-pipeline`)
      setStatus(await res.json())
    } catch { /* ignore */ }
    finally { setStatusLoading(false) }
  }

  async function runCveTest() {
    setCveTestLoading(true)
    setCveTestResult(null)
    try {
      const res = await fetch(`${API_BASE}/debug/cve-test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ technology: cveTestTech, version: cveTestVer }),
      })
      setCveTestResult(await res.json())
    } catch { /* ignore */ }
    finally { setCveTestLoading(false) }
  }

  async function runTechTest() {
    setTechTestLoading(true)
    setTechTestResult(null)
    try {
      const res = await fetch(`${API_BASE}/debug/tech-detection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: techTestUrl }),
      })
      setTechTestResult(await res.json())
    } catch { /* ignore */ }
    finally { setTechTestLoading(false) }
  }

  useEffect(() => { loadStatus() }, [])

  return (
    <div className="p-8 space-y-8 max-w-5xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">CVE Pipeline Debug</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Audit every stage of the CVE Intelligence pipeline — tools, detection, NVD lookup, Firestore writes
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadStatus} disabled={statusLoading} className="gap-2">
          <RefreshCw className={`w-4 h-4 ${statusLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* ── Section 1: Tool Availability ─────────────────────────────── */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Server className="w-4 h-4 text-primary" /> Tool Availability
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!status ? (
            <div className="text-sm text-muted-foreground">{statusLoading ? 'Loading…' : 'Click Refresh'}</div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { key: 'subfinder',     label: 'Subfinder',      desc: 'Asset Discovery' },
                { key: 'httpx_toolkit', label: 'httpx-toolkit',  desc: 'Asset Probing' },
                { key: 'nuclei',        label: 'Nuclei',          desc: 'Vuln Scanning' },
                { key: 'nvd_reachable', label: 'NVD API',         desc: 'CVE Lookup' },
              ].map(({ key, label, desc }) => {
                const ok = status.tools[key as keyof typeof status.tools]
                return (
                  <div key={key} className={`p-3 rounded-lg border ${
                    ok === null ? 'border-foreground/10' :
                    ok ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/20 bg-red-500/5'
                  }`}>
                    <div className="flex items-center gap-2 mb-1">
                      <StatusDot ok={ok} loading={statusLoading && ok === null} />
                      <span className="text-sm font-semibold text-foreground">{label}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">{desc}</div>
                    {key === 'nvd_reachable' && !ok && status.nvdError && (
                      <div className="text-xs text-red-400 mt-1 truncate" title={status.nvdError}>{status.nvdError}</div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Section 2: CVE Test (NVD lookup) ─────────────────────────── */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-primary" /> Step 4–5: CVE Lookup Test
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            Run a live NVD CVE lookup for any technology+version to verify the pipeline works.
            Expected: Apache 2.4.49 → CVE-2021-41773, CVE-2021-42013
          </p>
          <div className="flex gap-2">
            <Input
              value={cveTestTech}
              onChange={(e) => setCveTestTech(e.target.value)}
              placeholder="Technology (e.g. Apache)"
              className="bg-foreground/5 border-foreground/20 w-40"
            />
            <Input
              value={cveTestVer}
              onChange={(e) => setCveTestVer(e.target.value)}
              placeholder="Version (e.g. 2.4.49)"
              className="bg-foreground/5 border-foreground/20 w-36"
            />
            <Button onClick={runCveTest} disabled={cveTestLoading} className="gap-2">
              {cveTestLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run Test
            </Button>
          </div>

          {cveTestResult && (
            <div className="space-y-4">
              {/* Summary banner */}
              <div className={`px-4 py-3 rounded-lg border text-sm font-medium flex items-center gap-2 ${
                cveTestResult.allPass
                  ? 'bg-green-500/10 border-green-500/30 text-green-400'
                  : 'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                {cveTestResult.allPass
                  ? <CheckCircle2 className="w-4 h-4 shrink-0" />
                  : <XCircle className="w-4 h-4 shrink-0" />}
                {cveTestResult.summary}
              </div>

              {/* Stage breakdown */}
              <div className="space-y-2">
                {cveTestResult.stages.map((s, i) => (
                  <div key={i} className="p-3 bg-foreground/5 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-foreground">{s.stage}</span>
                      <StageBadge pass={s.pass} label={s.pass ? 'PASS' : 'FAIL'} />
                    </div>
                    {s.error && <p className="text-xs text-red-400">{s.error}</p>}
                    {s.elapsedSec != null && (
                      <p className="text-xs text-muted-foreground">⏱ {s.elapsedSec}s</p>
                    )}
                    {s.result && (
                      <pre className="text-xs text-muted-foreground mt-1 overflow-x-auto">
                        {JSON.stringify(s.result, null, 2)}
                      </pre>
                    )}
                    {s.cves && s.cves.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {s.cves.map((cve) => (
                          <div key={cve.cveId} className="flex items-center gap-2 text-xs">
                            <span className="font-mono text-foreground">{cve.cveId}</span>
                            <span className={SEVERITY_COLORS[cve.severity] ?? 'text-gray-400'}>
                              {cve.severity}
                            </span>
                            <span className="text-muted-foreground">CVSS {cve.cvss}</span>
                            {cve.exploit && (
                              <span className="text-xs bg-red-500/15 text-red-400 px-1.5 rounded">exploit</span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Section 3: Technology Detection Test ──────────────────────── */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Cpu className="w-4 h-4 text-primary" /> Step 2: Technology Detection Test
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            Run httpx-toolkit tech detection on any URL. Shows exactly which technologies and versions will be passed to NVD.
            Versions come from the Server response header (e.g. <code className="text-primary">nginx/1.18.0</code>).
          </p>
          <div className="flex gap-2">
            <Input
              value={techTestUrl}
              onChange={(e) => setTechTestUrl(e.target.value)}
              placeholder="https://example.com"
              className="bg-foreground/5 border-foreground/20 flex-1"
            />
            <Button onClick={runTechTest} disabled={techTestLoading} className="gap-2">
              {techTestLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              Probe
            </Button>
          </div>

          {techTestResult && (
            <div className="space-y-3">
              {/* Asset info */}
              <div className="p-3 bg-foreground/5 rounded-lg">
                <div className="flex items-center gap-3 text-sm">
                  <StatusDot ok={techTestResult.alive} />
                  <span className="font-mono text-foreground">{techTestResult.url}</span>
                  {techTestResult.statusCode && (
                    <span className="text-muted-foreground">HTTP {techTestResult.statusCode}</span>
                  )}
                  {techTestResult.ip && (
                    <span className="text-muted-foreground">{techTestResult.ip}</span>
                  )}
                </div>
                {techTestResult.server && (
                  <div className="mt-1 text-xs text-muted-foreground">
                    Server: <span className="text-primary font-mono">{techTestResult.server}</span>
                  </div>
                )}
                {techTestResult.title && (
                  <div className="mt-0.5 text-xs text-muted-foreground">Title: {techTestResult.title}</div>
                )}
              </div>

              {/* Detected technologies */}
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-2">
                  All Technologies ({techTestResult.technologies.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {techTestResult.technologies.map((t) => {
                    const hasVersion = techTestResult.versioned.some((v) => v.raw === t)
                    return (
                      <span
                        key={t}
                        className={`text-xs px-2 py-0.5 rounded font-medium ${
                          hasVersion
                            ? 'bg-primary/15 text-primary border border-primary/30'
                            : 'bg-foreground/10 text-muted-foreground'
                        }`}
                      >
                        {t}
                        {hasVersion && ' ✓'}
                      </span>
                    )
                  })}
                </div>
              </div>

              {/* Versioned (will trigger CVE lookup) */}
              {techTestResult.versioned.length > 0 ? (
                <div>
                  <p className="text-xs font-semibold text-green-400 mb-2">
                    Versioned — will trigger NVD CVE lookup ({techTestResult.versionedCount})
                  </p>
                  <div className="space-y-1">
                    {techTestResult.versioned.map((v) => (
                      <div key={v.raw} className="flex items-center gap-3 text-xs p-2 bg-green-500/5 border border-green-500/20 rounded">
                        <CheckCircle2 className="w-3.5 h-3.5 text-green-500 shrink-0" />
                        <span className="font-semibold text-foreground">{v.name}</span>
                        <span className="font-mono text-primary">{v.version}</span>
                        <span className="text-muted-foreground">raw: {v.raw}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-500 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-yellow-400">No versioned technologies detected</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{techTestResult.note}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Section 4: CVE Cache ──────────────────────────────────────── */}
      {status && status.cveCache.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-primary" /> CVE Cache ({status.cveCache.length} entries)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {status.cveCache.map((entry, i) => (
                <div key={i} className="flex items-center gap-4 text-sm p-2 hover:bg-foreground/5 rounded">
                  <span className="font-semibold text-foreground w-28 shrink-0">{entry.technology}</span>
                  <span className="font-mono text-primary w-20 shrink-0">{entry.version}</span>
                  <span className={`text-xs font-medium ${entry.cveCount > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>
                    {entry.cveCount} CVEs
                  </span>
                  {entry.topCves.length > 0 && (
                    <span className="text-xs text-muted-foreground font-mono">{entry.topCves.join(', ')}</span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Section 5: Active Scan Assets + CVEs ─────────────────────── */}
      {status && status.activeScans.length > 0 && status.activeScans.map((scan) => (
        <Card key={scan.scanId} className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="w-4 h-4 text-primary" />
              Scan: {scan.target}
              <span className={`text-xs px-2 py-0.5 rounded ml-2 ${
                scan.status === 'completed' ? 'bg-green-500/10 text-green-400' : 'bg-blue-500/10 text-blue-400'
              }`}>{scan.status}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Counters */}
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-foreground">{scan.totalAssets}</div>
                <div className="text-xs text-muted-foreground">Total Assets</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-500">{scan.liveAssets}</div>
                <div className="text-xs text-muted-foreground">Live Assets</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">{scan.totalCves}</div>
                <div className="text-xs text-muted-foreground">CVE Documents</div>
              </div>
            </div>

            {/* Detected technologies */}
            {scan.detectedTechs.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-2">
                  Detected Technologies ({scan.detectedTechs.length})
                </p>
                <div className="space-y-1">
                  {scan.detectedTechs.map((t, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs">
                      {t.version
                        ? <CheckCircle2 className="w-3 h-3 text-green-500 shrink-0" />
                        : <XCircle className="w-3 h-3 text-muted-foreground shrink-0" />}
                      <span className="text-foreground font-medium">{t.technology}</span>
                      {t.version
                        ? <span className="font-mono text-primary">{t.version}</span>
                        : <span className="text-muted-foreground">no version</span>}
                      <span className="text-muted-foreground truncate">{t.assetUrl}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* CVE Documents */}
            {scan.cveDocuments.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-2">
                  CVE Documents (first {scan.cveDocuments.length})
                </p>
                <div className="space-y-1">
                  {scan.cveDocuments.map((cve, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs p-1.5 hover:bg-foreground/5 rounded">
                      <span className="font-mono text-foreground w-36 shrink-0">{cve.cveId}</span>
                      <span className={`w-16 shrink-0 ${SEVERITY_COLORS[cve.severity] ?? 'text-gray-400'}`}>{cve.severity}</span>
                      <span className="text-muted-foreground">CVSS {cve.cvssScore}</span>
                      <span className="text-muted-foreground">{cve.technology} {cve.version}</span>
                      <span className="text-muted-foreground truncate">{cve.assetUrl}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {scan.totalCves === 0 && scan.status === 'completed' && (
              <div className="p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg text-xs text-yellow-400">
                <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
                No CVEs found. Check detected technologies above — only techs with a version trigger NVD lookup.
                Run the Technology Detection test to verify version detection.
              </div>
            )}
          </CardContent>
        </Card>
      ))}

      {/* ── Section 6: Pipeline Stages Reference ─────────────────────── */}
      {status && (
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle className="text-base">Pipeline Stages Reference</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {status.pipelineStages.map((s, i) => (
                <div key={i} className="text-xs text-muted-foreground py-1 border-b border-foreground/5 last:border-0">
                  {s}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
