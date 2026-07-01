'use client'

import { Fragment, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  Search, ShieldAlert, Zap, AlertTriangle, Bug,
  ChevronDown, ChevronRight, Globe, X, ExternalLink, Server,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { listenToFindings, type FirestoreFinding } from '@/lib/firestore-findings'
import { listenToCves, type FirestoreCve } from '@/lib/firestore-cves'
import { listenToNetworkFindings, type FirestoreNetworkFinding } from '@/lib/firestore-network-findings'
import { listenToNetworkCves, type FirestoreNetworkCve } from '@/lib/firestore-network-cves'
import { useAuth } from '@/context/auth-context'

// ── Types ──────────────────────────────────────────────────────────────

type ModuleFilter = 'all' | 'web' | 'network'
type TypeFilter   = 'findings' | 'cves'
type Module       = 'web' | 'network'

interface NormalizedFinding {
  id:          string
  module:      Module
  severity:    string
  title:       string
  target:      string
  scanner:     string
  template:    string
  description: string
  createdAt:   string
  scanId:      string
  port?:       number | null
  host?:       string | null
}

interface NormalizedCve {
  id:               string
  module:           Module
  cveId:            string
  technology:       string
  version:          string
  cvssScore:        number
  severity:         string
  exploitAvailable: boolean
  target:           string
  published:        string | null
  description:      string
  scanId:           string
  createdAt:        string
}

interface TargetSummary {
  key:       string
  target:    string
  module:    Module
  findings:  NormalizedFinding[]
  cveCount:  number
  scanCount: number
  latestAt:  string
  total:     number
  critical:  number
  high:      number
  medium:    number
  low:       number
  info:      number
}

interface CveTargetSummary {
  key:         string
  target:      string
  module:      Module
  cves:        NormalizedCve[]
  latestAt:    string
  total:       number
  critical:    number
  high:        number
  medium:      number
  low:         number
  exploitable: number
}

// ── Constants ──────────────────────────────────────────────────────────

const MODULE_BADGE: Record<Module, { label: string; cls: string }> = {
  web:     { label: 'WEB',     cls: 'bg-blue-500/15 text-blue-400 border-blue-500/25'    },
  network: { label: 'NETWORK', cls: 'bg-green-500/15 text-green-400 border-green-500/25' },
}

const MODULE_ICON: Record<Module, React.ComponentType<{ className?: string }>> = {
  web:     Globe,
  network: Server,
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border border-red-500/25',
  high:     'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  medium:   'bg-yellow-500/15 text-yellow-500 border border-yellow-500/25',
  low:      'bg-blue-500/15 text-blue-400 border border-blue-500/25',
  info:     'bg-slate-500/15 text-slate-400 border border-slate-500/25',
  unknown:  'bg-gray-500/15 text-gray-400 border border-gray-500/25',
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/25',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  MEDIUM:   'bg-yellow-500/15 text-yellow-500 border border-yellow-500/25',
  LOW:      'bg-blue-500/15 text-blue-400 border border-blue-500/25',
  NONE:     'bg-gray-500/15 text-gray-400 border border-gray-500/25',
}

const SEV_ORDER: Record<string, number> = {
  critical: 0, CRITICAL: 0,
  high:     1, HIGH:     1,
  medium:   2, MEDIUM:   2,
  low:      3, LOW:      3,
  info:     4, INFO:     4,
  none:     5, NONE:     5,
  unknown:  6,
}

const MODULE_FILTERS: { value: ModuleFilter; label: string }[] = [
  { value: 'all',     label: 'All Modules'      },
  { value: 'web',     label: 'Web Security'     },
  { value: 'network', label: 'Network Security' },
]

const FINDING_SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info'] as const
const CVE_SEV_KEYS     = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']  as const

// ── Normalize helpers ──────────────────────────────────────────────────

function normalizeFinding(f: FirestoreFinding): NormalizedFinding {
  return {
    id: f.findingId, module: 'web',
    severity: (f.severity ?? 'unknown').toLowerCase(),
    title: f.title, target: f.target,
    scanner: f.source ?? 'nuclei', template: f.template,
    description: f.description ?? '',
    createdAt: f.createdAt, scanId: f.scanId, host: f.host ?? null,
  }
}

function normalizeNetworkFinding(f: FirestoreNetworkFinding): NormalizedFinding {
  return {
    id: f.findingId, module: 'network',
    severity: (f.severity ?? 'unknown').toLowerCase(),
    title: f.title, target: f.ip,
    scanner: f.source, template: f.template,
    description: f.description ?? '',
    createdAt: f.createdAt, scanId: f.scanId,
    port: f.port ?? null, host: f.host ?? null,
  }
}

function normalizeCve(c: FirestoreCve): NormalizedCve {
  return {
    id: c.id, module: 'web',
    cveId: c.cveId, technology: c.technology, version: c.version,
    cvssScore: c.cvssScore, severity: c.severity,
    exploitAvailable: c.exploitAvailable,
    target: c.assetUrl, published: c.published ?? null,
    description: c.description, scanId: c.discoveryId,
    createdAt: c.createdAt,
  }
}

function normalizeNetworkCve(c: FirestoreNetworkCve): NormalizedCve {
  return {
    id: c.id, module: 'network',
    cveId: c.cveId, technology: c.technology, version: c.version,
    cvssScore: c.cvssScore, severity: c.severity,
    exploitAvailable: c.exploitAvailable,
    target: c.ip, published: c.published ?? null,
    description: c.description, scanId: c.scanId,
    createdAt: c.createdAt,
  }
}

// ── Display helpers ────────────────────────────────────────────────────

function formatRelative(iso: string) {
  if (!iso) return '—'
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000)
  if (mins < 2)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function cvssColor(score: number) {
  if (score >= 9.0) return 'text-red-400'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-400'
  return 'text-blue-400'
}

// ── Grouping helpers ───────────────────────────────────────────────────

function buildTargetSummaries(
  findings: NormalizedFinding[],
  cves: NormalizedCve[],
): TargetSummary[] {
  const map = new Map<string, TargetSummary & { _scanIds: Set<string> }>()

  for (const f of findings) {
    const key = `${f.module}~${f.target}`
    if (!map.has(key)) {
      map.set(key, {
        key, target: f.target, module: f.module,
        findings: [], cveCount: 0, scanCount: 0, latestAt: f.createdAt,
        total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
        _scanIds: new Set(),
      })
    }
    const g = map.get(key)!
    g.findings.push(f)
    g._scanIds.add(f.scanId)
    if (f.createdAt > g.latestAt) g.latestAt = f.createdAt
  }

  const cveCounts = new Map<string, number>()
  for (const c of cves) {
    const k = `${c.module}~${c.target}`
    cveCounts.set(k, (cveCounts.get(k) ?? 0) + 1)
  }

  const results: TargetSummary[] = []
  for (const [key, g] of map) {
    results.push({
      key, target: g.target, module: g.module, findings: g.findings,
      latestAt:  g.latestAt,
      cveCount:  cveCounts.get(key) ?? 0,
      scanCount: g._scanIds.size,
      total:     g.findings.length,
      critical:  g.findings.filter(f => f.severity === 'critical').length,
      high:      g.findings.filter(f => f.severity === 'high').length,
      medium:    g.findings.filter(f => f.severity === 'medium').length,
      low:       g.findings.filter(f => f.severity === 'low').length,
      info:      g.findings.filter(f => f.severity === 'info').length,
    })
  }

  return results.sort((a, b) =>
    b.critical - a.critical ||
    b.high     - a.high     ||
    b.medium   - a.medium   ||
    new Date(b.latestAt).getTime() - new Date(a.latestAt).getTime(),
  )
}

function buildCveTargetSummaries(cves: NormalizedCve[]): CveTargetSummary[] {
  const map = new Map<string, CveTargetSummary>()

  for (const c of cves) {
    const key = `${c.module}~${c.target}`
    if (!map.has(key)) {
      map.set(key, {
        key, target: c.target, module: c.module,
        cves: [], latestAt: c.createdAt,
        total: 0, critical: 0, high: 0, medium: 0, low: 0, exploitable: 0,
      })
    }
    const g = map.get(key)!
    g.cves.push(c)
    if (c.createdAt > g.latestAt) g.latestAt = c.createdAt
  }

  const results: CveTargetSummary[] = []
  for (const [, g] of map) {
    results.push({
      ...g,
      total:      g.cves.length,
      critical:   g.cves.filter(c => c.severity === 'CRITICAL').length,
      high:       g.cves.filter(c => c.severity === 'HIGH').length,
      medium:     g.cves.filter(c => c.severity === 'MEDIUM').length,
      low:        g.cves.filter(c => c.severity === 'LOW').length,
      exploitable: g.cves.filter(c => c.exploitAvailable).length,
    })
  }

  return results.sort((a, b) =>
    b.critical - a.critical ||
    b.high     - a.high     ||
    b.medium   - a.medium   ||
    new Date(b.latestAt).getTime() - new Date(a.latestAt).getTime(),
  )
}

function cardSevCount(s: TargetSummary | CveTargetSummary, sev: string): number {
  const k = sev.toLowerCase()
  if (k === 'critical') return s.critical
  if (k === 'high')     return s.high
  if (k === 'medium')   return s.medium
  if (k === 'low')      return s.low
  if (k === 'info' && 'info' in s) return (s as TargetSummary).info
  return 0
}

// ── Badge components ───────────────────────────────────────────────────

function ModuleBadge({ module }: { module: Module }) {
  const { label, cls } = MODULE_BADGE[module]
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border tracking-wide ${cls}`}>
      {label}
    </span>
  )
}

function SevBadge({ severity }: { severity: string }) {
  const cls   = SEV_BADGE[severity] ?? SEV_BADGE.unknown
  const label = severity.toUpperCase()
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide ${cls}`}>
      {label === 'UNKNOWN' ? '?' : label.slice(0, 4)}
    </span>
  )
}

// ── Risk accent bar (top of card, color = highest severity) ────────────

function RiskBar({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  const cls =
    critical > 0 ? 'bg-red-500' :
    high     > 0 ? 'bg-orange-500' :
    medium   > 0 ? 'bg-yellow-500' :
    low      > 0 ? 'bg-blue-500' :
    'bg-slate-600/40'
  return <div className={`h-[3px] w-full ${cls}`} />
}

function RiskLabel({ critical, high, medium, low, total }: { critical: number; high: number; medium: number; low: number; total: number }) {
  if (total === 0) return <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Clean</span>
  if (critical > 0) return <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Critical Risk</span>
  if (high     > 0) return <span className="text-[10px] font-semibold text-orange-400 uppercase tracking-wider">High Risk</span>
  if (medium   > 0) return <span className="text-[10px] font-semibold text-yellow-500 uppercase tracking-wider">Medium Risk</span>
  return <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider">Low Risk</span>
}

// ── Target cards ───────────────────────────────────────────────────────

function TargetCard({
  summary,
  isSelected,
  onToggle,
}: {
  summary:    TargetSummary
  isSelected: boolean
  onToggle:   () => void
}) {
  const Icon   = MODULE_ICON[summary.module]
  const maxSev = Math.max(summary.critical, summary.high, summary.medium, summary.low, summary.info, 1)

  return (
    <div className={`bg-card rounded-xl border overflow-hidden flex flex-col transition-all duration-200 ${
      isSelected
        ? 'border-primary/50 shadow-lg shadow-primary/10 ring-1 ring-primary/20'
        : 'border-foreground/10 hover:border-foreground/25 hover:shadow-md hover:shadow-black/8'
    }`}>

      {/* Severity accent bar */}
      <RiskBar critical={summary.critical} high={summary.high} medium={summary.medium} low={summary.low} />

      {/* Body */}
      <div className="p-5 flex flex-col gap-4 flex-1">

        {/* Target + module row */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <Icon className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0 mt-0.5" />
            <span
              className="text-sm font-semibold text-foreground truncate font-mono"
              title={summary.target}
            >
              {summary.target}
            </span>
          </div>
          <ModuleBadge module={summary.module} />
        </div>

        {/* Risk label + total */}
        <div className="flex items-end justify-between">
          <div>
            <RiskLabel
              critical={summary.critical} high={summary.high}
              medium={summary.medium} low={summary.low} total={summary.total}
            />
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-4xl font-bold text-foreground tabular-nums leading-none">
                {summary.total}
              </span>
              <span className="text-sm text-muted-foreground">
                finding{summary.total !== 1 ? 's' : ''}
              </span>
            </div>
          </div>
          {summary.cveCount > 0 && (
            <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/25 shrink-0">
              {summary.cveCount} CVE{summary.cveCount !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {/* Severity breakdown bars */}
        <div className="space-y-2">
          {[
            { label: 'Critical', count: summary.critical, bar: 'bg-red-500',    num: 'text-red-400'    },
            { label: 'High',     count: summary.high,     bar: 'bg-orange-500', num: 'text-orange-400' },
            { label: 'Medium',   count: summary.medium,   bar: 'bg-yellow-500', num: 'text-yellow-500' },
            { label: 'Low',      count: summary.low,      bar: 'bg-blue-500',   num: 'text-blue-400'   },
            { label: 'Info',     count: summary.info,     bar: 'bg-slate-500',  num: 'text-slate-400'  },
          ].map(({ label, count, bar, num }) => (
            <div key={label} className="flex items-center gap-2.5">
              <span className="text-xs text-muted-foreground/70 w-11 shrink-0">{label}</span>
              <div className="flex-1 h-1.5 bg-foreground/[0.06] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${bar}`}
                  style={{ width: count === 0 ? '0%' : `${(count / maxSev) * 100}%`, opacity: count === 0 ? 0 : 1 }}
                />
              </div>
              <span className={`text-xs font-bold w-5 text-right tabular-nums ${count > 0 ? num : 'text-muted-foreground/25'}`}>
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="px-5 py-3 bg-foreground/[0.025] border-t border-foreground/8 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/60 min-w-0">
          <span className="shrink-0">{formatRelative(summary.latestAt)}</span>
          {summary.scanCount > 1 && (
            <>
              <span className="text-foreground/20">·</span>
              <span className="shrink-0">{summary.scanCount} scans</span>
            </>
          )}
        </div>
        <Button
          size="sm"
          onClick={onToggle}
          variant={isSelected ? 'default' : 'outline'}
          className={`h-7 text-xs rounded-lg shrink-0 gap-1.5 min-w-[110px] justify-center ${
            isSelected ? '' : 'border-foreground/20 text-foreground hover:bg-foreground/8'
          }`}
        >
          {isSelected ? (
            <><ChevronDown className="w-3 h-3" /> Hide</>
          ) : (
            <>View Findings <ChevronRight className="w-3 h-3" /></>
          )}
        </Button>
      </div>
    </div>
  )
}

function CveTargetCard({
  summary,
  isSelected,
  onToggle,
}: {
  summary:    CveTargetSummary
  isSelected: boolean
  onToggle:   () => void
}) {
  const Icon   = MODULE_ICON[summary.module]
  const maxSev = Math.max(summary.critical, summary.high, summary.medium, summary.low, 1)

  return (
    <div className={`bg-card rounded-xl border overflow-hidden flex flex-col transition-all duration-200 ${
      isSelected
        ? 'border-primary/50 shadow-lg shadow-primary/10 ring-1 ring-primary/20'
        : 'border-foreground/10 hover:border-foreground/25 hover:shadow-md hover:shadow-black/8'
    }`}>
      <RiskBar critical={summary.critical} high={summary.high} medium={summary.medium} low={summary.low} />

      <div className="p-5 flex flex-col gap-4 flex-1">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <Icon className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0 mt-0.5" />
            <span className="text-sm font-semibold text-foreground truncate font-mono" title={summary.target}>
              {summary.target}
            </span>
          </div>
          <ModuleBadge module={summary.module} />
        </div>

        <div className="flex items-end justify-between">
          <div>
            <RiskLabel
              critical={summary.critical} high={summary.high}
              medium={summary.medium} low={summary.low} total={summary.total}
            />
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-4xl font-bold text-foreground tabular-nums leading-none">{summary.total}</span>
              <span className="text-sm text-muted-foreground">CVE{summary.total !== 1 ? 's' : ''}</span>
            </div>
          </div>
          {summary.exploitable > 0 && (
            <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/25 shrink-0">
              <Zap className="w-3 h-3" /> {summary.exploitable} exploit{summary.exploitable !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        <div className="space-y-2">
          {[
            { label: 'Critical', count: summary.critical, bar: 'bg-red-500',    num: 'text-red-400'    },
            { label: 'High',     count: summary.high,     bar: 'bg-orange-500', num: 'text-orange-400' },
            { label: 'Medium',   count: summary.medium,   bar: 'bg-yellow-500', num: 'text-yellow-500' },
            { label: 'Low',      count: summary.low,      bar: 'bg-blue-500',   num: 'text-blue-400'   },
          ].map(({ label, count, bar, num }) => (
            <div key={label} className="flex items-center gap-2.5">
              <span className="text-xs text-muted-foreground/70 w-11 shrink-0">{label}</span>
              <div className="flex-1 h-1.5 bg-foreground/[0.06] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${bar}`}
                  style={{ width: count === 0 ? '0%' : `${(count / maxSev) * 100}%`, opacity: count === 0 ? 0 : 1 }}
                />
              </div>
              <span className={`text-xs font-bold w-5 text-right tabular-nums ${count > 0 ? num : 'text-muted-foreground/25'}`}>
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="px-5 py-3 bg-foreground/[0.025] border-t border-foreground/8 flex items-center justify-between gap-3">
        <span className="text-[11px] text-muted-foreground/60">{formatRelative(summary.latestAt)}</span>
        <Button
          size="sm"
          onClick={onToggle}
          variant={isSelected ? 'default' : 'outline'}
          className={`h-7 text-xs rounded-lg shrink-0 gap-1.5 min-w-[100px] justify-center ${
            isSelected ? '' : 'border-foreground/20 text-foreground hover:bg-foreground/8'
          }`}
        >
          {isSelected ? (
            <><ChevronDown className="w-3 h-3" /> Hide</>
          ) : (
            <>View CVEs <ChevronRight className="w-3 h-3" /></>
          )}
        </Button>
      </div>
    </div>
  )
}

// ── Findings detail panel ──────────────────────────────────────────────

function FindingsPanel({
  summary,
  onClose,
  onViewScanReport,
}: {
  summary:          TargetSummary
  onClose:          () => void
  onViewScanReport: (scanId: string) => void
}) {
  const Icon = MODULE_ICON[summary.module]
  const [panelSearch, setPanelSearch] = useState('')
  const [expandedId,  setExpandedId]  = useState<string | null>(null)

  const rows = useMemo(() => {
    let r = [...summary.findings].sort((a, b) =>
      (SEV_ORDER[a.severity] ?? 6) - (SEV_ORDER[b.severity] ?? 6),
    )
    if (panelSearch.trim()) {
      const q = panelSearch.toLowerCase()
      r = r.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.template.toLowerCase().includes(q) ||
        f.scanner.toLowerCase().includes(q),
      )
    }
    return r
  }, [summary.findings, panelSearch])

  return (
    <div className="bg-card border border-primary/25 rounded-xl overflow-hidden shadow-lg shadow-primary/5">

      {/* Panel header */}
      <div className="flex items-center justify-between gap-4 px-5 py-3.5 border-b border-foreground/10 bg-primary/[0.03]">
        <div className="flex items-center gap-2.5 min-w-0">
          <Icon className="w-4 h-4 text-muted-foreground/70 shrink-0" />
          <span className="text-sm font-semibold text-foreground truncate font-mono">{summary.target}</span>
          <span className="text-xs text-muted-foreground/50 shrink-0">— {summary.total} findings</span>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/40" />
            <input
              placeholder="Filter within target…"
              value={panelSearch}
              onChange={(e) => setPanelSearch(e.target.value)}
              className="pl-7 pr-3 py-1.5 bg-foreground/5 border border-foreground/15 rounded-lg text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-primary/40 w-48"
            />
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
            title="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="py-12 text-center text-sm text-muted-foreground/60">
          No findings match your filter.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-foreground/8 bg-foreground/[0.02]">
                {['Severity', 'Title', 'Target', 'Scanner', 'Status', 'Created', ''].map((h) => (
                  <th
                    key={h}
                    className="text-left py-2.5 px-3 first:px-4 text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => {
                const isExp  = expandedId === row.id
                const rowCls = isExp
                  ? 'bg-primary/5'
                  : i % 2 === 1
                    ? 'bg-foreground/[0.015] hover:bg-foreground/[0.04]'
                    : 'hover:bg-foreground/[0.03]'
                return (
                  <Fragment key={row.id}>
                    <tr
                      className={`border-b border-foreground/5 cursor-pointer transition-colors ${rowCls}`}
                      onClick={() => setExpandedId(p => p === row.id ? null : row.id)}
                    >
                      <td className="py-2.5 px-4"><SevBadge severity={row.severity} /></td>
                      <td className="py-2.5 px-3 max-w-[280px]">
                        <p className="text-sm text-foreground font-medium truncate">{row.title}</p>
                        <p className="text-[10px] text-muted-foreground/45 font-mono truncate mt-0.5">{row.template}</p>
                      </td>
                      <td className="py-2.5 px-3 max-w-[160px]">
                        <span className="text-xs font-mono text-muted-foreground truncate block">{row.target}</span>
                        {row.port != null && <span className="text-[10px] text-muted-foreground/45">:{row.port}</span>}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-muted-foreground capitalize">{row.scanner}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-500 border border-yellow-500/20">
                          Open
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatRelative(row.createdAt)}
                      </td>
                      <td className="py-2.5 px-3 w-6">
                        {isExp
                          ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/55" />
                          : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/30" />}
                      </td>
                    </tr>
                    {isExp && (
                      <tr className="border-b border-foreground/5 bg-primary/[0.03]">
                        <td colSpan={7} className="px-5 py-4">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                            <div className="md:col-span-2">
                              <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-wider mb-1.5">
                                Description
                              </p>
                              <p className="text-xs text-muted-foreground leading-relaxed">
                                {row.description || 'No description available.'}
                              </p>
                            </div>
                            <div className="space-y-3">
                              <div>
                                <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-wider mb-1.5">
                                  Details
                                </p>
                                <div className="space-y-0.5 text-[11px] font-mono text-muted-foreground">
                                  <p>Scan: <span className="text-foreground/65">{row.scanId}</span></p>
                                  <p>Template: <span className="text-foreground/65">{row.template}</span></p>
                                  {row.port != null && <p>Port: <span className="text-foreground/65">{row.port}</span></p>}
                                  {row.host && <p>Host: <span className="text-foreground/65">{row.host}</span></p>}
                                </div>
                              </div>
                              {row.module === 'web' && (
                                <Button
                                  variant="outline" size="sm"
                                  className="h-7 text-xs border-foreground/20 rounded-lg gap-1.5"
                                  onClick={(e) => { e.stopPropagation(); onViewScanReport(row.scanId) }}
                                >
                                  <ExternalLink className="w-3 h-3" />
                                  View Scan Report
                                </Button>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── CVE detail panel ───────────────────────────────────────────────────

function CvesPanel({
  summary,
  onClose,
}: {
  summary: CveTargetSummary
  onClose: () => void
}) {
  const Icon = MODULE_ICON[summary.module]
  const [panelSearch, setPanelSearch] = useState('')
  const [expandedId,  setExpandedId]  = useState<string | null>(null)

  const rows = useMemo(() => {
    let r = [...summary.cves].sort((a, b) =>
      (SEV_ORDER[a.severity] ?? 6) - (SEV_ORDER[b.severity] ?? 6) || b.cvssScore - a.cvssScore,
    )
    if (panelSearch.trim()) {
      const q = panelSearch.toLowerCase()
      r = r.filter(c =>
        c.cveId.toLowerCase().includes(q) ||
        c.technology.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q),
      )
    }
    return r
  }, [summary.cves, panelSearch])

  return (
    <div className="bg-card border border-primary/25 rounded-xl overflow-hidden shadow-lg shadow-primary/5">

      <div className="flex items-center justify-between gap-4 px-5 py-3.5 border-b border-foreground/10 bg-primary/[0.03]">
        <div className="flex items-center gap-2.5 min-w-0">
          <Icon className="w-4 h-4 text-muted-foreground/70 shrink-0" />
          <span className="text-sm font-semibold text-foreground truncate font-mono">{summary.target}</span>
          <span className="text-xs text-muted-foreground/50 shrink-0">— {summary.total} CVEs</span>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/40" />
            <input
              placeholder="Filter CVEs…"
              value={panelSearch}
              onChange={(e) => setPanelSearch(e.target.value)}
              className="pl-7 pr-3 py-1.5 bg-foreground/5 border border-foreground/15 rounded-lg text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-primary/40 w-44"
            />
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="py-12 text-center text-sm text-muted-foreground/60">
          No CVEs match your filter.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-foreground/8 bg-foreground/[0.02]">
                {['CVE ID', 'Technology', 'Version', 'Severity', 'CVSS', 'Exploit', 'Published', ''].map((h) => (
                  <th key={h} className="text-left py-2.5 px-3 first:px-4 text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => {
                const isExp  = expandedId === row.id
                const rowCls = isExp
                  ? 'bg-primary/5'
                  : i % 2 === 1
                    ? 'bg-foreground/[0.015] hover:bg-foreground/[0.04]'
                    : 'hover:bg-foreground/[0.03]'
                return (
                  <Fragment key={row.id}>
                    <tr
                      className={`border-b border-foreground/5 cursor-pointer transition-colors ${rowCls}`}
                      onClick={() => setExpandedId(p => p === row.id ? null : row.id)}
                    >
                      <td className="py-2.5 px-4">
                        <span className="text-xs font-mono font-semibold text-primary">{row.cveId}</span>
                      </td>
                      <td className="py-2.5 px-3"><span className="text-sm text-foreground">{row.technology}</span></td>
                      <td className="py-2.5 px-3"><span className="text-xs font-mono text-muted-foreground">{row.version}</span></td>
                      <td className="py-2.5 px-3"><SevBadge severity={row.severity} /></td>
                      <td className="py-2.5 px-3">
                        <span className={`text-sm font-bold ${cvssColor(row.cvssScore)}`}>{row.cvssScore.toFixed(1)}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        {row.exploitAvailable ? (
                          <span className="flex items-center gap-1 text-xs text-red-400 font-medium">
                            <Zap className="w-3 h-3" /> Yes
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(row.published)}
                      </td>
                      <td className="py-2.5 px-3 w-6">
                        {isExp
                          ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/55" />
                          : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/30" />}
                      </td>
                    </tr>
                    {isExp && (
                      <tr className="border-b border-foreground/5 bg-primary/[0.03]">
                        <td colSpan={8} className="px-5 py-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                            <div>
                              <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-wider mb-1.5">Description</p>
                              <p className="text-xs text-muted-foreground leading-relaxed">
                                {row.description || 'No description available.'}
                              </p>
                            </div>
                            <div>
                              <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-wider mb-1.5">Details</p>
                              <div className="space-y-0.5 text-[11px] font-mono text-muted-foreground">
                                <p>Scan ID: <span className="text-foreground/65">{row.scanId}</span></p>
                                <p>Target: <span className="text-foreground/65">{row.target}</span></p>
                                {row.published && <p>Published: <span className="text-foreground/65">{formatDate(row.published)}</span></p>}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Main page content ──────────────────────────────────────────────────

function VulnMgmtContent() {
  const router       = useRouter()
  const searchParams = useSearchParams()
  const { user }     = useAuth()

  const rawModule = searchParams.get('module') ?? 'all'
  const rawType   = searchParams.get('type')   ?? 'findings'
  const moduleFilter: ModuleFilter = (['all', 'web', 'network'] as const).includes(rawModule as ModuleFilter)
    ? rawModule as ModuleFilter : 'all'
  const typeFilter: TypeFilter = rawType === 'cves' ? 'cves' : 'findings'

  // Raw Firestore state
  const [webFindings, setWebFindings] = useState<FirestoreFinding[]>([])
  const [netFindings, setNetFindings] = useState<FirestoreNetworkFinding[]>([])
  const [webCves,     setWebCves]     = useState<FirestoreCve[]>([])
  const [netCves,     setNetCves]     = useState<FirestoreNetworkCve[]>([])

  // Filter state
  const [search,    setSearch]    = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)

  // Selected target for inline detail panel
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  function pushParams(updates: Partial<{ module: string; type: string }>) {
    const p = new URLSearchParams(searchParams.toString())
    Object.entries(updates).forEach(([k, v]) => p.set(k, v))
    router.replace(`/app/findings?${p.toString()}`, { scroll: false })
    setSearch('')
    setSevFilter(null)
    setSelectedKey(null)
  }

  useEffect(() => {
    if (!user) return
    const u1 = listenToFindings(user.uid, setWebFindings)
    const u2 = listenToNetworkFindings(user.uid, setNetFindings)
    const u3 = listenToCves(user.uid, setWebCves)
    const u4 = listenToNetworkCves(user.uid, setNetCves)
    return () => { u1(); u2(); u3(); u4() }
  }, [user])

  // Normalize
  const allFindings = useMemo<NormalizedFinding[]>(() => [
    ...webFindings.map(normalizeFinding),
    ...netFindings.map(normalizeNetworkFinding),
  ], [webFindings, netFindings])

  const allCves = useMemo<NormalizedCve[]>(() => [
    ...webCves.map(normalizeCve),
    ...netCves.map(normalizeNetworkCve),
  ], [webCves, netCves])

  // Module filter
  const moduleFindings = useMemo(() =>
    moduleFilter === 'all' ? allFindings : allFindings.filter(f => f.module === moduleFilter),
  [allFindings, moduleFilter])

  const moduleCves = useMemo(() =>
    moduleFilter === 'all' ? allCves : allCves.filter(c => c.module === moduleFilter),
  [allCves, moduleFilter])

  // Build target summaries (grouped by target)
  const allFindingSummaries = useMemo(
    () => buildTargetSummaries(moduleFindings, moduleCves),
    [moduleFindings, moduleCves],
  )

  const allCveSummaries = useMemo(
    () => buildCveTargetSummaries(moduleCves),
    [moduleCves],
  )

  // Filter cards by search + severity
  const visibleFindingSummaries = useMemo(() => {
    let r = allFindingSummaries
    if (sevFilter) r = r.filter(s => cardSevCount(s, sevFilter) > 0)
    if (search.trim()) {
      const q = search.toLowerCase()
      r = r.filter(s => s.target.toLowerCase().includes(q))
    }
    return r
  }, [allFindingSummaries, sevFilter, search])

  const visibleCveSummaries = useMemo(() => {
    let r = allCveSummaries
    if (sevFilter) r = r.filter(s => cardSevCount(s, sevFilter) > 0)
    if (search.trim()) {
      const q = search.toLowerCase()
      r = r.filter(s => s.target.toLowerCase().includes(q))
    }
    return r
  }, [allCveSummaries, sevFilter, search])

  // Global stats (from module-filtered data, not card-filtered)
  const findingStats = useMemo(() => ({
    total:    moduleFindings.length,
    critical: moduleFindings.filter(f => f.severity === 'critical').length,
    high:     moduleFindings.filter(f => f.severity === 'high').length,
    medium:   moduleFindings.filter(f => f.severity === 'medium').length,
    low:      moduleFindings.filter(f => f.severity === 'low').length,
    info:     moduleFindings.filter(f => f.severity === 'info').length,
  }), [moduleFindings])

  const cveStats = useMemo(() => ({
    total:       moduleCves.length,
    critical:    moduleCves.filter(c => c.severity === 'CRITICAL').length,
    high:        moduleCves.filter(c => c.severity === 'HIGH').length,
    medium:      moduleCves.filter(c => c.severity === 'MEDIUM').length,
    low:         moduleCves.filter(c => c.severity === 'LOW').length,
    exploitable: moduleCves.filter(c => c.exploitAvailable).length,
  }), [moduleCves])

  const stats = typeFilter === 'cves'
    ? [
        { label: 'Total CVEs',  value: cveStats.total,       cls: 'text-foreground' },
        { label: 'Critical',    value: cveStats.critical,     cls: 'text-red-400'    },
        { label: 'High',        value: cveStats.high,         cls: 'text-orange-400' },
        { label: 'Medium',      value: cveStats.medium,       cls: 'text-yellow-400' },
        { label: 'Low',         value: cveStats.low,          cls: 'text-blue-400'   },
        { label: 'Exploitable', value: cveStats.exploitable,  cls: 'text-red-400'    },
      ]
    : [
        { label: 'Total',    value: findingStats.total,    cls: 'text-foreground' },
        { label: 'Critical', value: findingStats.critical,  cls: 'text-red-400'    },
        { label: 'High',     value: findingStats.high,      cls: 'text-orange-400' },
        { label: 'Medium',   value: findingStats.medium,    cls: 'text-yellow-400' },
        { label: 'Low',      value: findingStats.low,       cls: 'text-blue-400'   },
        { label: 'Info',     value: findingStats.info,      cls: 'text-slate-400'  },
      ]

  const sevKeys = typeFilter === 'cves' ? CVE_SEV_KEYS : FINDING_SEV_KEYS

  // Selected summaries for detail panels
  const selectedFindingSummary = useMemo(
    () => selectedKey ? allFindingSummaries.find(s => s.key === selectedKey) ?? null : null,
    [selectedKey, allFindingSummaries],
  )
  const selectedCveSummary = useMemo(
    () => selectedKey ? allCveSummaries.find(s => s.key === selectedKey) ?? null : null,
    [selectedKey, allCveSummaries],
  )

  function handleToggleCard(key: string) {
    const opening = selectedKey !== key
    setSelectedKey(opening ? key : null)
    if (opening) {
      setTimeout(() => panelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 80)
    }
  }

  const cardCount = typeFilter === 'findings' ? visibleFindingSummaries.length : visibleCveSummaries.length
  const totalTargets = typeFilter === 'findings' ? allFindingSummaries.length : allCveSummaries.length

  return (
    <div className="p-6 space-y-5">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold text-foreground tracking-tight">Vulnerability Management</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {cardCount === totalTargets
            ? `${totalTargets} scanned target${totalTargets !== 1 ? 's' : ''}`
            : `${cardCount} of ${totalTargets} targets`}
          {moduleFilter !== 'all' && (
            <span className="ml-1.5 text-muted-foreground/50">
              · {moduleFilter === 'web' ? 'Web Security' : 'Network Security'}
            </span>
          )}
        </p>
      </div>

      {/* ── Filter bar ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">

        {/* Module filter */}
        <div className="flex items-center gap-0.5 p-1 bg-foreground/5 rounded-lg border border-foreground/8">
          {MODULE_FILTERS.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => pushParams({ module: value, type: typeFilter })}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                moduleFilter === value
                  ? 'bg-card text-foreground shadow-sm border border-foreground/12'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {label}
            </button>
          ))}
          <button
            disabled
            title="Cloud — coming soon"
            className="px-3 py-1.5 rounded-md text-xs font-medium text-muted-foreground/30 cursor-not-allowed"
          >
            Cloud
          </button>
        </div>

        <div className="h-6 w-px bg-foreground/10" />

        {/* Type filter */}
        <div className="flex items-center gap-0.5 p-1 bg-foreground/5 rounded-lg border border-foreground/8">
          <button
            onClick={() => pushParams({ module: moduleFilter, type: 'findings' })}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              typeFilter === 'findings'
                ? 'bg-card text-foreground shadow-sm border border-foreground/12'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <AlertTriangle className="w-3 h-3" /> Findings
          </button>
          <button
            onClick={() => pushParams({ module: moduleFilter, type: 'cves' })}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              typeFilter === 'cves'
                ? 'bg-card text-foreground shadow-sm border border-foreground/12'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <Bug className="w-3 h-3" /> CVE Intelligence
          </button>
        </div>

        <div className="h-6 w-px bg-foreground/10" />

        {/* Severity filter */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setSevFilter(null)}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              !sevFilter
                ? 'bg-primary/15 text-primary'
                : 'text-muted-foreground hover:bg-foreground/5'
            }`}
          >
            All
          </button>
          {sevKeys.map((sev) => (
            <button
              key={sev}
              onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-all ${
                sevFilter === sev
                  ? (SEV_BADGE[sev] ?? 'bg-gray-500/15 text-gray-400 border-gray-500/25')
                  : 'border-transparent text-muted-foreground hover:bg-foreground/5'
              }`}
            >
              {sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase()}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-xs ml-auto">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/45" />
          <Input
            placeholder="Search targets…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 bg-foreground/5 border-foreground/15 rounded-lg h-8 text-xs"
          />
        </div>
      </div>

      {/* ── Stats strip ────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {stats.map((s) => (
          <div
            key={s.label}
            className="bg-card border border-foreground/8 rounded-xl px-4 py-3 hover:border-foreground/15 transition-colors"
          >
            <p className="text-[10px] font-semibold text-muted-foreground/60 uppercase tracking-wider">{s.label}</p>
            <p className={`text-2xl font-bold mt-0.5 tabular-nums ${s.cls}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* ── Target cards grid ───────────────────────────────────────── */}
      {typeFilter === 'findings' && (
        allFindingSummaries.length === 0 ? (
          <div className="flex flex-col items-center gap-4 py-24 text-muted-foreground">
            <ShieldAlert className="w-14 h-14 opacity-15" />
            <div className="text-center space-y-1.5">
              <p className="text-base font-semibold text-foreground/70">No scanned targets yet</p>
              <p className="text-sm opacity-60">Run your first scan to begin monitoring vulnerabilities.</p>
            </div>
            <Button
              variant="outline" size="sm"
              className="mt-1 border-foreground/20 rounded-lg px-5"
              onClick={() => router.push('/app/scans')}
            >
              Start a Scan
            </Button>
          </div>
        ) : visibleFindingSummaries.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground/60">
            No targets match the current filters.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {visibleFindingSummaries.map((summary) => (
              <TargetCard
                key={summary.key}
                summary={summary}
                isSelected={selectedKey === summary.key}
                onToggle={() => handleToggleCard(summary.key)}
              />
            ))}
          </div>
        )
      )}

      {typeFilter === 'cves' && (
        allCveSummaries.length === 0 ? (
          <div className="flex flex-col items-center gap-4 py-24 text-muted-foreground">
            <Bug className="w-14 h-14 opacity-15" />
            <div className="text-center space-y-1.5">
              <p className="text-base font-semibold text-foreground/70">No CVEs found</p>
              <p className="text-sm opacity-60">CVE correlation runs automatically after asset discovery and network scans.</p>
            </div>
          </div>
        ) : visibleCveSummaries.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground/60">
            No targets match the current filters.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {visibleCveSummaries.map((summary) => (
              <CveTargetCard
                key={summary.key}
                summary={summary}
                isSelected={selectedKey === summary.key}
                onToggle={() => handleToggleCard(summary.key)}
              />
            ))}
          </div>
        )
      )}

      {/* ── Inline detail panel ─────────────────────────────────────── */}
      {selectedFindingSummary && typeFilter === 'findings' && (
        <div ref={panelRef}>
          <FindingsPanel
            summary={selectedFindingSummary}
            onClose={() => setSelectedKey(null)}
            onViewScanReport={(id) => router.push(`/app/findings/${id}`)}
          />
        </div>
      )}

      {selectedCveSummary && typeFilter === 'cves' && (
        <div ref={panelRef}>
          <CvesPanel
            summary={selectedCveSummary}
            onClose={() => setSelectedKey(null)}
          />
        </div>
      )}

    </div>
  )
}

// ── Page export ────────────────────────────────────────────────────────

export default function FindingsPage() {
  return (
    <Suspense
      fallback={
        <div className="p-8 flex items-center justify-center min-h-64">
          <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
        </div>
      }
    >
      <VulnMgmtContent />
    </Suspense>
  )
}
