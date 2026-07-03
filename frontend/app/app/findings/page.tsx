'use client'

import { Fragment, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  Search, ShieldAlert, Zap, AlertTriangle, Bug,
  ChevronDown, ChevronRight, Globe, X, ExternalLink, Server,
  MessageSquare, Check, Download, Clock, RotateCcw, CheckCheck,
  Filter, SlidersHorizontal, FileText, User, UserCheck, UserMinus,
  Copy, Link2, CheckCircle2, XCircle, CalendarClock, Code2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { listenToFindings, type FirestoreFinding } from '@/lib/firestore-findings'
import { listenToCves, type FirestoreCve } from '@/lib/firestore-cves'
import { listenToNetworkFindings, type FirestoreNetworkFinding } from '@/lib/firestore-network-findings'
import { listenToNetworkCves, type FirestoreNetworkCve } from '@/lib/firestore-network-cves'
import { listenToSastFindings, type FirestoreSastFinding } from '@/lib/firestore-sast-findings'
import { useAuth } from '@/context/auth-context'
import {
  listenToCveTracking, upsertCveTracking, defaultTracking, genTrackingId,
  type CveStatus, type CveComment, type CveTimelineEvent, type CveTracking,
} from '@/lib/firestore-cve-tracking'
import {
  listenToFindingTracking, upsertFindingTracking, defaultFindingTracking, genFindingId,
  type FindingStatus, type FindingComment, type FindingTimelineEvent, type FindingTracking,
} from '@/lib/firestore-finding-tracking'
import {
  listenToSlaPolicy, saveSlaPolicy, DEFAULT_SLA, computeSlaStatus,
  type SlaPolicy, type SlaStatus,
} from '@/lib/firestore-sla'

// ── Types ──────────────────────────────────────────────────────────────

type ModuleFilter = 'all' | 'web' | 'network' | 'sast'
type TypeFilter   = 'findings' | 'cves'
type Module       = 'web' | 'network' | 'sast'

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
  matchedAt?:  string | null
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

type SlaFilter = 'all' | 'within_sla' | 'due_soon' | 'breached'

// ── Constants ──────────────────────────────────────────────────────────

const MODULE_BADGE: Record<Module, { label: string; cls: string }> = {
  web:     { label: 'WEB',     cls: 'bg-blue-500/15 text-blue-400 border-blue-500/25'       },
  network: { label: 'NETWORK', cls: 'bg-green-500/15 text-green-400 border-green-500/25'    },
  sast:    { label: 'SAST',    cls: 'bg-violet-500/15 text-violet-400 border-violet-500/25' },
}

const MODULE_ICON: Record<Module, React.ComponentType<{ className?: string }>> = {
  web:     Globe,
  network: Server,
  sast:    Code2,
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
  { value: 'sast',    label: 'SAST'             },
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
    matchedAt: f.matchedAt ?? null,
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
    matchedAt: f.matched_at ?? null,
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

function normalizeSastFinding(f: FirestoreSastFinding): NormalizedFinding {
  return {
    id: f.findingId, module: 'sast',
    severity: (f.severity ?? 'unknown').toLowerCase(),
    title: f.title,
    target: f.projectName,
    scanner: f.category,
    template: f.type,
    description: f.description ?? '',
    createdAt: f.createdAt,
    scanId: f.scanId,
    host: f.file ?? null,
    matchedAt: f.line > 0 ? `line ${f.line}` : null,
    port: null,
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

// ── CVE Status system ─────────────────────────────────────────────────

const STATUS_CONFIG: Record<CveStatus, { label: string; cls: string; dot: string }> = {
  open:           { label: 'Open',           cls: 'bg-red-500/15 text-red-400 border-red-500/25',          dot: 'bg-red-400'    },
  in_progress:    { label: 'In Progress',    cls: 'bg-blue-500/15 text-blue-400 border-blue-500/25',       dot: 'bg-blue-400'   },
  fixed:          { label: 'Fixed',          cls: 'bg-green-500/15 text-green-400 border-green-500/25',    dot: 'bg-green-400'  },
  accepted_risk:  { label: 'Accepted Risk',  cls: 'bg-orange-500/15 text-orange-400 border-orange-500/25', dot: 'bg-orange-400' },
  false_positive: { label: 'False Positive', cls: 'bg-gray-500/15 text-gray-400 border-gray-500/25',       dot: 'bg-gray-400'   },
  not_applicable: { label: 'N/A',            cls: 'bg-purple-500/15 text-purple-400 border-purple-500/25', dot: 'bg-purple-400' },
}
const STATUS_OPTIONS = Object.entries(STATUS_CONFIG).map(([v, c]) => ({
  value: v as CveStatus, ...c,
}))

interface ExportOptions {
  includeComments: boolean
  includeTimeline: boolean
  includeFixed:    boolean
  onlyOpen:        boolean
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

function computeCardSlaCounts(
  findings: NormalizedFinding[],
  policy:   SlaPolicy,
  tracking: Record<string, FindingTracking>,
) {
  let withinSla = 0, dueSoon = 0, breached = 0
  for (const f of findings) {
    const t = tracking[f.id]
    const isResolved = t?.status === 'fixed' || t?.status === 'false_positive' || t?.status === 'not_applicable'
    if (isResolved) continue
    const { status } = computeSlaStatus(f.severity, f.createdAt, policy, false)
    if (status === 'within_sla') withinSla++
    else if (status === 'due_soon') dueSoon++
    else if (status === 'breached') breached++
  }
  return { withinSla, dueSoon, breached }
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

// ── SLA badge ─────────────────────────────────────────────────────────

function SlaBadge({ severity, createdAt, isFixed, policy }: {
  severity:  string
  createdAt: string
  isFixed:   boolean
  policy:    SlaPolicy
}) {
  const { status, daysRemaining } = computeSlaStatus(severity, createdAt, policy, isFixed)
  if (status === 'fixed')  return <span className="text-[10px] text-muted-foreground/40">Fixed</span>
  if (status === 'no_sla') return <span className="text-[10px] text-muted-foreground/30">No SLA</span>
  const abs = Math.abs(daysRemaining ?? 0)
  if (status === 'breached') return (
    <span className="inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/25 whitespace-nowrap">
      <XCircle className="w-2.5 h-2.5 shrink-0" />
      {abs === 0 ? 'Due Today' : `${abs}d overdue`}
    </span>
  )
  if (status === 'due_soon') return (
    <span className="inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/25 whitespace-nowrap">
      <AlertTriangle className="w-2.5 h-2.5 shrink-0" />
      {daysRemaining === 0 ? 'Due Today' : daysRemaining === 1 ? 'Due Tomorrow' : `${daysRemaining}d left`}
    </span>
  )
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/25 whitespace-nowrap">
      <CheckCircle2 className="w-2.5 h-2.5 shrink-0" />
      {daysRemaining}d left
    </span>
  )
}

// ── Target cards ───────────────────────────────────────────────────────

function TargetCard({
  summary,
  isSelected,
  onToggle,
  slaPolicy,
  slaTracking,
}: {
  summary:     TargetSummary
  isSelected:  boolean
  onToggle:    () => void
  slaPolicy:   SlaPolicy
  slaTracking: Record<string, FindingTracking>
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

        {/* SLA mini-summary */}
        {(() => {
          const { withinSla, dueSoon, breached } = computeCardSlaCounts(summary.findings, slaPolicy, slaTracking)
          const hasSla = withinSla + dueSoon + breached > 0
          if (!hasSla) return null
          return (
            <div className="border-t border-foreground/8 pt-3 flex items-center gap-3 flex-wrap">
              <CalendarClock className="w-3 h-3 text-muted-foreground/40 shrink-0" />
              {withinSla > 0 && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-green-400">
                  <CheckCircle2 className="w-2.5 h-2.5" /> {withinSla}
                </span>
              )}
              {dueSoon > 0 && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-orange-400">
                  <Clock className="w-2.5 h-2.5" /> {dueSoon} soon
                </span>
              )}
              {breached > 0 && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-red-400">
                  <XCircle className="w-2.5 h-2.5" /> {breached} breached
                </span>
              )}
            </div>
          )
        })()}
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

// ── Findings enterprise panel — shared constants ───────────────────────

const TEAM_MEMBERS = [
  { id: 'user-john',  name: 'John Doe'      },
  { id: 'user-jane',  name: 'Jane Smith'    },
  { id: 'user-bob',   name: 'Bob Johnson'   },
  { id: 'user-alice', name: 'Alice Williams'},
]

function avatarInitials(name: string) {
  return name.split(' ').map(p => p[0]).join('').toUpperCase().slice(0, 2)
}

function AssigneeAvatar({ name, size = 'sm' }: { name: string | null; size?: 'sm' | 'xs' }) {
  const dim = size === 'xs' ? 'w-5 h-5 text-[9px]' : 'w-6 h-6 text-[10px]'
  if (!name) {
    return (
      <div className={`${dim} rounded-full bg-foreground/10 border border-foreground/20 flex items-center justify-center shrink-0`}>
        <User className="w-3 h-3 text-muted-foreground/40" />
      </div>
    )
  }
  return (
    <div className={`${dim} rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0 font-bold text-primary`}>
      {avatarInitials(name)}
    </div>
  )
}

// Assignee picker modal — select or unassign
function AssigneePickerModal({
  current,
  currentUser,
  onSelect,
  onUnassign,
  onClose,
}: {
  current:     { id: string; name: string } | null
  currentUser: { uid: string; name: string } | null
  onSelect:    (m: { id: string; name: string }) => void
  onUnassign:  () => void
  onClose:     () => void
}) {
  const allMembers = useMemo(() => {
    const base = [...TEAM_MEMBERS]
    if (currentUser && !base.find(m => m.id === currentUser.uid)) {
      base.unshift({ id: currentUser.uid, name: currentUser.name })
    }
    return base
  }, [currentUser])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-xs p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Assign To</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded text-muted-foreground hover:text-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="space-y-1">
          {allMembers.map(m => (
            <button
              key={m.id}
              onClick={() => { onSelect(m); onClose() }}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm hover:bg-foreground/5 transition-colors ${
                current?.id === m.id ? 'text-foreground' : 'text-muted-foreground'
              }`}
            >
              <AssigneeAvatar name={m.name} />
              <span>{m.name}</span>
              {current?.id === m.id && <Check className="w-3.5 h-3.5 ml-auto text-primary" strokeWidth={2.5} />}
            </button>
          ))}
          {current && (
            <>
              <div className="h-px bg-foreground/8 my-1" />
              <button
                onClick={() => { onUnassign(); onClose() }}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-foreground/5 transition-colors"
              >
                <UserMinus className="w-4 h-4 text-muted-foreground/50" />
                Unassign
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// Bulk assign modal
function BulkAssignModal({
  count,
  currentUser,
  onAssign,
  onClose,
  loading,
}: {
  count:       number
  currentUser: { uid: string; name: string } | null
  onAssign:    (m: { id: string; name: string }) => void
  onClose:     () => void
  loading:     boolean
}) {
  const allMembers = useMemo(() => {
    const base = [...TEAM_MEMBERS]
    if (currentUser && !base.find(m => m.id === currentUser.uid)) {
      base.unshift({ id: currentUser.uid, name: currentUser.name })
    }
    return base
  }, [currentUser])
  const [chosen, setChosen] = useState<{ id: string; name: string } | null>(null)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-sm p-6 space-y-5">
        <div className="flex items-center gap-2.5">
          <UserCheck className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Assign {count} Findings</h3>
        </div>
        <div className="space-y-1">
          {allMembers.map(m => (
            <button
              key={m.id}
              onClick={() => setChosen(m)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                chosen?.id === m.id
                  ? 'bg-primary/10 text-foreground border border-primary/25'
                  : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground border border-transparent'
              }`}
            >
              <AssigneeAvatar name={m.name} />
              <span>{m.name}</span>
              {chosen?.id === m.id && <Check className="w-3.5 h-3.5 ml-auto text-primary" strokeWidth={2.5} />}
            </button>
          ))}
        </div>
        <div className="flex gap-3">
          <Button variant="outline" className="flex-1 border-foreground/20" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            className="flex-1"
            disabled={!chosen || loading}
            onClick={() => chosen && onAssign(chosen)}
          >
            {loading ? 'Assigning…' : 'Assign'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// Finding details drawer — right-side panel, replaces all navigation away from page
function FindingDrawer({
  finding,
  tracking,
  currentUser,
  slaPolicy,
  onClose,
  onStatusChange,
  onAssign,
  onUnassign,
  onAddComment,
}: {
  finding:        NormalizedFinding
  tracking:       FindingTracking
  currentUser:    { uid: string; name: string } | null
  slaPolicy:      SlaPolicy
  onClose:        () => void
  onStatusChange: (s: FindingStatus) => void
  onAssign:       (m: { id: string; name: string }) => void
  onUnassign:     () => void
  onAddComment:   () => void
}) {
  const [scanExpanded,    setScanExpanded]    = useState(false)
  const [statusOpen,      setStatusOpen]      = useState(false)
  const [assigneeOpen,    setAssigneeOpen]    = useState(false)
  const statusBtnRef   = useRef<HTMLButtonElement>(null)
  const [dropPos, setDropPos] = useState({ x: 0, y: 0 })

  const { cls, dot } = STATUS_CONFIG[tracking.status]

  function openStatusDrop() {
    if (statusBtnRef.current) {
      const r = statusBtnRef.current.getBoundingClientRect()
      setDropPos({ x: r.left, y: r.bottom + 4 })
    }
    setStatusOpen(true)
  }

  function copyFindingLink() {
    const url = `${window.location.origin}/app/findings?findingId=${finding.id}`
    navigator.clipboard.writeText(url).catch(() => {})
  }

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-[2px]" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-[540px] max-w-[95vw] bg-card border-l border-foreground/10 flex flex-col shadow-2xl">

        {/* Drawer header */}
        <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-foreground/10 shrink-0">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <ModuleBadge module={finding.module} />
              <SevBadge severity={finding.severity} />
              <span className="text-[10px] text-muted-foreground/50 font-mono truncate">{finding.id.slice(0, 20)}</span>
            </div>
            <h2 className="text-base font-bold text-foreground leading-tight">{finding.title}</h2>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              onClick={copyFindingLink}
              title="Copy link"
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
            >
              <Link2 className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto">

          {/* Key metrics strip */}
          <div className="grid grid-cols-4 border-b border-foreground/8">
            {[
              { label: 'Severity',  value: finding.severity.toUpperCase(), cls: SEV_BADGE[finding.severity] ?? '' },
              { label: 'Module',    value: finding.module.toUpperCase(),   cls: 'text-muted-foreground'          },
              { label: 'Scanner',   value: finding.scanner,                cls: 'text-muted-foreground'          },
              { label: 'Reported',  value: formatRelative(finding.createdAt), cls: 'text-muted-foreground'       },
            ].map(({ label, value, cls: c }) => (
              <div key={label} className="px-4 py-3.5 border-r last:border-r-0 border-foreground/8">
                <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-xs font-bold truncate ${c}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Target + technical details */}
          <div className="px-6 py-5 border-b border-foreground/8 space-y-3">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Finding Details</p>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2.5 text-sm">
              {[
                ['Target',    finding.target],
                ['Template',  finding.template],
                ...(finding.port   != null ? [['Port',    String(finding.port)]] : []),
                ...(finding.host             ? [['Host',    finding.host]]           : []),
                ...(finding.matchedAt        ? [['Matched', formatDate(finding.matchedAt)]] : []),
                ['Created',   formatDate(finding.createdAt)],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-muted-foreground shrink-0 w-16">{k}</span>
                  <span className="text-foreground font-mono text-xs break-all">{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Description */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-2">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              {finding.description || 'No description available.'}
            </p>
          </div>

          {/* Related scan — collapsible */}
          <div className="border-b border-foreground/8">
            <button
              onClick={() => setScanExpanded(p => !p)}
              className="w-full flex items-center justify-between px-6 py-4 hover:bg-foreground/[0.02] transition-colors"
            >
              <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Related Scan</p>
              {scanExpanded
                ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/40" />
                : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40" />}
            </button>
            {scanExpanded && (
              <div className="px-6 pb-5 space-y-2 text-sm">
                <div className="bg-foreground/[0.03] border border-foreground/8 rounded-xl p-4 space-y-2.5">
                  {[
                    ['Scan ID',   finding.scanId],
                    ['Scanner',   finding.scanner],
                    ['Target',    finding.target],
                    ['Module',    finding.module.toUpperCase()],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3">
                      <span className="text-muted-foreground w-16 shrink-0">{k}</span>
                      <span className="text-foreground/80 font-mono text-xs break-all">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* SLA */}
          {(() => {
            const isFixed = tracking.status === 'fixed'
            const sla     = computeSlaStatus(finding.severity, finding.createdAt, slaPolicy, isFixed)
            const slaDays = slaPolicy[finding.severity.toLowerCase() as keyof Pick<SlaPolicy,'critical'|'high'|'medium'|'low'|'info'>]
            if (sla.status === 'no_sla') return null
            const dueLabel = sla.dueDate
              ? sla.dueDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
              : '—'
            const remainLabel =
              sla.status === 'fixed'     ? 'Fixed'
              : sla.status === 'breached' ? `${Math.abs(sla.daysRemaining ?? 0)} days overdue`
              : sla.daysRemaining === 0   ? 'Due Today'
              : sla.daysRemaining === 1   ? 'Due Tomorrow'
              : `${sla.daysRemaining} days remaining`
            const bgCls =
              sla.status === 'breached'   ? 'bg-red-500/[0.06] border-red-500/15'
              : sla.status === 'due_soon' ? 'bg-orange-500/[0.06] border-orange-500/15'
              : sla.status === 'fixed'    ? 'bg-foreground/[0.03] border-foreground/10'
              : 'bg-green-500/[0.06] border-green-500/15'
            return (
              <div className={`mx-6 my-5 rounded-xl border p-4 ${bgCls}`}>
                <div className="flex items-center gap-2 mb-3">
                  <CalendarClock className="w-3.5 h-3.5 text-muted-foreground/60" />
                  <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">SLA Deadline</p>
                  <SlaBadge severity={finding.severity} createdAt={finding.createdAt} isFixed={isFixed} policy={slaPolicy} />
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <div>
                    <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wider">Discovery Date</p>
                    <p className="text-xs font-medium text-foreground/80 mt-0.5">{formatDate(finding.createdAt)}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wider">SLA ({slaDays}d)</p>
                    <p className="text-xs font-medium text-foreground/80 mt-0.5">{dueLabel}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wider">Status</p>
                    <p className={`text-xs font-bold mt-0.5 ${
                      sla.status === 'breached'   ? 'text-red-400'
                      : sla.status === 'due_soon' ? 'text-orange-400'
                      : sla.status === 'fixed'    ? 'text-muted-foreground'
                      : 'text-green-400'
                    }`}>{remainLabel}</p>
                  </div>
                </div>
              </div>
            )
          })()}

          {/* Status */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-3">Status</p>
            <button
              ref={statusBtnRef}
              onClick={openStatusDrop}
              className={`flex items-center gap-2 text-xs font-semibold px-3 py-1.5 rounded-full border hover:opacity-80 transition-opacity ${cls}`}
            >
              <span className={`w-2 h-2 rounded-full ${dot}`} />
              {STATUS_CONFIG[tracking.status].label}
              <ChevronDown className="w-3 h-3 ml-1 opacity-60" />
            </button>
            {statusOpen && (
              <StatusDropdown
                anchorPos={dropPos}
                current={tracking.status}
                onSelect={(s) => { onStatusChange(s); setStatusOpen(false) }}
                onClose={() => setStatusOpen(false)}
              />
            )}
          </div>

          {/* Assignee */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-3">Assigned To</p>
            <button
              onClick={() => setAssigneeOpen(true)}
              className="flex items-center gap-2.5 px-3 py-2 rounded-xl border border-foreground/15 hover:border-foreground/30 hover:bg-foreground/5 transition-all"
            >
              <AssigneeAvatar name={tracking.assigneeName} />
              <span className="text-sm text-foreground/80">
                {tracking.assigneeName ?? 'Unassigned'}
              </span>
              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/40 ml-auto" />
            </button>
          </div>

          {/* Comments */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <div className="flex items-center justify-between mb-3">
              <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">
                Internal Comments ({tracking.comments.length})
              </p>
              <button
                onClick={onAddComment}
                className="text-[10px] font-semibold text-primary hover:underline"
              >
                + Add Comment
              </button>
            </div>
            {tracking.comments.length === 0 ? (
              <p className="text-xs text-muted-foreground/50 italic">No internal comments yet.</p>
            ) : (
              <div className="space-y-4">
                {tracking.comments.map((c) => (
                  <div key={c.id} className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <AssigneeAvatar name={c.userName} size="xs" />
                      <span className="text-xs font-medium text-foreground">{c.userName}</span>
                      <span className="text-[10px] text-muted-foreground/50 ml-auto">{formatDate(c.createdAt)}</span>
                    </div>
                    <p className="text-xs text-muted-foreground pl-7 leading-relaxed">{c.text}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Activity Timeline */}
          <div className="px-6 py-5">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-4">
              Activity Timeline
            </p>
            {tracking.timeline.length === 0 ? (
              <p className="text-xs text-muted-foreground/50 italic">No activity yet.</p>
            ) : (
              <div className="relative pl-5">
                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-foreground/10" />
                <div className="space-y-4">
                  {[...tracking.timeline].sort((a, b) =>
                    new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
                  ).map((ev) => {
                    const Icon =
                      ev.action === 'created'        ? ShieldAlert   :
                      ev.action === 'comment_added'  ? MessageSquare :
                      ev.action === 'marked_fixed'   ? CheckCheck    :
                      ev.action === 'reopened'       ? RotateCcw     :
                      ev.action === 'assigned'       ? UserCheck     :
                      ev.action === 'unassigned'     ? UserMinus     :
                      Clock
                    return (
                      <div key={ev.id} className="flex items-start gap-3">
                        <div className="w-3.5 h-3.5 rounded-full bg-card border-2 border-primary/40 flex items-center justify-center shrink-0 mt-0.5">
                          <Icon className="w-2 h-2 text-primary/60" />
                        </div>
                        <div>
                          <p className="text-xs text-foreground/80">
                            {ev.details ?? ev.action.replace(/_/g, ' ')}
                          </p>
                          <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                            {ev.userName && `${ev.userName} · `}{formatDate(ev.createdAt)}
                          </p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

        </div>
      </div>

      {assigneeOpen && (
        <AssigneePickerModal
          current={tracking.assigneeId ? { id: tracking.assigneeId, name: tracking.assigneeName ?? '' } : null}
          currentUser={currentUser}
          onSelect={onAssign}
          onUnassign={onUnassign}
          onClose={() => setAssigneeOpen(false)}
        />
      )}
    </>
  )
}

// Finding comment modal (reuses same pattern as CveCommentModal)
function FindingCommentModal({
  targets,
  allFindings,
  existingComments,
  onSubmit,
  onClose,
  loading,
}: {
  targets:          string[]
  allFindings:      NormalizedFinding[]
  existingComments: FindingComment[]
  onSubmit:         (text: string) => void
  onClose:          () => void
  loading:          boolean
}) {
  const [text, setText] = useState('')
  const single = targets.length === 1 ? allFindings.find(f => f.id === targets[0]) : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-lg flex flex-col max-h-[80vh]">

        <div className="flex items-center justify-between px-5 py-4 border-b border-foreground/10">
          <div className="flex items-center gap-2.5">
            <MessageSquare className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">
              {single ? `Comments — ${single.title.slice(0, 40)}` : `Add Comment to ${targets.length} Findings`}
            </h3>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10">
            <X className="w-4 h-4" />
          </button>
        </div>

        {existingComments.length > 0 && (
          <div className="overflow-y-auto max-h-48 px-5 py-3 space-y-3 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Comment History</p>
            {existingComments.map((c) => (
              <div key={c.id} className="space-y-1">
                <div className="flex items-center gap-2">
                  <AssigneeAvatar name={c.userName} size="xs" />
                  <span className="text-xs font-medium text-foreground">{c.userName}</span>
                  <span className="text-[10px] text-muted-foreground/50 ml-auto">{formatDate(c.createdAt)}</span>
                </div>
                <p className="text-xs text-muted-foreground pl-7 leading-relaxed">{c.text}</p>
              </div>
            ))}
          </div>
        )}

        <div className="px-5 py-4 space-y-3">
          <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Add Note</p>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Add an internal note…"
            rows={4}
            className="w-full bg-foreground/5 border border-foreground/15 rounded-xl text-sm text-foreground placeholder:text-muted-foreground/40 px-3.5 py-2.5 resize-none focus:outline-none focus:ring-1 focus:ring-primary/40"
          />
          <div className="flex gap-3">
            <Button variant="outline" className="flex-1 border-foreground/20" onClick={onClose} disabled={loading}>Cancel</Button>
            <Button className="flex-1" onClick={() => onSubmit(text)} disabled={loading || !text.trim()}>
              {loading ? 'Saving…' : 'Save Comment'}
            </Button>
          </div>
        </div>

      </div>
    </div>
  )
}

// ── Enterprise Findings Panel ──────────────────────────────────────────

function FindingsPanel({
  summary,
  onClose,
  slaPolicy,
}: {
  summary:   TargetSummary
  onClose:   () => void
  slaPolicy: SlaPolicy
}) {
  const { user } = useAuth()
  const Icon     = MODULE_ICON[summary.module]

  // ── Tracking state ────────────────────────────────────────────────
  const [tracking, setTracking] = useState<Record<string, FindingTracking>>({})

  // ── Filter state ──────────────────────────────────────────────────
  const [panelSearch,    setPanelSearch]    = useState('')
  const [statusFilter,   setStatusFilter]   = useState<FindingStatus | 'all'>('all')
  const [assigneeFilter, setAssigneeFilter] = useState<string>('all')
  const [commentFilter,  setCommentFilter]  = useState<'all' | 'has' | 'none'>('all')
  const [sevFilter,      setSevFilter]      = useState<string>('all')

  // ── Selection ─────────────────────────────────────────────────────
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // ── Status dropdown ───────────────────────────────────────────────
  const [statusDropFor, setStatusDropFor] = useState<string | null>(null)
  const [statusDropPos, setStatusDropPos] = useState({ x: 0, y: 0 })

  // ── Modals / drawer ───────────────────────────────────────────────
  const [drawerFinding,   setDrawerFinding]   = useState<NormalizedFinding | null>(null)
  const [commentTargets,  setCommentTargets]  = useState<string[] | null>(null)
  const [fixTargets,      setFixTargets]      = useState<string[] | null>(null)
  const [assignTargets,   setAssignTargets]   = useState<string[] | null>(null)
  const [exportOpen,      setExportOpen]      = useState(false)
  const [opLoading,       setOpLoading]       = useState(false)

  // ── Load tracking ─────────────────────────────────────────────────
  useEffect(() => {
    if (!user) return
    return listenToFindingTracking(user.uid, setTracking)
  }, [user])

  function getT(findingId: string): FindingTracking {
    return tracking[findingId] ?? defaultFindingTracking(findingId)
  }

  // ── Status change ─────────────────────────────────────────────────
  async function changeStatus(findingDocId: string, newStatus: FindingStatus) {
    if (!user) return
    const existing = getT(findingDocId)
    const now = new Date().toISOString()
    const ev: FindingTimelineEvent = {
      id: genFindingId(), action: 'status_changed',
      userId: user.uid, userName: user.name, createdAt: now,
      details: `Status changed to ${STATUS_CONFIG[newStatus].label}`,
    }
    const updated: FindingTracking = {
      ...existing, findingDocId, status: newStatus,
      timeline: [...existing.timeline, ev], updatedAt: now,
    }
    setTracking(prev => ({ ...prev, [findingDocId]: updated }))
    await upsertFindingTracking(user.uid, updated)
  }

  // ── Assign ────────────────────────────────────────────────────────
  async function assignFinding(findingDocId: string, assignee: { id: string; name: string } | null) {
    if (!user) return
    const existing = getT(findingDocId)
    const now = new Date().toISOString()
    const ev: FindingTimelineEvent = {
      id: genFindingId(),
      action: assignee ? 'assigned' : 'unassigned',
      userId: user.uid, userName: user.name, createdAt: now,
      details: assignee ? `Assigned to ${assignee.name}` : 'Unassigned',
    }
    const updated: FindingTracking = {
      ...existing, findingDocId,
      assigneeId:   assignee?.id   ?? null,
      assigneeName: assignee?.name ?? null,
      timeline: [...existing.timeline, ev], updatedAt: now,
    }
    setTracking(prev => ({ ...prev, [findingDocId]: updated }))
    await upsertFindingTracking(user.uid, updated)
  }

  // ── Bulk assign ───────────────────────────────────────────────────
  async function bulkAssign(findingIds: string[], assignee: { id: string; name: string }) {
    if (!user) return
    setOpLoading(true)
    try {
      await Promise.all(findingIds.map(id => assignFinding(id, assignee)))
      setSelected(new Set())
      setAssignTargets(null)
    } finally {
      setOpLoading(false)
    }
  }

  // ── Add comment ───────────────────────────────────────────────────
  async function submitComment(findingDocIds: string[], text: string) {
    if (!user || !text.trim()) return
    setOpLoading(true)
    try {
      const now = new Date().toISOString()
      await Promise.all(findingDocIds.map(findingDocId => {
        const existing = getT(findingDocId)
        const comment: FindingComment = {
          id: genFindingId(), userId: user.uid, userName: user.name,
          text: text.trim(), createdAt: now,
        }
        const ev: FindingTimelineEvent = {
          id: genFindingId(), action: 'comment_added',
          userId: user.uid, userName: user.name, createdAt: now,
        }
        const updated: FindingTracking = {
          ...existing, findingDocId,
          comments: [...existing.comments, comment],
          timeline: [...existing.timeline, ev], updatedAt: now,
        }
        setTracking(prev => ({ ...prev, [findingDocId]: updated }))
        return upsertFindingTracking(user.uid, updated)
      }))
    } finally {
      setOpLoading(false)
      setCommentTargets(null)
    }
  }

  // ── Bulk mark fixed ───────────────────────────────────────────────
  async function confirmFix(findingDocIds: string[]) {
    if (!user) return
    setOpLoading(true)
    try {
      await Promise.all(findingDocIds.map(id => changeStatus(id, 'fixed')))
      setSelected(new Set())
      setFixTargets(null)
    } finally {
      setOpLoading(false)
    }
  }

  // ── Export ────────────────────────────────────────────────────────
  function doExport(opts: ExportOptions) {
    const rows = filteredRows.filter(r => {
      const st = getT(r.id).status
      if (opts.onlyOpen)      return st === 'open'
      if (!opts.includeFixed) return st !== 'fixed'
      return true
    })
    const data = rows.map(r => {
      const t = getT(r.id)
      return {
        id: r.id, title: r.title, severity: r.severity, target: r.target,
        scanner: r.scanner, template: r.template, module: r.module,
        status: t.status, assignee: t.assigneeName ?? 'Unassigned',
        createdAt: r.createdAt,
        ...(opts.includeComments && { comments: t.comments }),
        ...(opts.includeTimeline && { timeline: t.timeline }),
      }
    })
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url
    a.download = `findings-${summary.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  // ── Unique assignees for filter dropdown ──────────────────────────
  const assigneeOptions = useMemo(() => {
    const names = new Set<string>()
    Object.values(tracking).forEach(t => { if (t.assigneeName) names.add(t.assigneeName) })
    return Array.from(names)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tracking])

  // ── Filtered rows ─────────────────────────────────────────────────
  const filteredRows = useMemo(() => {
    let r = [...summary.findings].sort((a, b) =>
      (SEV_ORDER[a.severity] ?? 6) - (SEV_ORDER[b.severity] ?? 6),
    )
    if (statusFilter !== 'all')   r = r.filter(f => getT(f.id).status === statusFilter)
    if (assigneeFilter !== 'all') r = r.filter(f => getT(f.id).assigneeName === assigneeFilter)
    if (commentFilter === 'has')  r = r.filter(f => getT(f.id).comments.length > 0)
    if (commentFilter === 'none') r = r.filter(f => getT(f.id).comments.length === 0)
    if (sevFilter !== 'all')      r = r.filter(f => f.severity === sevFilter)
    if (panelSearch.trim()) {
      const q = panelSearch.toLowerCase()
      r = r.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.template.toLowerCase().includes(q) ||
        f.scanner.toLowerCase().includes(q) ||
        f.target.toLowerCase().includes(q),
      )
    }
    return r
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary.findings, tracking, statusFilter, assigneeFilter, commentFilter, sevFilter, panelSearch])

  // ── Quick metrics ─────────────────────────────────────────────────
  const metrics = useMemo(() => ({
    open:        summary.findings.filter(f => getT(f.id).status === 'open').length,
    in_progress: summary.findings.filter(f => tracking[f.id]?.status === 'in_progress').length,
    fixed:       summary.findings.filter(f => tracking[f.id]?.status === 'fixed').length,
    accepted:    summary.findings.filter(f => tracking[f.id]?.status === 'accepted_risk').length,
    assigned:    summary.findings.filter(f => !!tracking[f.id]?.assigneeName).length,
    unassigned:  summary.findings.filter(f => !tracking[f.id]?.assigneeName).length,
    critical:    summary.critical,
    high:        summary.high,
    medium:      summary.medium,
    low:         summary.low,
    info:        summary.info,
    total:       summary.total,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [summary, tracking])

  // ── Selection helpers ─────────────────────────────────────────────
  const allSelected  = filteredRows.length > 0 && filteredRows.every(r => selected.has(r.id))
  const someSelected = !allSelected && filteredRows.some(r => selected.has(r.id))

  function toggleAll() {
    if (allSelected) setSelected(new Set())
    else setSelected(new Set(filteredRows.map(r => r.id)))
  }
  function toggleRow(id: string) {
    setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }
  function openStatusDropFor(e: React.MouseEvent, fid: string) {
    e.stopPropagation()
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setStatusDropPos({ x: rect.left, y: rect.bottom + 4 })
    setStatusDropFor(fid)
  }

  const selectedIds = Array.from(selected)

  // ── Render ────────────────────────────────────────────────────────
  return (
    <>
      <div className="bg-card border border-primary/25 rounded-xl overflow-hidden shadow-lg shadow-primary/5">

        {/* ── Panel header ───────────────────────────────────────── */}
        <div className="flex items-center justify-between gap-4 px-5 py-3.5 border-b border-foreground/10 bg-primary/[0.03]">
          <div className="flex items-center gap-2.5 min-w-0">
            <Icon className="w-4 h-4 text-muted-foreground/70 shrink-0" />
            <span className="text-sm font-semibold text-foreground truncate font-mono">{summary.target}</span>
            <span className="text-xs text-muted-foreground/50 shrink-0">— {summary.total} findings</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/40" />
              <input
                placeholder="Search findings…"
                value={panelSearch}
                onChange={(e) => setPanelSearch(e.target.value)}
                className="pl-7 pr-3 py-1.5 bg-foreground/5 border border-foreground/15 rounded-lg text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-primary/40 w-44"
              />
            </div>
            <Button
              variant="outline" size="sm"
              className="h-7 px-2.5 border-foreground/20 text-xs gap-1.5"
              onClick={() => setExportOpen(true)}
            >
              <Download className="w-3.5 h-3.5" /> Export
            </Button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Filter bar ─────────────────────────────────────────── */}
        <div className="px-5 py-2 border-b border-foreground/8 flex flex-wrap items-center gap-2 bg-foreground/[0.015]">
          <SlidersHorizontal className="w-3.5 h-3.5 text-muted-foreground/50 shrink-0" />

          {/* Status filter */}
          <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${statusFilter === 'all' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
            >All</button>
            {STATUS_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setStatusFilter(statusFilter === opt.value ? 'all' : opt.value)}
                className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-all ${statusFilter === opt.value ? `${opt.cls} border` : 'text-muted-foreground hover:text-foreground'}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${opt.dot}`} />
                {opt.label}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-foreground/10" />

          {/* Severity filter */}
          <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
            {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSevFilter(sev === sevFilter ? 'all' : sev)}
                className={`px-2 py-1 rounded text-[10px] font-medium transition-all capitalize ${sevFilter === sev ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                {sev === 'all' ? 'All Sev' : sev.charAt(0).toUpperCase() + sev.slice(1, 4)}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-foreground/10" />

          {/* Comment filter */}
          <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
            {([['all', 'All'], ['has', 'Has Comments'], ['none', 'No Comments']] as const).map(([v, l]) => (
              <button
                key={v}
                onClick={() => setCommentFilter(v)}
                className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${commentFilter === v ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
              >
                {l}
              </button>
            ))}
          </div>

          {/* Assignee filter */}
          {assigneeOptions.length > 0 && (
            <>
              <div className="h-4 w-px bg-foreground/10" />
              <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
                <button
                  onClick={() => setAssigneeFilter('all')}
                  className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${assigneeFilter === 'all' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                >All Assignees</button>
                {assigneeOptions.map(name => (
                  <button
                    key={name}
                    onClick={() => setAssigneeFilter(assigneeFilter === name ? 'all' : name)}
                    className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-all ${assigneeFilter === name ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                  >
                    <AssigneeAvatar name={name} size="xs" />
                    {name.split(' ')[0]}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* ── Quick metrics ───────────────────────────────────────── */}
        <div className="grid grid-cols-4 md:grid-cols-8 border-b border-foreground/8">
          {[
            { label: 'Open',        val: metrics.open,        cls: 'text-red-400',    f: () => setStatusFilter('open')                                     },
            { label: 'In Progress', val: metrics.in_progress, cls: 'text-blue-400',   f: () => setStatusFilter('in_progress')                               },
            { label: 'Fixed',       val: metrics.fixed,       cls: 'text-green-400',  f: () => setStatusFilter('fixed')                                     },
            { label: 'Accepted',    val: metrics.accepted,    cls: 'text-orange-400', f: () => setStatusFilter('accepted_risk')                              },
            { label: 'Assigned',    val: metrics.assigned,    cls: 'text-primary',    f: () => setAssigneeFilter(assigneeFilter === 'all' ? (assigneeOptions[0] ?? 'all') : 'all') },
            { label: 'Unassigned',  val: metrics.unassigned,  cls: 'text-muted-foreground', f: () => {} },
            { label: 'Critical',    val: metrics.critical,    cls: 'text-red-400',    f: () => setSevFilter('critical')                                      },
            { label: 'High',        val: metrics.high,        cls: 'text-orange-400', f: () => setSevFilter('high')                                          },
          ].map(m => (
            <button
              key={m.label}
              onClick={m.f}
              className="px-3 py-3 text-left hover:bg-foreground/5 transition-colors border-r last:border-r-0 border-foreground/8 group"
            >
              <p className="text-[9px] font-semibold text-muted-foreground/55 uppercase tracking-wider group-hover:text-muted-foreground transition-colors truncate">
                {m.label}
              </p>
              <p className={`text-lg font-bold tabular-nums mt-0.5 ${m.cls}`}>{m.val}</p>
            </button>
          ))}
        </div>

        {/* ── Bulk toolbar ────────────────────────────────────────── */}
        {selected.size > 0 && (
          <div className="px-5 py-2.5 border-b border-foreground/8 flex items-center gap-3 bg-primary/[0.04]">
            <span className="text-sm font-semibold text-foreground tabular-nums">{selected.size} selected</span>
            <div className="h-4 w-px bg-foreground/15" />
            <Button size="sm" variant="outline"
              className="h-7 text-xs border-foreground/20 gap-1.5"
              onClick={() => setAssignTargets(selectedIds)}>
              <UserCheck className="w-3.5 h-3.5" /> Assign
            </Button>
            <Button size="sm" variant="outline"
              className="h-7 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10 gap-1.5"
              onClick={() => setFixTargets(selectedIds)}>
              <CheckCheck className="w-3.5 h-3.5" /> Mark Fixed
            </Button>
            <Button size="sm" variant="outline"
              className="h-7 text-xs border-foreground/20 gap-1.5"
              onClick={() => setCommentTargets(selectedIds)}>
              <MessageSquare className="w-3.5 h-3.5" /> Add Comment
            </Button>
            <Button size="sm" variant="outline"
              className="h-7 text-xs border-foreground/20 gap-1.5"
              onClick={() => setExportOpen(true)}>
              <Download className="w-3.5 h-3.5" /> Export
            </Button>
            <button
              onClick={() => setSelected(new Set())}
              className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors">
              Clear
            </button>
          </div>
        )}

        {/* ── Findings table ──────────────────────────────────────── */}
        {filteredRows.length === 0 ? (
          <div className="py-14 text-center text-sm text-muted-foreground/60">
            No findings match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/8 bg-foreground/[0.02] sticky top-0 z-10">
                  <th className="py-2.5 px-4 w-9">
                    <CB checked={allSelected} indeterminate={someSelected} onToggle={toggleAll} />
                  </th>
                  {['Severity', 'Title', 'Target', 'Scanner', 'Status', 'SLA', 'Assignee', 'Comments', 'Created', 'Actions'].map(h => (
                    <th key={h} className="text-left py-2.5 px-3 text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row, i) => {
                  const t   = getT(row.id)
                  const isSel = selected.has(row.id)
                  const rowCls = isSel
                    ? 'bg-primary/[0.06]'
                    : i % 2 === 1
                      ? 'bg-foreground/[0.015] hover:bg-foreground/[0.04]'
                      : 'hover:bg-foreground/[0.03]'
                  const commentCount = t.comments.length

                  return (
                    <tr key={row.id} className={`border-b border-foreground/5 transition-colors ${rowCls}`}>

                      {/* Checkbox */}
                      <td className="py-2.5 px-4">
                        <CB checked={isSel} onToggle={() => toggleRow(row.id)} />
                      </td>

                      {/* Severity */}
                      <td className="py-2.5 px-3"><SevBadge severity={row.severity} /></td>

                      {/* Title — opens drawer */}
                      <td className="py-2.5 px-3 max-w-[260px]">
                        <button
                          onClick={() => setDrawerFinding(row)}
                          className="text-sm text-foreground font-medium hover:text-primary transition-colors text-left line-clamp-1"
                        >
                          {row.title}
                        </button>
                        <p className="text-[10px] text-muted-foreground/45 font-mono truncate mt-0.5">{row.template}</p>
                      </td>

                      {/* Target */}
                      <td className="py-2.5 px-3 max-w-[140px]">
                        <span className="text-xs font-mono text-muted-foreground truncate block">{row.target}</span>
                        {row.port != null && <span className="text-[10px] text-muted-foreground/45">:{row.port}</span>}
                      </td>

                      {/* Scanner */}
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-muted-foreground capitalize">{row.scanner}</span>
                      </td>

                      {/* Status — clickable badge → dropdown */}
                      <td className="py-2.5 px-3">
                        <StatusBadge
                          status={t.status}
                          onClick={(e) => openStatusDropFor(e, row.id)}
                        />
                      </td>

                      {/* SLA badge */}
                      <td className="py-2.5 px-3">
                        <SlaBadge
                          severity={row.severity}
                          createdAt={row.createdAt}
                          isFixed={t.status === 'fixed'}
                          policy={slaPolicy}
                        />
                      </td>

                      {/* Assignee */}
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => { setDrawerFinding(row) }}
                          className="flex items-center gap-1.5 hover:opacity-80 transition-opacity"
                          title={t.assigneeName ?? 'Unassigned — click to assign'}
                        >
                          <AssigneeAvatar name={t.assigneeName} size="xs" />
                          <span className="text-xs text-muted-foreground max-w-[80px] truncate">
                            {t.assigneeName ?? <span className="text-muted-foreground/40">—</span>}
                          </span>
                        </button>
                      </td>

                      {/* Comment count */}
                      <td className="py-2.5 px-3">
                        {commentCount > 0 ? (
                          <span className="flex items-center gap-1 text-xs text-muted-foreground">
                            <MessageSquare className="w-3 h-3" /> {commentCount}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground/25">—</span>
                        )}
                      </td>

                      {/* Created */}
                      <td className="py-2.5 px-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatRelative(row.createdAt)}
                      </td>

                      {/* Quick actions */}
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-0.5">
                          <button
                            onClick={() => setCommentTargets([row.id])}
                            title="Add comment"
                            className="relative p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
                          >
                            <MessageSquare className="w-3.5 h-3.5" />
                            {commentCount > 0 && (
                              <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-primary text-[8px] font-bold text-primary-foreground flex items-center justify-center">
                                {commentCount > 9 ? '9+' : commentCount}
                              </span>
                            )}
                          </button>
                          <button
                            onClick={() => setAssignTargets([row.id])}
                            title="Assign"
                            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
                          >
                            <UserCheck className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setFixTargets([row.id])}
                            title="Mark fixed"
                            disabled={t.status === 'fixed'}
                            className="p-1.5 rounded-lg text-muted-foreground hover:text-green-400 hover:bg-green-500/10 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <CheckCheck className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setDrawerFinding(row)}
                            title="View details"
                            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Status dropdown (fixed, outside overflow) ────────────── */}
      {statusDropFor && (
        <StatusDropdown
          anchorPos={statusDropPos}
          current={getT(statusDropFor).status}
          onSelect={(s) => changeStatus(statusDropFor, s)}
          onClose={() => setStatusDropFor(null)}
        />
      )}

      {/* ── Fix confirmation ─────────────────────────────────────── */}
      {fixTargets && (
        <ConfirmFixModal
          targets={fixTargets}
          allCves={[]}
          onConfirm={() => confirmFix(fixTargets)}
          onClose={() => setFixTargets(null)}
          loading={opLoading}
        />
      )}

      {/* ── Comment modal ────────────────────────────────────────── */}
      {commentTargets && (
        <FindingCommentModal
          targets={commentTargets}
          allFindings={summary.findings}
          existingComments={commentTargets.length === 1 ? getT(commentTargets[0]).comments : []}
          onSubmit={(text) => submitComment(commentTargets, text)}
          onClose={() => setCommentTargets(null)}
          loading={opLoading}
        />
      )}

      {/* ── Bulk assign modal ────────────────────────────────────── */}
      {assignTargets && (
        <BulkAssignModal
          count={assignTargets.length}
          currentUser={user}
          onAssign={(m) => bulkAssign(assignTargets, m)}
          onClose={() => setAssignTargets(null)}
          loading={opLoading}
        />
      )}

      {/* ── Export modal ─────────────────────────────────────────── */}
      {exportOpen && (
        <ExportModal onExport={doExport} onClose={() => setExportOpen(false)} />
      )}

      {/* ── Finding details drawer ───────────────────────────────── */}
      {drawerFinding && (
        <FindingDrawer
          finding={drawerFinding}
          tracking={getT(drawerFinding.id)}
          currentUser={user}
          slaPolicy={slaPolicy}
          onClose={() => setDrawerFinding(null)}
          onStatusChange={(s) => changeStatus(drawerFinding.id, s)}
          onAssign={(m) => assignFinding(drawerFinding.id, m)}
          onUnassign={() => assignFinding(drawerFinding.id, null)}
          onAddComment={() => { setCommentTargets([drawerFinding.id]); setDrawerFinding(null) }}
        />
      )}
    </>
  )
}

// ── CVE enterprise panel ───────────────────────────────────────────────
// All status/comment/export/drawer sub-components live here.

// Tiny checkbox button (avoids importing a full Checkbox from shadcn)
function CB({ checked, indeterminate, onToggle }: {
  checked: boolean; indeterminate?: boolean; onToggle: () => void
}) {
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onToggle() }}
      className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
        checked || indeterminate
          ? 'bg-primary border-primary'
          : 'border-foreground/30 hover:border-foreground/60 bg-transparent'
      }`}
    >
      {indeterminate && !checked
        ? <span className="w-2 h-px bg-primary-foreground" />
        : checked
          ? <Check className="w-2.5 h-2.5 text-primary-foreground" strokeWidth={3} />
          : null}
    </button>
  )
}

// Status badge (clickable — triggers dropdown via parent)
function StatusBadge({ status, onClick }: {
  status:   CveStatus
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void
}) {
  const { label, cls, dot } = STATUS_CONFIG[status]
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick?.(e) }}
      className={`flex items-center gap-1.5 text-[10px] font-semibold px-2 py-0.5 rounded-full border whitespace-nowrap transition-opacity hover:opacity-80 ${cls}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
      {label}
    </button>
  )
}

// Floating status dropdown (fixed to viewport — survives overflow clipping)
function StatusDropdown({
  anchorPos,
  current,
  onSelect,
  onClose,
}: {
  anchorPos:  { x: number; y: number }
  current:    CveStatus
  onSelect:   (s: CveStatus) => void
  onClose:    () => void
}) {
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        className="fixed z-50 bg-card border border-foreground/15 rounded-xl shadow-2xl py-1.5 min-w-[180px]"
        style={{ left: anchorPos.x, top: anchorPos.y }}
      >
        <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-wider px-3 pt-1 pb-1.5">
          Set Status
        </p>
        {STATUS_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => { onSelect(opt.value); onClose() }}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs hover:bg-foreground/5 transition-colors ${
              current === opt.value ? 'text-foreground' : 'text-muted-foreground'
            }`}
          >
            <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
            {opt.label}
            {current === opt.value && <Check className="w-3 h-3 ml-auto text-primary" strokeWidth={2.5} />}
          </button>
        ))}
      </div>
    </>
  )
}

// Confirmation dialog (fix single or bulk)
function ConfirmFixModal({
  targets,
  allCves,
  onConfirm,
  onClose,
  loading,
}: {
  targets:  string[]
  allCves:  NormalizedCve[]
  onConfirm: () => void
  onClose:  () => void
  loading:  boolean
}) {
  const single = targets.length === 1
    ? allCves.find(c => c.id === targets[0])
    : null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-md p-6 space-y-5">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-green-500/15 flex items-center justify-center shrink-0">
            <CheckCheck className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-foreground">
              Mark as Fixed?
            </h3>
            <p className="text-sm text-muted-foreground mt-0.5">
              {targets.length === 1 ? 'This vulnerability' : `${targets.length} selected vulnerabilities`} will be marked as Fixed.
            </p>
          </div>
        </div>
        {single && (
          <div className="bg-foreground/5 border border-foreground/10 rounded-xl p-4 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">CVE</span>
              <span className="font-mono font-semibold text-primary">{single.cveId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Target</span>
              <span className="font-mono text-foreground/80 truncate max-w-[220px]">{single.target}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">CVSS</span>
              <span className={`font-bold ${cvssColor(single.cvssScore)}`}>{single.cvssScore.toFixed(1)}</span>
            </div>
          </div>
        )}
        <div className="flex gap-3 pt-1">
          <Button variant="outline" className="flex-1 border-foreground/20" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            className="flex-1 bg-green-600 hover:bg-green-500 text-white"
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? 'Marking…' : 'Mark Fixed'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// Comment modal (single or bulk)
function CommentModal({
  targets,
  allCves,
  existingComments,
  onSubmit,
  onClose,
  loading,
}: {
  targets:          string[]
  allCves:          NormalizedCve[]
  existingComments: CveComment[]
  onSubmit:         (text: string) => void
  onClose:          () => void
  loading:          boolean
}) {
  const [text, setText] = useState('')
  const single = targets.length === 1 ? allCves.find(c => c.id === targets[0]) : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-lg flex flex-col max-h-[80vh]">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-foreground/10">
          <div className="flex items-center gap-2.5">
            <MessageSquare className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">
              {single ? `Comments — ${single.cveId}` : `Add Comment to ${targets.length} CVEs`}
            </h3>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Existing comments */}
        {existingComments.length > 0 && (
          <div className="overflow-y-auto max-h-48 px-5 py-3 space-y-3 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Comment History</p>
            {existingComments.map((c) => (
              <div key={c.id} className="space-y-1">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary shrink-0">
                    {c.userName.charAt(0).toUpperCase()}
                  </div>
                  <span className="text-xs font-medium text-foreground">{c.userName}</span>
                  <span className="text-[10px] text-muted-foreground/50 ml-auto">{formatDate(c.createdAt)}</span>
                </div>
                <p className="text-xs text-muted-foreground pl-8 leading-relaxed">{c.text}</p>
              </div>
            ))}
          </div>
        )}

        {/* Input */}
        <div className="px-5 py-4 space-y-3">
          <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Internal Notes</p>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Add an internal note (never included in exported reports)…"
            rows={4}
            className="w-full bg-foreground/5 border border-foreground/15 rounded-xl text-sm text-foreground placeholder:text-muted-foreground/40 px-3.5 py-2.5 resize-none focus:outline-none focus:ring-1 focus:ring-primary/40"
          />
          <div className="flex gap-3">
            <Button variant="outline" className="flex-1 border-foreground/20" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button
              className="flex-1"
              onClick={() => onSubmit(text)}
              disabled={loading || !text.trim()}
            >
              {loading ? 'Saving…' : 'Save Comment'}
            </Button>
          </div>
        </div>

      </div>
    </div>
  )
}

// Export options modal
function ExportModal({
  onExport,
  onClose,
}: {
  onExport: (opts: ExportOptions) => void
  onClose:  () => void
}) {
  const [opts, setOpts] = useState<ExportOptions>({
    includeComments: true,
    includeTimeline: false,
    includeFixed:    true,
    onlyOpen:        false,
  })
  function toggle(k: keyof ExportOptions) {
    setOpts(p => ({ ...p, [k]: !p[k] }))
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border border-foreground/15 rounded-2xl shadow-2xl w-full max-w-sm p-6 space-y-5">
        <div className="flex items-center gap-2.5">
          <FileText className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Export CVEs</h3>
        </div>
        <div className="space-y-3">
          {([
            ['includeComments', 'Include comments'],
            ['includeTimeline', 'Include activity timeline'],
            ['includeFixed',    'Include fixed CVEs'],
            ['onlyOpen',        'Export only open CVEs'],
          ] as [keyof ExportOptions, string][]).map(([k, label]) => (
            <label key={k} className="flex items-center gap-3 cursor-pointer group">
              <CB checked={opts[k]} onToggle={() => toggle(k)} />
              <span className="text-sm text-muted-foreground group-hover:text-foreground transition-colors">{label}</span>
            </label>
          ))}
        </div>
        <div className="flex gap-3 pt-1">
          <Button variant="outline" className="flex-1 border-foreground/20" onClick={onClose}>Cancel</Button>
          <Button className="flex-1" onClick={() => onExport(opts)}>
            <Download className="w-3.5 h-3.5 mr-1.5" /> Export JSON
          </Button>
        </div>
      </div>
    </div>
  )
}

// Right-side CVE details drawer
function CveDrawer({
  cve,
  tracking,
  onClose,
  onStatusChange,
  onAddComment,
}: {
  cve:            NormalizedCve
  tracking:       CveTracking
  onClose:        () => void
  onStatusChange: (s: CveStatus) => void
  onAddComment:   () => void
}) {
  const { cls } = STATUS_CONFIG[tracking.status]
  const { dot } = STATUS_CONFIG[tracking.status]
  const [statusOpen, setStatusOpen] = useState(false)
  const statusBtnRef = useRef<HTMLButtonElement>(null)
  const [dropPos, setDropPos] = useState({ x: 0, y: 0 })

  function openStatusDrop() {
    if (statusBtnRef.current) {
      const r = statusBtnRef.current.getBoundingClientRect()
      setDropPos({ x: r.left, y: r.bottom + 4 })
    }
    setStatusOpen(true)
  }

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-[2px]" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-[500px] max-w-[95vw] bg-card border-l border-foreground/10 flex flex-col shadow-2xl">

        {/* Drawer header */}
        <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-foreground/10">
          <div>
            <p className="text-xs text-muted-foreground font-mono mb-1">{cve.module.toUpperCase()} · {cve.technology}</p>
            <h2 className="text-lg font-bold text-foreground">{cve.cveId}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto">

          {/* Key metrics strip */}
          <div className="grid grid-cols-3 border-b border-foreground/8">
            {[
              { label: 'Severity', value: cve.severity, cls: SEV_BADGE[cve.severity] ?? '' },
              { label: 'CVSS',     value: cve.cvssScore.toFixed(1), cls: cvssColor(cve.cvssScore)    },
              { label: 'Exploit',  value: cve.exploitAvailable ? 'Yes' : 'No',
                cls: cve.exploitAvailable ? 'text-red-400 font-bold' : 'text-muted-foreground' },
            ].map(({ label, value, cls: c }) => (
              <div key={label} className="px-5 py-4 border-r last:border-r-0 border-foreground/8">
                <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-sm font-bold ${c}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Details */}
          <div className="px-6 py-5 space-y-4 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Vulnerability Details</p>
            <div className="space-y-3 text-sm">
              {[
                ['Technology',   cve.technology],
                ['Version',      cve.version],
                ['Target',       cve.target],
                ['Published',    formatDate(cve.published)],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <span className="text-muted-foreground w-24 shrink-0">{k}</span>
                  <span className="text-foreground font-mono text-xs break-all">{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Description */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-2">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{cve.description || 'No description available.'}</p>
          </div>

          {/* Status */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-3">Current Status</p>
            <button
              ref={statusBtnRef}
              onClick={openStatusDrop}
              className={`flex items-center gap-2 text-xs font-semibold px-3 py-1.5 rounded-full border hover:opacity-80 transition-opacity ${cls}`}
            >
              <span className={`w-2 h-2 rounded-full ${dot}`} />
              {STATUS_CONFIG[tracking.status].label}
              <ChevronDown className="w-3 h-3 ml-1 opacity-60" />
            </button>
            {statusOpen && (
              <StatusDropdown
                anchorPos={dropPos}
                current={tracking.status}
                onSelect={(s) => { onStatusChange(s); setStatusOpen(false) }}
                onClose={() => setStatusOpen(false)}
              />
            )}
          </div>

          {/* Comments */}
          <div className="px-6 py-5 border-b border-foreground/8">
            <div className="flex items-center justify-between mb-3">
              <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">
                Internal Comments ({tracking.comments.length})
              </p>
              <button
                onClick={onAddComment}
                className="text-[10px] font-semibold text-primary hover:underline"
              >
                + Add Comment
              </button>
            </div>
            {tracking.comments.length === 0 ? (
              <p className="text-xs text-muted-foreground/50 italic">No internal comments yet.</p>
            ) : (
              <div className="space-y-4">
                {tracking.comments.map((c) => (
                  <div key={c.id} className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary shrink-0">
                        {c.userName.charAt(0).toUpperCase()}
                      </div>
                      <span className="text-xs font-medium text-foreground">{c.userName}</span>
                      <span className="text-[10px] text-muted-foreground/50 ml-auto">{formatDate(c.createdAt)}</span>
                    </div>
                    <p className="text-xs text-muted-foreground pl-8 leading-relaxed">{c.text}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Timeline */}
          <div className="px-6 py-5">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-4">Activity Timeline</p>
            {tracking.timeline.length === 0 ? (
              <p className="text-xs text-muted-foreground/50 italic">No activity recorded.</p>
            ) : (
              <div className="relative pl-5">
                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-foreground/10" />
                <div className="space-y-4">
                  {[...tracking.timeline].sort((a, b) =>
                    new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
                  ).map((ev) => {
                    const Icon =
                      ev.action === 'discovered'     ? ShieldAlert   :
                      ev.action === 'comment_added'  ? MessageSquare :
                      ev.action === 'marked_fixed'   ? CheckCheck    :
                      ev.action === 'reopened'       ? RotateCcw     :
                      Clock
                    return (
                      <div key={ev.id} className="flex items-start gap-3">
                        <div className="w-3.5 h-3.5 rounded-full bg-card border-2 border-primary/40 flex items-center justify-center shrink-0 mt-0.5">
                          <Icon className="w-2 h-2 text-primary/60" />
                        </div>
                        <div>
                          <p className="text-xs text-foreground/80">
                            {ev.details ?? ev.action.replace(/_/g, ' ')}
                          </p>
                          <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                            {ev.userName && `${ev.userName} · `}{formatDate(ev.createdAt)}
                          </p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

        </div>
      </div>
    </>
  )
}

// ── Enterprise CVE panel ───────────────────────────────────────────────

function CvesPanel({
  summary,
  onClose,
}: {
  summary: CveTargetSummary
  onClose: () => void
}) {
  const { user } = useAuth()
  const Icon     = MODULE_ICON[summary.module]

  // ── Tracking state ────────────────────────────────────────────────
  const [tracking, setTracking] = useState<Record<string, CveTracking>>({})

  // ── Filter state ──────────────────────────────────────────────────
  const [panelSearch,   setPanelSearch]   = useState('')
  const [statusFilter,  setStatusFilter]  = useState<CveStatus | 'all'>('all')
  const [commentFilter, setCommentFilter] = useState<'all' | 'has' | 'none'>('all')
  const [exploitOnly,   setExploitOnly]   = useState(false)

  // ── Selection ─────────────────────────────────────────────────────
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // ── Status dropdown ───────────────────────────────────────────────
  const [statusDropFor, setStatusDropFor] = useState<string | null>(null)
  const [statusDropPos, setStatusDropPos] = useState({ x: 0, y: 0 })

  // ── Modals / drawer ───────────────────────────────────────────────
  const [drawerCve,       setDrawerCve]       = useState<NormalizedCve | null>(null)
  const [commentTargets,  setCommentTargets]  = useState<string[] | null>(null)
  const [fixTargets,      setFixTargets]      = useState<string[] | null>(null)
  const [exportOpen,      setExportOpen]      = useState(false)
  const [opLoading,       setOpLoading]       = useState(false)

  // ── Load tracking ─────────────────────────────────────────────────
  useEffect(() => {
    if (!user) return
    return listenToCveTracking(user.uid, setTracking)
  }, [user])

  function getT(cveId: string): CveTracking {
    return tracking[cveId] ?? defaultTracking(cveId)
  }

  // ── Status change ─────────────────────────────────────────────────
  async function changeStatus(cveDocId: string, newStatus: CveStatus) {
    if (!user) return
    const existing = getT(cveDocId)
    const now = new Date().toISOString()
    const ev: CveTimelineEvent = {
      id:       genTrackingId(),
      action:   'status_changed',
      userId:   user.uid,
      userName: user.name,
      createdAt: now,
      details:  `Status changed to ${STATUS_CONFIG[newStatus].label}`,
    }
    const updated: CveTracking = {
      ...existing,
      cveDocId,
      status:   newStatus,
      timeline: [...existing.timeline, ev],
      updatedAt: now,
    }
    setTracking(prev => ({ ...prev, [cveDocId]: updated }))
    await upsertCveTracking(user.uid, updated)
  }

  // ── Add comment ───────────────────────────────────────────────────
  async function submitComment(cveDocIds: string[], text: string) {
    if (!user || !text.trim()) return
    setOpLoading(true)
    try {
      const now = new Date().toISOString()
      await Promise.all(cveDocIds.map(cveDocId => {
        const existing = getT(cveDocId)
        const comment: CveComment = {
          id: genTrackingId(), userId: user.uid, userName: user.name,
          text: text.trim(), createdAt: now,
        }
        const ev: CveTimelineEvent = {
          id: genTrackingId(), action: 'comment_added',
          userId: user.uid, userName: user.name, createdAt: now,
        }
        const updated: CveTracking = {
          ...existing, cveDocId,
          comments: [...existing.comments, comment],
          timeline: [...existing.timeline, ev],
          updatedAt: now,
        }
        setTracking(prev => ({ ...prev, [cveDocId]: updated }))
        return upsertCveTracking(user.uid, updated)
      }))
    } finally {
      setOpLoading(false)
      setCommentTargets(null)
    }
  }

  // ── Bulk mark fixed ───────────────────────────────────────────────
  async function confirmFix(cveDocIds: string[]) {
    if (!user) return
    setOpLoading(true)
    try {
      await Promise.all(cveDocIds.map(id => changeStatus(id, 'fixed')))
      setSelected(new Set())
      setFixTargets(null)
    } finally {
      setOpLoading(false)
    }
  }

  // ── Export ────────────────────────────────────────────────────────
  function doExport(opts: ExportOptions) {
    const rows = filteredRows.filter(r => {
      const st = getT(r.id).status
      if (opts.onlyOpen)      return st === 'open'
      if (!opts.includeFixed) return st !== 'fixed'
      return true
    })
    const data = rows.map(r => {
      const t = getT(r.id)
      return {
        cveId:            r.cveId,
        technology:       r.technology,
        version:          r.version,
        severity:         r.severity,
        cvssScore:        r.cvssScore,
        target:           r.target,
        exploitAvailable: r.exploitAvailable,
        published:        r.published,
        status:           t.status,
        ...(opts.includeComments && { comments: t.comments }),
        ...(opts.includeTimeline && { timeline: t.timeline }),
      }
    })
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cves-${summary.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  // ── Filtered rows ─────────────────────────────────────────────────
  const filteredRows = useMemo(() => {
    let r = [...summary.cves].sort((a, b) =>
      (SEV_ORDER[a.severity] ?? 6) - (SEV_ORDER[b.severity] ?? 6) || b.cvssScore - a.cvssScore,
    )
    if (statusFilter !== 'all') r = r.filter(c => getT(c.id).status === statusFilter)
    if (commentFilter === 'has')  r = r.filter(c => getT(c.id).comments.length > 0)
    if (commentFilter === 'none') r = r.filter(c => getT(c.id).comments.length === 0)
    if (exploitOnly)  r = r.filter(c => c.exploitAvailable)
    if (panelSearch.trim()) {
      const q = panelSearch.toLowerCase()
      r = r.filter(c =>
        c.cveId.toLowerCase().includes(q) ||
        c.technology.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q),
      )
    }
    return r
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary.cves, tracking, statusFilter, commentFilter, exploitOnly, panelSearch])

  // ── Quick metrics ─────────────────────────────────────────────────
  const metrics = useMemo(() => ({
    open:         summary.cves.filter(c => getT(c.id).status === 'open').length,
    in_progress:  summary.cves.filter(c => tracking[c.id]?.status === 'in_progress').length,
    fixed:        summary.cves.filter(c => tracking[c.id]?.status === 'fixed').length,
    accepted:     summary.cves.filter(c => tracking[c.id]?.status === 'accepted_risk').length,
    exploitable:  summary.cves.filter(c => c.exploitAvailable).length,
    total:        summary.cves.length,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [summary.cves, tracking])

  // ── Selection helpers ─────────────────────────────────────────────
  const allSelected = filteredRows.length > 0 && filteredRows.every(r => selected.has(r.id))
  const someSelected = !allSelected && filteredRows.some(r => selected.has(r.id))

  function toggleAll() {
    if (allSelected) setSelected(new Set())
    else setSelected(new Set(filteredRows.map(r => r.id)))
  }

  function toggleRow(id: string) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function openStatusDropFor(e: React.MouseEvent, cveId: string) {
    e.stopPropagation()
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setStatusDropPos({ x: rect.left, y: rect.bottom + 4 })
    setStatusDropFor(cveId)
  }

  const selectedCveIds = Array.from(selected)

  // ── Render ────────────────────────────────────────────────────────
  return (
    <>
      <div className="bg-card border border-primary/25 rounded-xl overflow-hidden shadow-lg shadow-primary/5">

        {/* ── Panel header ───────────────────────────────────────── */}
        <div className="flex items-center justify-between gap-4 px-5 py-3.5 border-b border-foreground/10 bg-primary/[0.03]">
          <div className="flex items-center gap-2.5 min-w-0">
            <Icon className="w-4 h-4 text-muted-foreground/70 shrink-0" />
            <span className="text-sm font-semibold text-foreground truncate font-mono">{summary.target}</span>
            <span className="text-xs text-muted-foreground/50 shrink-0">— {summary.total} CVEs</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/40" />
              <input
                placeholder="Search CVEs…"
                value={panelSearch}
                onChange={(e) => setPanelSearch(e.target.value)}
                className="pl-7 pr-3 py-1.5 bg-foreground/5 border border-foreground/15 rounded-lg text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-primary/40 w-44"
              />
            </div>
            <Button
              variant="outline" size="sm"
              className="h-7 px-2.5 border-foreground/20 text-xs gap-1.5"
              onClick={() => setExportOpen(true)}
            >
              <Download className="w-3.5 h-3.5" /> Export
            </Button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Filter bar ─────────────────────────────────────────── */}
        <div className="px-5 py-2 border-b border-foreground/8 flex flex-wrap items-center gap-2 bg-foreground/[0.015]">
          <SlidersHorizontal className="w-3.5 h-3.5 text-muted-foreground/50 shrink-0" />

          {/* Status filter */}
          <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${
                statusFilter === 'all' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              }`}
            >All</button>
            {STATUS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setStatusFilter(statusFilter === opt.value ? 'all' : opt.value)}
                className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-all ${
                  statusFilter === opt.value
                    ? `${opt.cls} border`
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${opt.dot}`} />
                {opt.label}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-foreground/10" />

          {/* Comment filter */}
          <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-md border border-foreground/8">
            {([['all','All'],['has','Has Comments'],['none','No Comments']] as const).map(([v,l]) => (
              <button
                key={v}
                onClick={() => setCommentFilter(v)}
                className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${
                  commentFilter === v ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {l}
              </button>
            ))}
          </div>

          <div className="h-4 w-px bg-foreground/10" />

          {/* Exploit filter */}
          <button
            onClick={() => setExploitOnly(p => !p)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-medium border transition-all ${
              exploitOnly
                ? 'bg-red-500/15 text-red-400 border-red-500/25'
                : 'border-transparent text-muted-foreground hover:bg-foreground/5'
            }`}
          >
            <Zap className="w-3 h-3" /> Exploitable Only
          </button>
        </div>

        {/* ── Quick metrics ───────────────────────────────────────── */}
        <div className="grid grid-cols-3 md:grid-cols-6 border-b border-foreground/8">
          {[
            { label: 'Open',        value: metrics.open,        cls: 'text-red-400',    filter: () => setStatusFilter('open')        },
            { label: 'In Progress', value: metrics.in_progress, cls: 'text-blue-400',   filter: () => setStatusFilter('in_progress') },
            { label: 'Fixed',       value: metrics.fixed,       cls: 'text-green-400',  filter: () => setStatusFilter('fixed')       },
            { label: 'Accepted',    value: metrics.accepted,    cls: 'text-orange-400', filter: () => setStatusFilter('accepted_risk') },
            { label: 'Exploitable', value: metrics.exploitable, cls: 'text-red-400',    filter: () => setExploitOnly(p => !p)        },
            { label: 'Total CVEs',  value: metrics.total,       cls: 'text-foreground', filter: () => { setStatusFilter('all'); setExploitOnly(false) } },
          ].map((m) => (
            <button
              key={m.label}
              onClick={m.filter}
              className="px-4 py-3 text-left hover:bg-foreground/5 transition-colors border-r last:border-r-0 border-foreground/8 group"
            >
              <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider group-hover:text-muted-foreground transition-colors">
                {m.label}
              </p>
              <p className={`text-xl font-bold tabular-nums mt-0.5 ${m.cls}`}>{m.value}</p>
            </button>
          ))}
        </div>

        {/* ── Bulk toolbar ────────────────────────────────────────── */}
        {selected.size > 0 && (
          <div className="px-5 py-2.5 border-b border-foreground/8 flex items-center gap-3 bg-primary/[0.04]">
            <span className="text-sm font-semibold text-foreground tabular-nums">
              {selected.size} selected
            </span>
            <div className="h-4 w-px bg-foreground/15" />
            <Button
              size="sm" variant="outline"
              className="h-7 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10 gap-1.5"
              onClick={() => setFixTargets(selectedCveIds)}
            >
              <CheckCheck className="w-3.5 h-3.5" /> Mark Fixed
            </Button>
            <Button
              size="sm" variant="outline"
              className="h-7 text-xs border-foreground/20 gap-1.5"
              onClick={() => setCommentTargets(selectedCveIds)}
            >
              <MessageSquare className="w-3.5 h-3.5" /> Add Comment
            </Button>
            <Button
              size="sm" variant="outline"
              className="h-7 text-xs border-foreground/20 gap-1.5"
              onClick={() => setExportOpen(true)}
            >
              <Download className="w-3.5 h-3.5" /> Export Selected
            </Button>
            <button
              onClick={() => setSelected(new Set())}
              className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear
            </button>
          </div>
        )}

        {/* ── CVE table ───────────────────────────────────────────── */}
        {filteredRows.length === 0 ? (
          <div className="py-14 text-center text-sm text-muted-foreground/60">
            No CVEs match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/8 bg-foreground/[0.02]">
                  <th className="py-2.5 px-4 w-9">
                    <CB checked={allSelected} indeterminate={someSelected} onToggle={toggleAll} />
                  </th>
                  {['CVE ID', 'Technology', 'Version', 'Severity', 'CVSS', 'Status', 'Exploit', 'Published', 'Actions'].map((h) => (
                    <th key={h} className="text-left py-2.5 px-3 text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row, i) => {
                  const t       = getT(row.id)
                  const isSel   = selected.has(row.id)
                  const rowCls  = isSel
                    ? 'bg-primary/[0.06]'
                    : i % 2 === 1
                      ? 'bg-foreground/[0.015] hover:bg-foreground/[0.04]'
                      : 'hover:bg-foreground/[0.03]'
                  const commentCount = t.comments.length
                  return (
                    <tr
                      key={row.id}
                      className={`border-b border-foreground/5 transition-colors ${rowCls}`}
                    >
                      {/* Checkbox */}
                      <td className="py-2.5 px-4">
                        <CB checked={isSel} onToggle={() => toggleRow(row.id)} />
                      </td>

                      {/* CVE ID — opens drawer */}
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => setDrawerCve(row)}
                          className="text-xs font-mono font-semibold text-primary hover:underline underline-offset-2 text-left"
                        >
                          {row.cveId}
                        </button>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="text-sm text-foreground">{row.technology}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-xs font-mono text-muted-foreground">{row.version}</span>
                      </td>
                      <td className="py-2.5 px-3"><SevBadge severity={row.severity} /></td>
                      <td className="py-2.5 px-3">
                        <span className={`text-sm font-bold ${cvssColor(row.cvssScore)}`}>{row.cvssScore.toFixed(1)}</span>
                      </td>

                      {/* Status — clickable badge → dropdown */}
                      <td className="py-2.5 px-3">
                        <StatusBadge
                          status={t.status}
                          onClick={(e) => openStatusDropFor(e, row.id)}
                        />
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

                      {/* Action buttons */}
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setCommentTargets([row.id])}
                            title="Add comment"
                            className="relative p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10 transition-colors"
                          >
                            <MessageSquare className="w-3.5 h-3.5" />
                            {commentCount > 0 && (
                              <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-primary text-[8px] font-bold text-primary-foreground flex items-center justify-center">
                                {commentCount > 9 ? '9+' : commentCount}
                              </span>
                            )}
                          </button>
                          <button
                            onClick={() => setFixTargets([row.id])}
                            title="Mark as fixed"
                            disabled={t.status === 'fixed'}
                            className="p-1.5 rounded-lg text-muted-foreground hover:text-green-400 hover:bg-green-500/10 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <CheckCheck className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Status dropdown (fixed, outside overflow) ────────────── */}
      {statusDropFor && (
        <StatusDropdown
          anchorPos={statusDropPos}
          current={getT(statusDropFor).status}
          onSelect={(s) => changeStatus(statusDropFor, s)}
          onClose={() => setStatusDropFor(null)}
        />
      )}

      {/* ── Modals ──────────────────────────────────────────────── */}
      {fixTargets && (
        <ConfirmFixModal
          targets={fixTargets}
          allCves={summary.cves}
          onConfirm={() => confirmFix(fixTargets)}
          onClose={() => setFixTargets(null)}
          loading={opLoading}
        />
      )}
      {commentTargets && (
        <CommentModal
          targets={commentTargets}
          allCves={summary.cves}
          existingComments={commentTargets.length === 1 ? getT(commentTargets[0]).comments : []}
          onSubmit={(text) => submitComment(commentTargets, text)}
          onClose={() => setCommentTargets(null)}
          loading={opLoading}
        />
      )}
      {exportOpen && (
        <ExportModal onExport={doExport} onClose={() => setExportOpen(false)} />
      )}

      {/* ── CVE Details Drawer ───────────────────────────────────── */}
      {drawerCve && (
        <CveDrawer
          cve={drawerCve}
          tracking={getT(drawerCve.id)}
          onClose={() => setDrawerCve(null)}
          onStatusChange={(s) => changeStatus(drawerCve.id, s)}
          onAddComment={() => { setCommentTargets([drawerCve.id]); setDrawerCve(null) }}
        />
      )}
    </>
  )
}

// ── SLA Config Modal ───────────────────────────────────────────────────

const SLA_MODAL_ROWS: {
  key: keyof Pick<SlaPolicy, 'critical' | 'high' | 'medium' | 'low' | 'info'>
  label: string; dotCls: string
}[] = [
  { key: 'critical', label: 'Critical', dotCls: 'bg-red-400'    },
  { key: 'high',     label: 'High',     dotCls: 'bg-orange-400' },
  { key: 'medium',   label: 'Medium',   dotCls: 'bg-yellow-400' },
  { key: 'low',      label: 'Low',      dotCls: 'bg-blue-400'   },
  { key: 'info',     label: 'Info',     dotCls: 'bg-slate-400'  },
]

function SlaConfigModal({
  policy,
  uid,
  onClose,
}: {
  policy:  SlaPolicy
  uid:     string
  onClose: () => void
}) {
  const [draft,  setDraft]  = useState<SlaPolicy>(policy)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)

  function setDays(
    key: keyof Pick<SlaPolicy, 'critical' | 'high' | 'medium' | 'low' | 'info'>,
    raw: string,
  ) {
    const n = parseInt(raw, 10)
    setDraft(prev => ({ ...prev, [key]: isNaN(n) || raw === '' ? null : Math.max(1, n) }))
  }

  async function handleSave() {
    setSaving(true)
    try {
      await saveSlaPolicy(uid, draft)
      setSaved(true)
      setTimeout(() => { setSaved(false); onClose() }, 900)
    } finally {
      setSaving(false)
    }
  }

  const isDirty = JSON.stringify(draft) !== JSON.stringify(policy)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 bg-card border border-foreground/12 rounded-2xl shadow-2xl w-full max-w-sm">
        <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-foreground/8">
          <div className="flex items-center gap-2.5">
            <CalendarClock className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">SLA Configuration</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-foreground/8 text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-1.5">
          {SLA_MODAL_ROWS.map(({ key, label, dotCls }) => (
            <div key={key} className="flex items-center justify-between gap-3 py-1">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full shrink-0 ${dotCls}`} />
                <span className="text-sm font-medium text-foreground">{label}</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  placeholder="—"
                  value={draft[key] ?? ''}
                  onChange={(e) => setDays(key, e.target.value)}
                  className="w-16 h-7 text-center bg-foreground/5 border border-foreground/15 rounded-lg text-sm font-semibold tabular-nums text-foreground focus:outline-none focus:ring-1 focus:ring-primary/40 placeholder:text-muted-foreground/30"
                />
                <span className="text-xs text-muted-foreground w-7 shrink-0">
                  {draft[key] != null ? 'days' : ''}
                </span>
              </div>
            </div>
          ))}

          <div className="border-t border-foreground/8 pt-3 mt-2">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-medium text-foreground">Due Soon Warning</p>
                <p className="text-[10px] text-muted-foreground/55 mt-0.5">
                  Flag findings N days before deadline
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={30}
                  value={draft.warnDays}
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10)
                    setDraft(prev => ({ ...prev, warnDays: isNaN(n) ? 3 : Math.max(1, n) }))
                  }}
                  className="w-16 h-7 text-center bg-foreground/5 border border-orange-500/20 rounded-lg text-sm font-semibold tabular-nums text-foreground focus:outline-none focus:ring-1 focus:ring-orange-400/40"
                />
                <span className="text-xs text-muted-foreground w-7 shrink-0">days</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 px-5 pb-5 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-foreground/8 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !isDirty}
            className={`flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              saved
                ? 'bg-green-500/20 text-green-400 border border-green-500/25'
                : isDirty
                  ? 'bg-primary text-primary-foreground hover:bg-primary/90'
                  : 'bg-foreground/8 text-muted-foreground cursor-not-allowed'
            }`}
          >
            {saving ? (
              <><RotateCcw className="w-3 h-3 animate-spin" /> Saving…</>
            ) : saved ? (
              <><Check className="w-3 h-3" /> Saved</>
            ) : (
              'Save Policy'
            )}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Filter Popover ─────────────────────────────────────────────────────

function FilterPopover({
  sevFilter,
  onSevFilter,
  slaFilter,
  onSlaFilter,
  statusFilter,
  onStatusFilter,
  sevKeys,
  typeFilter,
}: {
  sevFilter:      string | null
  onSevFilter:    (v: string | null) => void
  slaFilter:      SlaFilter
  onSlaFilter:    (v: SlaFilter) => void
  statusFilter:   string | null
  onStatusFilter: (v: string | null) => void
  sevKeys:        readonly string[]
  typeFilter:     TypeFilter
}) {
  const btnRef           = useRef<HTMLButtonElement>(null)
  const [open, setOpen]  = useState(false)
  const [pos,  setPos]   = useState({ x: 0, y: 0 })

  function handleOpen() {
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      setPos({ x: Math.max(8, r.right - 288), y: r.bottom + 6 })
    }
    setOpen(p => !p)
  }

  const activeCount = [
    sevFilter,
    slaFilter !== 'all' ? slaFilter : null,
    statusFilter,
  ].filter(Boolean).length

  return (
    <>
      <button
        ref={btnRef}
        onClick={handleOpen}
        className={`flex items-center gap-1.5 h-7 px-2.5 rounded-lg border text-xs font-medium transition-all ${
          activeCount > 0
            ? 'border-primary/40 text-primary bg-primary/8'
            : 'border-foreground/20 text-muted-foreground hover:text-foreground hover:border-foreground/35 hover:bg-foreground/5'
        }`}
      >
        <SlidersHorizontal className="w-3.5 h-3.5" />
        Filter
        {activeCount > 0 && (
          <span className="flex items-center justify-center w-4 h-4 rounded-full bg-primary text-[9px] text-primary-foreground font-bold leading-none">
            {activeCount}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div
            className="fixed z-50 bg-card border border-foreground/12 rounded-2xl shadow-2xl w-72 overflow-hidden"
            style={{ left: pos.x, top: pos.y }}
          >
            <div className="px-4 py-3 border-b border-foreground/8 flex items-center justify-between">
              <p className="text-xs font-semibold text-foreground">Filters</p>
              {activeCount > 0 && (
                <button
                  onClick={() => { onSevFilter(null); onSlaFilter('all'); onStatusFilter(null) }}
                  className="text-[10px] text-primary hover:underline"
                >
                  Clear all
                </button>
              )}
            </div>

            <div className="px-4 py-3 space-y-4 max-h-[70vh] overflow-y-auto">
              {/* Severity */}
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-2">
                  Severity
                </p>
                <div className="grid grid-cols-2 gap-0.5">
                  {sevKeys.map((sev) => {
                    const active = sevFilter === sev
                    const dotCls =
                      sev === 'critical' || sev === 'CRITICAL' ? 'bg-red-400'    :
                      sev === 'high'     || sev === 'HIGH'     ? 'bg-orange-400' :
                      sev === 'medium'   || sev === 'MEDIUM'   ? 'bg-yellow-400' :
                      sev === 'low'      || sev === 'LOW'      ? 'bg-blue-400'   :
                      'bg-slate-400'
                    return (
                      <button
                        key={sev}
                        onClick={() => onSevFilter(active ? null : sev)}
                        className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                          active
                            ? (SEV_BADGE[sev] ?? 'bg-foreground/10 text-foreground border border-foreground/20')
                            : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                        }`}
                      >
                        {active
                          ? <Check className="w-3 h-3 shrink-0" />
                          : <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`} />
                        }
                        <span className="capitalize">
                          {sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase()}
                        </span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* SLA (findings only) */}
              {typeFilter === 'findings' && (
                <div>
                  <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-2">
                    SLA Status
                  </p>
                  <div className="space-y-0.5">
                    {([
                      { key: 'within_sla' as SlaFilter, label: 'Within SLA', dotCls: 'bg-green-400',  textCls: 'text-green-400'  },
                      { key: 'due_soon'   as SlaFilter, label: 'Due Soon',   dotCls: 'bg-orange-400', textCls: 'text-orange-400' },
                      { key: 'breached'   as SlaFilter, label: 'Breached',   dotCls: 'bg-red-400',    textCls: 'text-red-400'    },
                    ]).map(({ key, label, dotCls, textCls }) => {
                      const active = slaFilter === key
                      return (
                        <button
                          key={key}
                          onClick={() => onSlaFilter(active ? 'all' : key)}
                          className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                            active
                              ? `bg-foreground/8 ${textCls}`
                              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`} />
                          {label}
                          {active && <Check className="w-3 h-3 ml-auto shrink-0" />}
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Workflow Status (findings only) */}
              {typeFilter === 'findings' && (
                <div>
                  <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider mb-2">
                    Workflow Status
                  </p>
                  <div className="space-y-0.5">
                    {STATUS_OPTIONS.map(({ value, label, dot }) => {
                      const active = statusFilter === value
                      return (
                        <button
                          key={value}
                          onClick={() => onStatusFilter(active ? null : value)}
                          className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                            active
                              ? 'bg-foreground/8 text-foreground'
                              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
                          {label}
                          {active && <Check className="w-3 h-3 ml-auto shrink-0" />}
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </>
  )
}

// ── Expandable Search ──────────────────────────────────────────────────

function ExpandableSearch({
  value,
  onChange,
}: {
  value:    string
  onChange: (v: string) => void
}) {
  const [expanded, setExpanded] = useState(!!value)
  const inputRef                = useRef<HTMLInputElement>(null)

  function handleExpand() {
    setExpanded(true)
    setTimeout(() => inputRef.current?.focus(), 50)
  }

  function handleBlur() {
    if (!value) setExpanded(false)
  }

  if (!expanded) {
    return (
      <button
        onClick={handleExpand}
        className="flex items-center justify-center w-7 h-7 rounded-lg border border-foreground/20 text-muted-foreground hover:text-foreground hover:border-foreground/35 hover:bg-foreground/5 transition-all"
        title="Search targets"
      >
        <Search className="w-3.5 h-3.5" />
      </button>
    )
  }

  return (
    <div className="relative">
      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/45 pointer-events-none" />
      <input
        ref={inputRef}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={handleBlur}
        placeholder="Search targets…"
        className="pl-8 pr-7 py-1 w-48 h-7 bg-foreground/5 border border-foreground/20 rounded-lg text-xs focus:outline-none focus:ring-1 focus:ring-primary/40 focus:border-primary/30 text-foreground placeholder:text-muted-foreground/40 transition-all"
      />
      {value && (
        <button
          onMouseDown={(e) => { e.preventDefault(); onChange('') }}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-muted-foreground transition-colors"
        >
          <X className="w-3 h-3" />
        </button>
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
  const moduleFilter: ModuleFilter = (['all', 'web', 'network', 'sast'] as const).includes(rawModule as ModuleFilter)
    ? rawModule as ModuleFilter : 'all'
  const typeFilter: TypeFilter = rawType === 'cves' ? 'cves' : 'findings'

  // Raw Firestore state
  const [webFindings,  setWebFindings]  = useState<FirestoreFinding[]>([])
  const [netFindings,  setNetFindings]  = useState<FirestoreNetworkFinding[]>([])
  const [sastFindings, setSastFindings] = useState<FirestoreSastFinding[]>([])
  const [webCves,      setWebCves]      = useState<FirestoreCve[]>([])
  const [netCves,      setNetCves]      = useState<FirestoreNetworkCve[]>([])

  // SLA state
  const [slaPolicy,   setSlaPolicy]   = useState<SlaPolicy>(DEFAULT_SLA)
  const [dashTracking,setDashTracking]= useState<Record<string, FindingTracking>>({})

  // Filter state
  const [search,       setSearch]       = useState('')
  const [sevFilter,    setSevFilter]    = useState<string | null>(null)
  const [slaFilter,    setSlaFilter]    = useState<SlaFilter>('all')
  const [statusFilter, setStatusFilter] = useState<string | null>(null)

  // Modal state
  const [slaConfigOpen, setSlaConfigOpen] = useState(false)

  // Selected target for inline detail panel
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  function pushParams(updates: Partial<{ module: string; type: string }>) {
    const p = new URLSearchParams(searchParams.toString())
    Object.entries(updates).forEach(([k, v]) => p.set(k, v))
    router.replace(`/app/findings?${p.toString()}`, { scroll: false })
    setSearch('')
    setSevFilter(null)
    setSlaFilter('all')
    setStatusFilter(null)
    setSelectedKey(null)
  }

  useEffect(() => {
    if (!user) return
    const u1 = listenToFindings(user.uid, setWebFindings)
    const u2 = listenToNetworkFindings(user.uid, setNetFindings)
    const u3 = listenToSastFindings(user.uid, setSastFindings)
    const u4 = listenToCves(user.uid, setWebCves)
    const u5 = listenToNetworkCves(user.uid, setNetCves)
    const u6 = listenToSlaPolicy(user.uid, setSlaPolicy)
    const u7 = listenToFindingTracking(user.uid, setDashTracking)
    return () => { u1(); u2(); u3(); u4(); u5(); u6(); u7() }
  }, [user])

  // Normalize
  const allFindings = useMemo<NormalizedFinding[]>(() => [
    ...webFindings.map(normalizeFinding),
    ...netFindings.map(normalizeNetworkFinding),
    ...sastFindings.map(normalizeSastFinding),
  ], [webFindings, netFindings, sastFindings])

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

  // Filter cards by search + severity + SLA + workflow status
  const visibleFindingSummaries = useMemo(() => {
    let r = allFindingSummaries
    if (sevFilter) r = r.filter(s => cardSevCount(s, sevFilter) > 0)
    if (slaFilter !== 'all') {
      r = r.filter(s => {
        const counts = computeCardSlaCounts(s.findings, slaPolicy, dashTracking)
        if (slaFilter === 'within_sla') return counts.withinSla > 0
        if (slaFilter === 'due_soon')   return counts.dueSoon > 0
        if (slaFilter === 'breached')   return counts.breached > 0
        return true
      })
    }
    if (statusFilter) {
      r = r.filter(s =>
        s.findings.some(f => (dashTracking[f.id]?.status ?? 'open') === statusFilter)
      )
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      r = r.filter(s => s.target.toLowerCase().includes(q))
    }
    return r
  }, [allFindingSummaries, sevFilter, slaFilter, statusFilter, slaPolicy, dashTracking, search])

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

  // ── SLA dashboard metrics ──────────────────────────────────────────
  const slaStats = useMemo(() => {
    const now           = new Date()
    const startOfMonth  = new Date(now.getFullYear(), now.getMonth(), 1)
    let withinSla = 0, dueSoon = 0, breached = 0, fixedThisMonth = 0
    let totalResMs = 0, resolvedCount = 0

    for (const f of moduleFindings) {
      const t = dashTracking[f.id]
      const status = t?.status ?? 'open'

      if (status === 'fixed') {
        const fixEv = t.timeline.find(e => e.action === 'marked_fixed')
        const fixedAt = new Date(fixEv?.createdAt ?? t.updatedAt)
        if (fixedAt >= startOfMonth) fixedThisMonth++
        const discoveredAt = new Date(f.createdAt)
        const resMs = fixedAt.getTime() - discoveredAt.getTime()
        if (resMs > 0) { totalResMs += resMs; resolvedCount++ }
        continue
      }
      if (status === 'false_positive' || status === 'not_applicable') continue

      const { status: s } = computeSlaStatus(f.severity, f.createdAt, slaPolicy, false)
      if (s === 'within_sla') withinSla++
      else if (s === 'due_soon') dueSoon++
      else if (s === 'breached') breached++
    }

    const avgDays = resolvedCount > 0
      ? Math.round(totalResMs / resolvedCount / 86_400_000)
      : null

    return {
      open: withinSla + dueSoon + breached,
      withinSla, dueSoon, breached, fixedThisMonth, avgDays,
    }
  }, [moduleFindings, dashTracking, slaPolicy])

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
    <div className="p-6 space-y-4">

      {/* ── Header row ─────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-xl font-bold text-foreground tracking-tight">Vulnerability Management</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {cardCount === totalTargets
              ? `${totalTargets} target${totalTargets !== 1 ? 's' : ''}`
              : `${cardCount} of ${totalTargets} targets`}
            {moduleFilter !== 'all' && (
              <span className="ml-1.5 text-muted-foreground/40">
                · {moduleFilter === 'web' ? 'Web' : moduleFilter === 'network' ? 'Network' : 'SAST'}
              </span>
            )}
          </p>
        </div>

        {/* Compact SLA strip — findings view only */}
        {typeFilter === 'findings' && (
          <div className="flex items-stretch border border-foreground/8 rounded-xl bg-card overflow-hidden divide-x divide-foreground/8 shrink-0">
            {([
              { key: 'all'        as const, label: 'Open',       value: slaStats.open,      dotCls: 'bg-foreground/35', numCls: 'text-foreground',  pulse: false               },
              { key: 'within_sla' as const, label: 'Within SLA', value: slaStats.withinSla, dotCls: 'bg-green-400',     numCls: 'text-green-400',   pulse: false               },
              { key: 'due_soon'   as const, label: 'Due Soon',   value: slaStats.dueSoon,   dotCls: 'bg-orange-400',    numCls: 'text-orange-400',  pulse: false               },
              { key: 'breached'   as const, label: 'Breached',   value: slaStats.breached,  dotCls: 'bg-red-400',       numCls: 'text-red-400',     pulse: slaStats.breached > 0 },
            ] as const).map(({ key, label, value, dotCls, numCls, pulse }) => {
              const isFilter  = key !== 'all'
              const isActive  = isFilter && slaFilter === key
              return (
                <button
                  key={key}
                  disabled={!isFilter}
                  onClick={() => isFilter && setSlaFilter(slaFilter === key ? 'all' : key)}
                  className={`flex flex-col items-start px-4 py-2.5 min-w-[76px] transition-colors ${
                    !isFilter   ? 'cursor-default' :
                    isActive    ? 'bg-foreground/[0.05]' :
                    'hover:bg-foreground/[0.03] cursor-pointer'
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotCls} ${pulse ? 'animate-pulse' : ''}`} />
                    <span className="text-[10px] font-medium text-muted-foreground/55 whitespace-nowrap">{label}</span>
                  </div>
                  <span className={`text-xl font-bold tabular-nums leading-none ${numCls}`}>{value}</span>
                </button>
              )
            })}
          </div>
        )}

        {/* Compact CVE stats strip — CVE view only */}
        {typeFilter === 'cves' && (
          <div className="flex items-stretch border border-foreground/8 rounded-xl bg-card overflow-hidden divide-x divide-foreground/8 shrink-0">
            {stats.map((s) => (
              <div key={s.label} className="flex flex-col items-start px-4 py-2.5 min-w-[64px]">
                <span className="text-[10px] font-medium text-muted-foreground/55 whitespace-nowrap mb-1">{s.label}</span>
                <span className={`text-xl font-bold tabular-nums leading-none ${s.cls}`}>{s.value}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Compact toolbar ─────────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">

        {/* Module tabs */}
        <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-lg border border-foreground/8">
          {MODULE_FILTERS.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => pushParams({ module: value, type: typeFilter })}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
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
            className="px-2.5 py-1 rounded-md text-xs font-medium text-muted-foreground/25 cursor-not-allowed"
          >
            Cloud
          </button>
        </div>


        <div className="h-4 w-px bg-foreground/10" />

        {/* Type tabs */}
        <div className="flex items-center gap-0.5 p-0.5 bg-foreground/5 rounded-lg border border-foreground/8">
          <button
            onClick={() => pushParams({ module: moduleFilter, type: 'findings' })}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              typeFilter === 'findings'
                ? 'bg-card text-foreground shadow-sm border border-foreground/12'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <AlertTriangle className="w-3 h-3" /> Findings
          </button>
          <button
            onClick={() => pushParams({ module: moduleFilter, type: 'cves' })}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              typeFilter === 'cves'
                ? 'bg-card text-foreground shadow-sm border border-foreground/12'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <Bug className="w-3 h-3" /> CVE Intel
          </button>
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Active filter badges */}
        {sevFilter && (
          <span className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-md border ${SEV_BADGE[sevFilter] ?? 'border-foreground/20 text-muted-foreground'}`}>
            <span className="capitalize">{sevFilter.toLowerCase()}</span>
            <button onClick={() => setSevFilter(null)} className="hover:opacity-70 ml-0.5">
              <X className="w-2.5 h-2.5" />
            </button>
          </span>
        )}
        {slaFilter !== 'all' && (
          <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-md border border-foreground/20 text-muted-foreground">
            {slaFilter === 'within_sla' ? 'Within SLA' : slaFilter === 'due_soon' ? 'Due Soon' : 'Breached'}
            <button onClick={() => setSlaFilter('all')} className="hover:opacity-70 ml-0.5">
              <X className="w-2.5 h-2.5" />
            </button>
          </span>
        )}
        {statusFilter && (
          <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-md border border-foreground/20 text-muted-foreground">
            {STATUS_CONFIG[statusFilter as FindingStatus]?.label ?? statusFilter}
            <button onClick={() => setStatusFilter(null)} className="hover:opacity-70 ml-0.5">
              <X className="w-2.5 h-2.5" />
            </button>
          </span>
        )}

        {/* Filter popover */}
        <FilterPopover
          sevFilter={sevFilter}
          onSevFilter={setSevFilter}
          slaFilter={slaFilter}
          onSlaFilter={setSlaFilter}
          statusFilter={statusFilter}
          onStatusFilter={setStatusFilter}
          sevKeys={sevKeys}
          typeFilter={typeFilter}
        />

        {/* Expandable search */}
        <ExpandableSearch value={search} onChange={setSearch} />

        {/* SLA Config button — findings only */}
        {typeFilter === 'findings' && (
          <button
            onClick={() => setSlaConfigOpen(true)}
            className="flex items-center gap-1.5 h-7 px-2.5 rounded-lg border border-foreground/20 text-xs font-medium text-muted-foreground hover:text-foreground hover:border-foreground/35 hover:bg-foreground/5 transition-all"
          >
            <CalendarClock className="w-3.5 h-3.5" />
            SLA
          </button>
        )}
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
                slaPolicy={slaPolicy}
                slaTracking={dashTracking}
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
            slaPolicy={slaPolicy}
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

      {/* ── SLA Config Modal ────────────────────────────────────────── */}
      {slaConfigOpen && user && (
        <SlaConfigModal
          policy={slaPolicy}
          uid={user.uid}
          onClose={() => setSlaConfigOpen(false)}
        />
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
