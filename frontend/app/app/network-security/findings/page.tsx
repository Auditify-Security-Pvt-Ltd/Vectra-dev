'use client'

import { useEffect, useState } from 'react'
import { AlertTriangle, Search, Wifi, ChevronDown, ChevronRight } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { useAuth } from '@/context/auth-context'
import { listenToNetworkFindings, type FirestoreNetworkFinding } from '@/lib/firestore-network-findings'

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info:     'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function FindingRow({ finding }: { finding: FirestoreNetworkFinding }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="border-b border-foreground/5 last:border-0">
      <div
        className="flex items-center gap-4 px-5 py-4 hover:bg-foreground/2 transition-colors cursor-pointer group"
        onClick={() => setExpanded(!expanded)}
      >
        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border shrink-0 ${SEV_BADGE[finding.severity] ?? SEV_BADGE.info}`}>
          {finding.severity.toUpperCase()}
        </span>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-foreground truncate">{finding.title}</p>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs font-mono text-muted-foreground">{finding.ip}</span>
            {finding.port && <span className="text-xs text-muted-foreground">:{finding.port}</span>}
            <span className="text-xs text-muted-foreground">{formatDate(finding.createdAt)}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground">{finding.source}</span>
          </div>
        </div>

        {expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground/40 shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground shrink-0" />}
      </div>

      {expanded && (
        <div className="px-5 pb-4 space-y-2 bg-foreground/1">
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
              <p className="text-[11px] text-muted-foreground mb-0.5">Template</p>
              <p className="text-xs font-mono text-foreground">{finding.template}</p>
            </div>
            {finding.matched_at && (
              <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
                <p className="text-[11px] text-muted-foreground mb-0.5">Matched At</p>
                <p className="text-xs font-mono text-foreground break-all">{finding.matched_at}</p>
              </div>
            )}
          </div>
          {finding.description && (
            <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
              <p className="text-[11px] text-muted-foreground mb-0.5">Description</p>
              <p className="text-xs text-foreground leading-relaxed">{finding.description}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export default function NetworkFindingsPage() {
  const { user }   = useAuth()
  const [findings, setFindings] = useState<FirestoreNetworkFinding[]>([])
  const [search,   setSearch]   = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)

  useEffect(() => {
    if (!user) return
    return listenToNetworkFindings(user.uid, setFindings)
  }, [user])

  const filtered = findings
    .filter((f) => !sevFilter || f.severity === sevFilter)
    .filter((f) =>
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.ip.includes(search) ||
      f.template.toLowerCase().includes(search.toLowerCase()),
    )

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]))

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      <div className="flex items-start gap-4">
        <div className="w-11 h-11 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center shrink-0">
          <AlertTriangle className="w-5 h-5 text-orange-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Network Findings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Vulnerabilities discovered via Nuclei across all network scans</p>
        </div>
      </div>

      {/* Severity counts */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setSevFilter(null)}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
            !sevFilter ? 'border-foreground/30 bg-foreground/8 text-foreground' : 'border-foreground/10 text-muted-foreground hover:border-foreground/20'
          }`}
        >
          All ({findings.length})
        </button>
        {SEVERITIES.map((s) => (
          counts[s] > 0 && (
            <button
              key={s}
              onClick={() => setSevFilter(sevFilter === s ? null : s)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                sevFilter === s ? `${SEV_BADGE[s]} font-bold` : 'border-foreground/10 text-muted-foreground hover:border-foreground/20'
              }`}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)} ({counts[s]})
            </button>
          )
        ))}
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by title, IP, or template…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-background border-foreground/15 h-10"
        />
      </div>

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="text-center py-16 space-y-3">
              <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
                <Wifi className="w-6 h-6 text-muted-foreground" />
              </div>
              <p className="text-sm text-muted-foreground">
                {search || sevFilter ? 'No findings match your filters' : 'No network findings yet — start a network scan'}
              </p>
            </div>
          ) : (
            <div>
              {filtered.map((f) => <FindingRow key={f.findingId} finding={f} />)}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
