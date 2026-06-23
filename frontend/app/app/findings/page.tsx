'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Search, ShieldAlert, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { listenToFindings, type FirestoreFinding } from '@/lib/firestore-findings'
import { useAuth } from '@/context/auth-context'

interface FindingGroup {
  scanId: string
  target: string
  totalFindings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  unknown: number
  latestAt: string
}

const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const

function buildGroups(findings: FirestoreFinding[]): FindingGroup[] {
  const map = new Map<string, FindingGroup>()

  for (const f of findings) {
    if (!map.has(f.scanId)) {
      map.set(f.scanId, {
        scanId: f.scanId,
        target: f.target,
        totalFindings: 0,
        critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0,
        latestAt: f.createdAt,
      })
    }
    const g = map.get(f.scanId)!
    g.totalFindings++
    const sev = SEV_KEYS.includes(f.severity as typeof SEV_KEYS[number]) ? f.severity as typeof SEV_KEYS[number] : 'unknown'
    g[sev]++
    if (f.createdAt > g.latestAt) g.latestAt = f.createdAt
  }

  return Array.from(map.values()).sort(
    (a, b) => new Date(b.latestAt).getTime() - new Date(a.latestAt).getTime(),
  )
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

const SEV_PILLS: { key: typeof SEV_KEYS[number]; label: string; cls: string }[] = [
  { key: 'critical', label: 'Critical', cls: 'bg-red-500/10 text-red-500 border-red-500/20' },
  { key: 'high',     label: 'High',     cls: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
  { key: 'medium',   label: 'Medium',   cls: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' },
  { key: 'low',      label: 'Low',      cls: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  { key: 'info',     label: 'Info',     cls: 'bg-gray-500/10 text-gray-400 border-gray-500/20' },
]

export default function FindingsPage() {
  const router = useRouter()
  const { user } = useAuth()
  const [findings, setFindings] = useState<FirestoreFinding[]>([])
  const [search, setSearch] = useState('')

  // Realtime listener on users/{uid}/findings — independent of scan page state
  useEffect(() => {
    if (!user) return
    return listenToFindings(user.uid, setFindings)
  }, [user])

  const groups = useMemo(() => buildGroups(findings), [findings])

  const filtered = useMemo(
    () =>
      groups.filter(
        (g) =>
          g.target.toLowerCase().includes(search.toLowerCase()) ||
          g.scanId.toLowerCase().includes(search.toLowerCase()),
      ),
    [groups, search],
  )

  const totals = useMemo(
    () =>
      findings.reduce(
        (acc, f) => {
          acc.total++
          const k = SEV_KEYS.includes(f.severity as typeof SEV_KEYS[number]) ? f.severity : 'unknown'
          ;(acc as Record<string, number>)[k] = ((acc as Record<string, number>)[k] ?? 0) + 1
          return acc
        },
        { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 } as Record<string, number>,
      ),
    [findings],
  )

  const statCards = [
    { label: 'Total',    value: totals.total,    cls: 'text-foreground' },
    { label: 'Critical', value: totals.critical,  cls: 'text-red-500' },
    { label: 'High',     value: totals.high,      cls: 'text-orange-500' },
    { label: 'Medium',   value: totals.medium,    cls: 'text-yellow-500' },
    { label: 'Low',      value: totals.low,       cls: 'text-blue-400' },
    { label: 'Info',     value: totals.info,      cls: 'text-gray-400' },
  ]

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Findings</h1>
          <p className="text-muted-foreground mt-1">
            {groups.length} scan group{groups.length !== 1 ? 's' : ''} · {findings.length} total findings
          </p>
        </div>
        <Button
          variant="outline"
          className="rounded-lg border-foreground/20 h-11 px-6"
          onClick={() => router.push('/app/scans')}
        >
          View Scans
        </Button>
      </div>

      {/* Severity stats */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-4">
        {statCards.map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-xs text-muted-foreground">{s.label}</CardTitle>
            </CardHeader>
            <CardContent className="pb-4 px-4">
              <div className={`text-2xl font-bold ${s.cls}`}>{s.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by target or scan ID…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg"
        />
      </div>

      {/* Grouped finding cards */}
      {filtered.length === 0 ? (
        <div className="text-center py-24 text-muted-foreground">
          {findings.length === 0 ? (
            <div className="flex flex-col items-center gap-3">
              <ShieldAlert className="w-10 h-10 text-muted-foreground/40" />
              <p className="text-sm font-medium">No findings yet</p>
              <p className="text-xs">Complete a scan to start seeing security findings here.</p>
              <Button
                variant="outline"
                size="sm"
                className="mt-2 border-foreground/20"
                onClick={() => router.push('/app/scans')}
              >
                Start a Scan
              </Button>
            </div>
          ) : (
            <p className="text-sm">No results match your search.</p>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map((group) => (
            <Card
              key={group.scanId}
              className="bg-card border-foreground/10 hover:border-foreground/25 transition-colors cursor-pointer"
              onClick={() => router.push(`/app/findings/${group.scanId}`)}
            >
              <CardContent className="pt-5 pb-5 px-5">
                {/* Target + scan ID */}
                <div className="flex items-start justify-between gap-3 mb-4">
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-foreground truncate">{group.target}</p>
                    <p className="text-xs text-muted-foreground font-mono mt-0.5 truncate">
                      {group.scanId}
                    </p>
                  </div>
                  <span className="text-xs px-2 py-0.5 rounded bg-foreground/5 text-muted-foreground border border-foreground/10 shrink-0">
                    {group.scanId.startsWith('scan_') ? 'DAST' : 'DAST'}
                  </span>
                </div>

                {/* Total count */}
                <div className="mb-4">
                  <span className="text-3xl font-bold text-foreground">{group.totalFindings}</span>
                  <span className="text-sm text-muted-foreground ml-1.5">findings</span>
                </div>

                {/* Severity pills */}
                <div className="flex flex-wrap gap-1.5">
                  {SEV_PILLS.filter((p) => group[p.key] > 0).map((p) => (
                    <span
                      key={p.key}
                      className={`text-xs font-semibold px-2.5 py-1 rounded border ${p.cls}`}
                    >
                      {group[p.key]} {p.label}
                    </span>
                  ))}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between mt-4 pt-4 border-t border-foreground/5">
                  <span className="text-xs text-muted-foreground">{formatDate(group.latestAt)}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 rounded-lg text-primary hover:bg-primary/10 gap-1"
                    onClick={(e) => {
                      e.stopPropagation()
                      router.push(`/app/findings/${group.scanId}`)
                    }}
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    View Findings
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
