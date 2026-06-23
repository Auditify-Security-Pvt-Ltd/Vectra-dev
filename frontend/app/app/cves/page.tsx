'use client'

import { useEffect, useState, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  ShieldAlert, Search, Filter, Zap, ExternalLink,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { listenToCves, type FirestoreCve } from '@/lib/firestore-cves'
import { useAuth } from '@/context/auth-context'

// ── Helpers ───────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  NONE:     'bg-gray-500/15 text-gray-400 border border-gray-500/30',
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
function sevOrd(s: string) { return SEVERITY_ORDER.indexOf(s.toUpperCase()) }

function formatDate(iso: string) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString() } catch { return iso }
}

function cvssColor(score: number) {
  if (score >= 9.0) return 'text-red-400'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-400'
  return 'text-blue-400'
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

// ── Page ──────────────────────────────────────────────────────────────

export default function CvesPage() {
  const { user } = useAuth()
  const router   = useRouter()
  const [cves, setCves] = useState<FirestoreCve[]>([])
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)
  const [techFilter, setTechFilter]         = useState<string | null>(null)

  useEffect(() => {
    if (!user) return
    return listenToCves(user.uid, setCves)
  }, [user])

  const totalCves     = cves.length
  const criticalCount = cves.filter((c) => c.severity === 'CRITICAL').length
  const highCount     = cves.filter((c) => c.severity === 'HIGH').length
  const mediumCount   = cves.filter((c) => c.severity === 'MEDIUM').length
  const lowCount      = cves.filter((c) => c.severity === 'LOW').length
  const exploitCount  = cves.filter((c) => c.exploitAvailable).length

  const allTechs = useMemo(
    () => [...new Set(cves.map((c) => c.technology))].sort(),
    [cves],
  )

  const filtered = useMemo(() => {
    let r = [...cves]
    if (severityFilter) r = r.filter((c) => c.severity === severityFilter)
    if (techFilter)     r = r.filter((c) => c.technology === techFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      r = r.filter(
        (c) =>
          c.cveId.toLowerCase().includes(q) ||
          c.technology.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.assetUrl.toLowerCase().includes(q),
      )
    }
    return r.sort((a, b) => sevOrd(a.severity) - sevOrd(b.severity) || b.cvssScore - a.cvssScore)
  }, [cves, severityFilter, techFilter, search])

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">CVE Intelligence</h1>
          <p className="text-muted-foreground mt-1">
            Known vulnerabilities correlated from discovered asset technologies
          </p>
        </div>
        {exploitCount > 0 && (
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30">
            <Zap className="w-4 h-4 text-red-400" />
            <span className="text-sm font-semibold text-red-400">{exploitCount} exploitable</span>
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Total CVEs', value: totalCves,     color: 'text-foreground', bg: '' },
          { label: 'Critical',   value: criticalCount, color: 'text-red-400',    bg: 'bg-red-500/5'    },
          { label: 'High',       value: highCount,     color: 'text-orange-400', bg: 'bg-orange-500/5' },
          { label: 'Medium',     value: mediumCount,   color: 'text-yellow-400', bg: 'bg-yellow-500/5' },
          { label: 'Low',        value: lowCount,      color: 'text-blue-400',   bg: 'bg-blue-500/5'   },
        ].map((s) => (
          <Card key={s.label} className={`border-foreground/10 ${s.bg}`}>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground">{s.label}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-muted-foreground" />
          <Button
            variant="ghost" size="sm"
            className={`h-7 rounded-lg text-xs ${!severityFilter ? 'bg-primary/15 text-primary' : 'text-muted-foreground'}`}
            onClick={() => setSeverityFilter(null)}
          >
            All
          </Button>
          {SEVERITIES.map((sev) => (
            <Button
              key={sev} variant="ghost" size="sm"
              className={`h-7 rounded-lg text-xs ${severityFilter === sev ? SEVERITY_BADGE[sev] : 'text-muted-foreground hover:bg-foreground/5'}`}
              onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
            >
              {sev[0] + sev.slice(1).toLowerCase()}
            </Button>
          ))}
        </div>

        {allTechs.length > 0 && (
          <select
            className="h-7 text-xs rounded-lg bg-foreground/5 border border-foreground/10 text-muted-foreground px-2 cursor-pointer"
            value={techFilter ?? ''}
            onChange={(e) => setTechFilter(e.target.value || null)}
          >
            <option value="">All Technologies</option>
            {allTechs.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        )}

        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search CVE ID, technology, asset…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 h-7 text-xs bg-foreground/5 border-foreground/20 rounded-lg"
          />
        </div>
      </div>

      {/* Table */}
      <Card className="bg-card border-foreground/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">CVE Findings</CardTitle>
            <span className="text-xs text-muted-foreground">
              {filtered.length} result{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              {totalCves === 0 ? (
                <div className="space-y-2">
                  <ShieldAlert className="w-8 h-8 mx-auto opacity-30" />
                  <p className="text-sm">No CVEs found yet.</p>
                  <p className="text-xs">
                    Complete an asset discovery — CVE correlation runs automatically for live assets with detected technologies.
                  </p>
                </div>
              ) : (
                <p className="text-sm">No CVEs match the current filters.</p>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">CVE ID</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Technology</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Version</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Severity</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">CVSS</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Exploit</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Asset</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Published</th>
                    <th className="py-3 px-4 text-xs font-semibold text-muted-foreground text-right">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((cve) => (
                    <tr
                      key={cve.id}
                      className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors cursor-pointer"
                      onClick={() => router.push(`/app/cves/${encodeURIComponent(cve.cveId)}`)}
                    >
                      <td className="py-3 px-4">
                        <span className="text-xs font-mono text-primary font-semibold">{cve.cveId}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-sm text-foreground">{cve.technology}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs font-mono text-muted-foreground">{cve.version}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded ${SEVERITY_BADGE[cve.severity] ?? SEVERITY_BADGE.NONE}`}>
                          {cve.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`text-sm font-bold ${cvssColor(cve.cvssScore)}`}>
                          {cve.cvssScore.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {cve.exploitAvailable ? (
                          <span className="flex items-center gap-1 text-xs text-red-400">
                            <Zap className="w-3 h-3" />Yes
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 max-w-[160px]">
                        <span className="text-xs font-mono text-muted-foreground truncate block">{cve.assetUrl}</span>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(cve.published)}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex justify-end">
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 rounded-lg text-primary hover:bg-primary/10 text-xs gap-1"
                            onClick={(e) => {
                              e.stopPropagation()
                              router.push(`/app/cves/${encodeURIComponent(cve.cveId)}`)
                            }}
                          >
                            View <ExternalLink className="w-3 h-3" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
