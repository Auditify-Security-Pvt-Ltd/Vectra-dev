'use client'

import { useEffect, useState } from 'react'
import { Bug, Search, Wifi, ChevronDown, ChevronRight, ShieldAlert } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { useAuth } from '@/context/auth-context'
import { listenToNetworkCves, type FirestoreNetworkCve } from '@/lib/firestore-network-cves'

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info:     'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

function cvssColor(score: number) {
  if (score >= 9.0) return 'text-red-500'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-500'
  return 'text-blue-400'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function CveRow({ cve }: { cve: FirestoreNetworkCve }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="border-b border-foreground/5 last:border-0">
      <div
        className="flex items-center gap-4 px-5 py-4 hover:bg-foreground/2 transition-colors cursor-pointer group"
        onClick={() => setExpanded(!expanded)}
      >
        {/* CVSS Score */}
        <div className="w-12 text-center shrink-0">
          <p className={`text-base font-bold ${cvssColor(cve.cvssScore)}`}>{cve.cvssScore.toFixed(1)}</p>
          <p className="text-[9px] text-muted-foreground">CVSS</p>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-violet-400 font-mono">{cve.cveId}</span>
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${SEV_BADGE[cve.severity] ?? SEV_BADGE.info}`}>
              {cve.severity.toUpperCase()}
            </span>
            {cve.exploitAvailable && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-red-500/10 text-red-400 border-red-500/20">
                EXPLOIT AVAILABLE
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            <span className="text-xs text-foreground">{cve.technology} {cve.version}</span>
            <span className="text-xs font-mono text-muted-foreground">{cve.ip}:{cve.port}</span>
            <span className="text-xs text-muted-foreground">{formatDate(cve.createdAt)}</span>
          </div>
        </div>

        {expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground/40 shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground shrink-0" />}
      </div>

      {expanded && (
        <div className="px-5 pb-4 bg-foreground/1">
          <div className="p-3 rounded-lg bg-foreground/3 border border-foreground/8">
            <p className="text-[11px] text-muted-foreground mb-1">Description</p>
            <p className="text-xs text-foreground leading-relaxed">
              {cve.description || 'No description available.'}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

const SEVERITIES = ['critical', 'high', 'medium', 'low']

export default function NetworkCvesPage() {
  const { user }    = useAuth()
  const [cves,      setCves]      = useState<FirestoreNetworkCve[]>([])
  const [search,    setSearch]    = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)

  useEffect(() => {
    if (!user) return
    return listenToNetworkCves(user.uid, setCves)
  }, [user])

  const filtered = cves
    .filter((c) => !sevFilter || c.severity === sevFilter)
    .filter((c) =>
      c.cveId.toLowerCase().includes(search.toLowerCase()) ||
      c.technology.toLowerCase().includes(search.toLowerCase()) ||
      c.ip.includes(search),
    )

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, cves.filter((c) => c.severity === s).length]))
  const exploitCount = cves.filter((c) => c.exploitAvailable).length
  const avgCvss = cves.length ? (cves.reduce((n, c) => n + c.cvssScore, 0) / cves.length).toFixed(1) : '—'

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      <div className="flex items-start gap-4">
        <div className="w-11 h-11 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
          <Bug className="w-5 h-5 text-violet-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Network CVEs</h1>
          <p className="text-sm text-muted-foreground mt-0.5">CVE intelligence correlated against discovered services</p>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total CVEs',          value: cves.length,   cls: 'text-foreground'  },
          { label: 'Critical / High',     value: (counts.critical ?? 0) + (counts.high ?? 0), cls: 'text-red-400' },
          { label: 'Exploit Available',   value: exploitCount,  cls: 'text-orange-400'  },
          { label: 'Average CVSS',        value: avgCvss,       cls: 'text-violet-400'  },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Severity filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setSevFilter(null)}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
            !sevFilter ? 'border-foreground/30 bg-foreground/8 text-foreground' : 'border-foreground/10 text-muted-foreground hover:border-foreground/20'
          }`}
        >
          All ({cves.length})
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
          placeholder="Search by CVE ID, technology, or IP…"
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
                {search || sevFilter ? 'No CVEs match your filters' : 'No CVEs yet — start a network scan to correlate services'}
              </p>
            </div>
          ) : (
            <div>
              {filtered.map((c) => <CveRow key={c.id} cve={c} />)}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
