'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, ExternalLink, Zap, ShieldCheck, ShieldAlert, Globe,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { listenToCvesByVulnId, type FirestoreCve } from '@/lib/firestore-cves'
import { useAuth } from '@/context/auth-context'

// ── Helpers ───────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  NONE:     'bg-gray-500/15 text-gray-400 border border-gray-500/30',
}

function cvssColor(score: number) {
  if (score >= 9.0) return 'text-red-400'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-400'
  return 'text-blue-400'
}

function cvssLabel(score: number) {
  if (score >= 9.0) return 'Critical'
  if (score >= 7.0) return 'High'
  if (score >= 4.0) return 'Medium'
  if (score > 0)    return 'Low'
  return 'None'
}

function formatDate(iso: string) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) }
  catch { return iso }
}

// ── Page ──────────────────────────────────────────────────────────────

export default function CveDetailPage() {
  const { cveId: encodedId } = useParams<{ cveId: string }>()
  const cveId = decodeURIComponent(encodedId)
  const router = useRouter()
  const { user } = useAuth()

  const [entries, setEntries] = useState<FirestoreCve[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!user) return
    setLoading(true)
    return listenToCvesByVulnId(user.uid, cveId, (cves) => {
      setEntries(cves)
      setLoading(false)
    })
  }, [user, cveId])

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
      </div>
    )
  }

  if (entries.length === 0) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-64 gap-3">
        <ShieldAlert className="w-8 h-8 text-muted-foreground opacity-40" />
        <p className="text-muted-foreground">CVE not found.</p>
        <Button variant="ghost" size="sm" onClick={() => router.push('/app/cves')}>
          ← Back to CVEs
        </Button>
      </div>
    )
  }

  // All entries share the same CVE metadata — use the first one for display
  const primary   = entries[0]
  const highScore = Math.max(...entries.map((e) => e.cvssScore))
  const highSev   = entries.find((e) => e.cvssScore === highScore) ?? primary

  // Deduplicate references across all entries
  const allRefs = [...new Set(entries.flatMap((e) => e.references))]
  const hasExploit = entries.some((e) => e.exploitAvailable)

  return (
    <div className="p-8 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost" size="icon"
            onClick={() => router.push('/app/cves')}
            className="rounded-lg"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold font-mono text-foreground">{cveId}</h1>
              <span className={`text-xs font-medium px-2.5 py-1 rounded ${SEVERITY_BADGE[highSev.severity] ?? SEVERITY_BADGE.NONE}`}>
                {highSev.severity}
              </span>
              {hasExploit && (
                <span className="flex items-center gap-1 text-xs text-red-400 px-2 py-1 rounded bg-red-500/10 border border-red-500/20">
                  <Zap className="w-3 h-3" />
                  Exploit Available
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {primary.technology} {primary.version} · Published {formatDate(primary.published)}
            </p>
          </div>
        </div>

        {/* NVD Link */}
        <a
          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          <Button variant="outline" size="sm" className="gap-1.5 rounded-lg border-foreground/20">
            <ExternalLink className="w-3.5 h-3.5" />
            NVD
          </Button>
        </a>
      </div>

      {/* CVSS Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs text-muted-foreground">CVSS Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold ${cvssColor(highScore)}`}>
              {highScore.toFixed(1)}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">{cvssLabel(highScore)}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs text-muted-foreground">Technology</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-sm font-semibold text-foreground">{primary.technology}</div>
            <div className="text-xs font-mono text-muted-foreground mt-0.5">{primary.version}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs text-muted-foreground">Affected Assets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground">{entries.length}</div>
          </CardContent>
        </Card>

        <Card className={`border-foreground/10 ${hasExploit ? 'bg-red-500/5 border-red-500/20' : 'bg-card'}`}>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs text-muted-foreground">Exploit</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`flex items-center gap-1.5 text-sm font-semibold ${hasExploit ? 'text-red-400' : 'text-green-500'}`}>
              {hasExploit ? (
                <><ShieldAlert className="w-4 h-4" /> Available</>
              ) : (
                <><ShieldCheck className="w-4 h-4" /> Not Known</>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Description */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base">Description</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-foreground leading-relaxed">
            {primary.description || 'No description available.'}
          </p>
        </CardContent>
      </Card>

      {/* Affected Assets */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="text-base">Affected Assets ({entries.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-foreground/10">
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Asset URL</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Technology</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Version</th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">CVSS</th>
                <th className="py-3 px-4 text-xs font-semibold text-muted-foreground text-right">Open</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="text-xs font-mono text-foreground truncate max-w-[200px] block">
                        {entry.assetUrl}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-sm text-foreground">{entry.technology}</td>
                  <td className="py-3 px-4 text-xs font-mono text-muted-foreground">{entry.version}</td>
                  <td className="py-3 px-4">
                    <span className={`text-sm font-bold ${cvssColor(entry.cvssScore)}`}>
                      {entry.cvssScore.toFixed(1)}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex justify-end">
                      <a href={entry.assetUrl} target="_blank" rel="noopener noreferrer">
                        <Button variant="ghost" size="sm" className="h-7 rounded-lg text-primary hover:bg-primary/10 text-xs gap-1">
                          <ExternalLink className="w-3 h-3" />
                        </Button>
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* References */}
      {allRefs.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle className="text-base">References ({allRefs.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {allRefs.map((url, i) => {
                const isExploit = ['exploit', 'poc', 'metasploit', 'exploitdb'].some(
                  (t) => url.toLowerCase().includes(t),
                )
                return (
                  <a
                    key={i}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-primary hover:underline group"
                  >
                    {isExploit
                      ? <Zap className="w-3 h-3 text-red-400 shrink-0" />
                      : <ExternalLink className="w-3 h-3 shrink-0 opacity-50 group-hover:opacity-100" />}
                    <span className="truncate">{url}</span>
                  </a>
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
