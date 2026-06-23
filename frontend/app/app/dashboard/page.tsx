'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { BarChart3, TrendingUp, AlertTriangle, Clock, Plus, CheckCircle2, XCircle, Ban, Timer, ShieldAlert, Zap } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer, LineChart, Line,
} from 'recharts'
import { NewScanModal } from '@/components/app/new-scan-modal'
import { listenToScans, ACTIVE_STATUSES, type FirestoreScan } from '@/lib/firestore-scans'
import { listenToFindings, type FirestoreFinding } from '@/lib/firestore-findings'
import { listenToAssets, type FirestoreAsset } from '@/lib/firestore-assets'
import { listenToCves, type FirestoreCve } from '@/lib/firestore-cves'
import { useAuth } from '@/context/auth-context'

const riskTrend = [
  { date: '1 Jan', critical: 180, high: 240, medium: 180 },
  { date: '8 Jan', critical: 165, high: 220, medium: 160 },
  { date: '15 Jan', critical: 150, high: 200, medium: 140 },
  { date: '22 Jan', critical: 143, high: 190, medium: 130 },
  { date: '29 Jan', critical: 135, high: 175, medium: 120 },
]

function buildScanActivity(scans: FirestoreScan[]) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
  const buckets: Record<string, { completed: number; failed: number; pending: number }> = {}
  const today = new Date()
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today)
    d.setDate(d.getDate() - i)
    buckets[days[d.getDay()]] = { completed: 0, failed: 0, pending: 0 }
  }
  scans.forEach((s) => {
    const label = days[new Date(s.createdAt).getDay()]
    if (!buckets[label]) return
    if (s.status === 'completed') buckets[label].completed++
    else if (s.status === 'failed') buckets[label].failed++
    else buckets[label].pending++
  })
  return Object.entries(buckets).map(([date, v]) => ({ date, ...v }))
}

function formatTime(iso: string) {
  const ms = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function DashboardPage() {
  const router = useRouter()
  const { user } = useAuth()
  const [scans, setScans]       = useState<FirestoreScan[]>([])
  const [findings, setFindings] = useState<FirestoreFinding[]>([])
  const [assets, setAssets]     = useState<FirestoreAsset[]>([])
  const [cves, setCves]         = useState<FirestoreCve[]>([])
  const [modalOpen, setModalOpen] = useState(false)

  useEffect(() => {
    if (!user) return
    return listenToScans(user.uid, setScans)
  }, [user])

  useEffect(() => {
    if (!user) return
    return listenToFindings(user.uid, setFindings)
  }, [user])

  useEffect(() => {
    if (!user) return
    return listenToAssets(user.uid, setAssets)
  }, [user])

  useEffect(() => {
    if (!user) return
    return listenToCves(user.uid, setCves)
  }, [user])

  const totalScans      = scans.length
  const queuedScans     = scans.filter((s) => s.status === 'queued').length
  const runningScans    = scans.filter((s) => ACTIVE_STATUSES.has(s.status) && s.status !== 'queued').length
  const completedScans  = scans.filter((s) => s.status === 'completed').length
  const failedScans     = scans.filter((s) => s.status === 'failed').length
  const cancelledScans  = scans.filter((s) => s.status === 'cancelled').length
  const totalFindings   = findings.length
  const criticalFindings = findings.filter((f) => f.severity === 'critical').length
  const highFindings     = findings.filter((f) => f.severity === 'high').length
  const mediumFindings   = findings.filter((f) => f.severity === 'medium').length
  const lowFindings      = findings.filter((f) => f.severity === 'low').length
  const infoFindings     = findings.filter((f) => f.severity === 'info').length

  const totalAssets    = assets.length
  const liveAssets     = assets.filter((a) => a.alive).length
  const today          = new Date().toDateString()
  const assetsToday    = assets.filter((a) => new Date(a.createdAt).toDateString() === today).length

  const totalCves      = cves.length
  const criticalCves   = cves.filter((c) => c.severity === 'CRITICAL').length
  const highCves       = cves.filter((c) => c.severity === 'HIGH').length
  const exploitableCves = cves.filter((c) => c.exploitAvailable).length

  const topTechnologies = (() => {
    const counts: Record<string, number> = {}
    for (const asset of assets) {
      for (const raw of asset.technologies ?? []) {
        const name = raw.split(':')[0].trim()
        if (name) counts[name] = (counts[name] ?? 0) + 1
      }
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
  })()

  const dashStats = [
    {
      title: 'Total Scans',
      value: totalScans.toString(),
      sub: `${totalFindings} findings`,
      icon: BarChart3,
      color: 'text-foreground',
      bg: 'bg-primary/10',
      iconColor: 'text-primary',
    },
    {
      title: 'Queued',
      value: queuedScans.toString(),
      sub: queuedScans === 1 ? 'waiting' : 'waiting',
      icon: Timer,
      color: 'text-yellow-500',
      bg: 'bg-yellow-500/10',
      iconColor: 'text-yellow-500',
    },
    {
      title: 'Running',
      value: runningScans.toString(),
      sub: runningScans > 0 ? 'in progress' : 'idle',
      icon: Clock,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      iconColor: 'text-blue-400',
    },
    {
      title: 'Completed',
      value: completedScans.toString(),
      sub: `${criticalFindings} critical`,
      icon: CheckCircle2,
      color: 'text-green-500',
      bg: 'bg-green-500/10',
      iconColor: 'text-green-500',
    },
    {
      title: 'Failed',
      value: failedScans.toString(),
      sub: 'scan errors',
      icon: XCircle,
      color: 'text-red-500',
      bg: 'bg-red-500/10',
      iconColor: 'text-red-500',
    },
    {
      title: 'Cancelled',
      value: cancelledScans.toString(),
      sub: 'by user',
      icon: Ban,
      color: 'text-gray-400',
      bg: 'bg-gray-500/10',
      iconColor: 'text-gray-400',
    },
  ]

  const scanActivity = buildScanActivity(scans)
  const recentScans = scans.slice(0, 4)

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground mt-1">Welcome back, {user?.name || 'User'}!</p>
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6 gap-2"
          onClick={() => setModalOpen(true)}
        >
          <Plus className="w-4 h-4" />
          Start New Scan
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {dashStats.map((stat) => {
          const Icon = stat.icon
          return (
            <Card
              key={stat.title}
              className="bg-card border-foreground/10 hover:border-foreground/20 transition-colors"
            >
              <CardHeader className="pb-2 pt-4 px-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-xs font-medium text-muted-foreground">
                    {stat.title}
                  </CardTitle>
                  <div className={`p-1.5 rounded-lg ${stat.bg}`}>
                    <Icon className={`w-3.5 h-3.5 ${stat.iconColor}`} />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{stat.sub}</div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Findings severity breakdown */}
      {totalFindings > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Findings by Severity</CardTitle>
              <span className="text-sm text-muted-foreground">{totalFindings} total</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-5 gap-3">
              {[
                { label: 'Critical', count: criticalFindings, cls: 'text-red-500', bar: 'bg-red-500' },
                { label: 'High', count: highFindings, cls: 'text-orange-500', bar: 'bg-orange-500' },
                { label: 'Medium', count: mediumFindings, cls: 'text-yellow-500', bar: 'bg-yellow-500' },
                { label: 'Low', count: lowFindings, cls: 'text-blue-400', bar: 'bg-blue-400' },
                { label: 'Info', count: infoFindings, cls: 'text-gray-400', bar: 'bg-gray-500' },
              ].map((s) => (
                <div key={s.label} className="flex flex-col gap-2">
                  <div className="flex justify-between items-end">
                    <span className="text-xs text-muted-foreground">{s.label}</span>
                    <span className={`text-sm font-bold ${s.cls}`}>{s.count}</span>
                  </div>
                  <div className="h-1.5 bg-foreground/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${s.bar}`}
                      style={{ width: totalFindings > 0 ? `${Math.round((s.count / totalFindings) * 100)}%` : '0%' }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Asset metrics */}
      {totalAssets > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Attack Surface</CardTitle>
              <span className="text-sm text-muted-foreground">{totalAssets} total assets</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Total Assets',     value: totalAssets,  cls: 'text-foreground'  },
                { label: 'Live Hosts',       value: liveAssets,   cls: 'text-green-500'   },
                { label: 'Found Today',      value: assetsToday,  cls: 'text-blue-400'    },
              ].map((s) => (
                <div key={s.label} className="space-y-1">
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                  <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Technologies */}
      {topTechnologies.length > 0 && (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Top Technologies</CardTitle>
              <span className="text-sm text-muted-foreground">across {liveAssets} live assets</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {topTechnologies.map(([name, count]) => {
                const pct = liveAssets > 0 ? Math.round((count / liveAssets) * 100) : 0
                return (
                  <div key={name} className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs text-foreground font-medium truncate">{name}</span>
                      <span className="text-xs text-primary font-semibold shrink-0">{count}</span>
                    </div>
                    <div className="h-1.5 bg-foreground/10 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${Math.min(pct, 100)}%` }}
                      />
                    </div>
                    <span className="text-xs text-muted-foreground">{pct}% of live</span>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* CVE Intelligence Summary */}
      {totalCves > 0 && (
        <Card className="bg-card border-foreground/10 cursor-pointer hover:border-foreground/20 transition-colors" onClick={() => router.push('/app/cves')}>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                <CardTitle className="text-base">CVE Intelligence</CardTitle>
              </div>
              <span className="text-xs text-primary hover:underline">View all →</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { label: 'Total CVEs',    value: totalCves,       cls: 'text-foreground', icon: null },
                { label: 'Critical',      value: criticalCves,    cls: 'text-red-400',    icon: null },
                { label: 'High',          value: highCves,        cls: 'text-orange-400', icon: null },
                { label: 'Exploitable',   value: exploitableCves, cls: 'text-red-400',    icon: Zap  },
              ].map((s) => (
                <div key={s.label} className="space-y-1">
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                  <p className={`text-2xl font-bold flex items-center gap-1 ${s.cls}`}>
                    {s.icon && <s.icon className="w-4 h-4" />}
                    {s.value}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Scan Activity</CardTitle>
            <CardDescription>Last 7 days of scan operations</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scanActivity}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="date" stroke="rgba(255,255,255,0.5)" />
                <YAxis stroke="rgba(255,255,255,0.5)" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
                <Bar dataKey="completed" fill="#8b5cf6" name="Completed" />
                <Bar dataKey="failed" fill="#ef4444" name="Failed" />
                <Bar dataKey="pending" fill="#f97316" name="Pending" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Risk Trend</CardTitle>
            <CardDescription>Security findings over time</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="date" stroke="rgba(255,255,255,0.5)" />
                <YAxis stroke="rgba(255,255,255,0.5)" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} name="Critical" />
                <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} name="High" />
                <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} name="Medium" />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>Latest security assessment activities</CardDescription>
            </div>
            <Button
              variant="outline"
              className="h-9 rounded-lg border-foreground/20"
              onClick={() => router.push('/app/scans')}
            >
              View All
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {recentScans.length === 0 ? (
            <div className="text-center py-10 text-muted-foreground">
              <p className="text-sm">No scans yet — click &ldquo;Start New Scan&rdquo; above.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {recentScans.map((scan) => (
                <div
                  key={scan.scanId}
                  className="flex items-center justify-between p-4 border border-foreground/5 rounded-lg hover:bg-foreground/5 transition-colors cursor-pointer"
                  onClick={() => router.push(`/app/scans/${scan.scanId}`)}
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-foreground truncate">{scan.target}</p>
                    <p className="text-sm text-muted-foreground mt-0.5">
                      {formatTime(scan.createdAt)}
                    </p>
                  </div>
                  <div className="flex items-center gap-6 ml-4">
                    <div className="text-right">
                      <p className="text-sm font-medium text-foreground">
                        {scan.totalFindings} findings
                      </p>
                      <p
                        className={`text-xs capitalize ${
                          scan.status === 'completed'
                            ? 'text-green-500'
                            : scan.status === 'failed'
                            ? 'text-red-500'
                            : ACTIVE_STATUSES.has(scan.status)
                            ? 'text-blue-500'
                            : 'text-muted-foreground'
                        }`}
                      >
                        {scan.status}
                      </p>
                    </div>
                    <Button variant="ghost" className="h-8 w-8 rounded-lg" size="icon">
                      →
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <NewScanModal open={modalOpen} onOpenChange={setModalOpen} />
    </div>
  )
}
