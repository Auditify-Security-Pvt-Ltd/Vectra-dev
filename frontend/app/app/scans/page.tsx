'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Search, Plus, StopCircle, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { NewScanModal } from '@/components/app/new-scan-modal'
import { listenToScans, updateFirestoreScan, createFirestoreScan, ACTIVE_STATUSES, type FirestoreScan } from '@/lib/firestore-scans'
import { cancelScan, restartScan } from '@/lib/api'
import { useAuth } from '@/context/auth-context'

const STATUS_BADGE: Record<string, string> = {
  // terminal
  completed:   'bg-green-500/10 text-green-500',
  failed:      'bg-red-500/10 text-red-500',
  cancelled:   'bg-gray-500/10 text-gray-400',
  // Quick Scan active
  queued:       'bg-yellow-500/10 text-yellow-500',
  initializing: 'bg-blue-500/10 text-blue-400',
  running:      'bg-blue-500/10 text-blue-400',
  processing:   'bg-purple-500/10 text-purple-400',
  saving:       'bg-teal-500/10 text-teal-400',
  // Full Scan pipeline
  discovering_assets:     'bg-violet-500/10 text-violet-400',
  validating_assets:      'bg-cyan-500/10 text-cyan-400',
  scanning_assets:        'bg-blue-500/10 text-blue-400',
  detecting_technologies: 'bg-orange-500/10 text-orange-400',
  cve_analysis:           'bg-red-500/10 text-red-400',
}

const STATUS_LABEL: Record<string, string> = {
  discovering_assets:     'Asset Discovery',
  validating_assets:      'Tech Detection',
  scanning_assets:        'Running Engines',
  detecting_technologies: 'Tech Summary',
  cve_analysis:           'CVE Analysis',
  completed:              'Completed',
  failed:                 'Failed',
  cancelled:              'Cancelled',
  queued:                 'Queued',
  initializing:           'Initializing',
  running:                'Running',
  processing:             'Processing',
  saving:                 'Saving',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export default function ScansPage() {
  const router = useRouter()
  const { user } = useAuth()
  const [scans, setScans] = useState<FirestoreScan[]>([])
  const [search, setSearch] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  // Firestore realtime listener
  useEffect(() => {
    if (!user) return
    const unsub = listenToScans(user.uid, setScans)
    return unsub
  }, [user])

  async function handleStop(scanId: string) {
    if (!user) return
    setActionLoading(scanId)
    try {
      await cancelScan(scanId)
      await updateFirestoreScan(user.uid, scanId, {
        status: 'cancelled',
        currentStep: 'Cancelled',
      })
      toast.success('Scan stopped')
    } catch (err) {
      toast.error('Failed to stop scan', {
        description: err instanceof Error ? err.message : undefined,
      })
    } finally {
      setActionLoading(null)
    }
  }

  async function handleRestart(originalScanId: string, target: string) {
    if (!user) return
    setActionLoading(originalScanId)
    try {
      const result = await restartScan(originalScanId)
      await createFirestoreScan(user.uid, {
        scanId: result.scanId,
        target,
        scanType: 'DAST',
        scanProfile: result.scanProfile,
        status: 'queued',
        progress: 0,
        currentStep: 'Queued',
        logs: [{ timestamp: new Date().toLocaleTimeString(), message: 'Scan Created (Restarted)' }],
        findings: [],
        totalFindings: 0,
        createdAt: new Date().toISOString(),
      })
      toast.success('Scan restarted', {
        action: {
          label: 'View',
          onClick: () => router.push(`/app/scans/${result.scanId}`),
        },
      })
      router.push(`/app/scans/${result.scanId}`)
    } catch (err) {
      toast.error('Failed to restart scan', {
        description: err instanceof Error ? err.message : undefined,
      })
    } finally {
      setActionLoading(null)
    }
  }

  const filtered = scans.filter(
    (s) =>
      s.target.toLowerCase().includes(search.toLowerCase()) ||
      s.scanId.toLowerCase().includes(search.toLowerCase()),
  )

  const totalScans     = scans.length
  const queuedScans    = scans.filter((s) => s.status === 'queued').length
  const runningScans   = scans.filter((s) => ACTIVE_STATUSES.has(s.status) && s.status !== 'queued').length
  const totalFindings  = scans.reduce((n, s) => n + s.totalFindings, 0)
  const completedScans = scans.filter((s) => s.status === 'completed').length

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Scans</h1>
          <p className="text-muted-foreground mt-1">Monitor and manage your security assessment scans</p>
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6 gap-2"
          onClick={() => setModalOpen(true)}
        >
          <Plus className="w-4 h-4" />
          Start New Scan
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Total</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{totalScans}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Queued</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-500">{queuedScans}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Running</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-400">{runningScans}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{completedScans}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{totalFindings}</div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>
                {filtered.length} scan{filtered.length !== 1 ? 's' : ''}
              </CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search scans…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <p className="text-sm">No scans yet.</p>
              <p className="text-xs mt-1">Click &ldquo;Start New Scan&rdquo; to run your first scan.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Scan ID</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Target</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Type</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Status</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Progress</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Findings</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Created</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((scan) => {
                    const isActive = ACTIVE_STATUSES.has(scan.status)
                    const isCancelled = scan.status === 'cancelled' || scan.status === 'failed'
                    const busy = actionLoading === scan.scanId
                    return (
                      <tr
                        key={scan.scanId}
                        className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors"
                      >
                        <td className="py-3 px-4">
                          <span className="text-xs font-mono text-muted-foreground">
                            {scan.scanId}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm font-medium text-foreground max-w-[180px] truncate block">
                            {scan.target}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-xs font-medium px-2 py-1 rounded bg-foreground/5 text-muted-foreground">
                            {scan.scanType}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`text-xs font-medium px-2 py-1 rounded ${
                              STATUS_BADGE[scan.status] ?? 'bg-gray-500/10 text-gray-400'
                            }`}
                          >
                            {STATUS_LABEL[scan.status] ?? scan.status.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2 w-28">
                            <div className="flex-1 h-1.5 bg-foreground/10 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary rounded-full transition-all duration-500"
                                style={{ width: `${scan.progress}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground w-8 text-right">
                              {scan.progress}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm font-medium text-foreground">
                            {scan.totalFindings}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                          {formatDate(scan.createdAt)}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1">
                            {isActive && (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={busy}
                                className="h-8 rounded-lg text-destructive hover:bg-destructive/10 gap-1"
                                onClick={() => handleStop(scan.scanId)}
                              >
                                <StopCircle className="w-3.5 h-3.5" />
                                Stop
                              </Button>
                            )}
                            {isCancelled && (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={busy}
                                className="h-8 rounded-lg text-blue-400 hover:bg-blue-500/10 gap-1"
                                onClick={() => handleRestart(scan.scanId, scan.target)}
                              >
                                <RotateCcw className="w-3.5 h-3.5" />
                                Restart
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-8 rounded-lg text-primary hover:bg-primary/10"
                              onClick={() => router.push(`/app/scans/${scan.scanId}`)}
                            >
                              View →
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

      <NewScanModal open={modalOpen} onOpenChange={setModalOpen} />
    </div>
  )
}
