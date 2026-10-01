'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Code2, Clock, Loader2, FileCode2, Trash2, ChevronRight,
  AlertTriangle, CheckCircle2, XCircle, RefreshCcw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { useAuth } from '@/context/auth-context'
import { TableSkeleton } from '@/components/app/loading-states'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listenToSastScans, deleteSastScan, type FirestoreSastScan, SAST_ACTIVE_STATUSES } from '@/lib/firestore-sast-scans'
import { deleteSastFindingsByScan } from '@/lib/firestore-sast-findings'
import { deleteSastScanApi } from '@/lib/api-sast'

// ── Helpers ───────────────────────────────────────────────────────────

function StatusIcon({ status }: { status: string }) {
  if (SAST_ACTIVE_STATUSES.has(status))
    return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
  if (status === 'completed')
    return <CheckCircle2 className="w-4 h-4 text-green-400" />
  if (status === 'failed')
    return <XCircle className="w-4 h-4 text-red-400" />
  return <RefreshCcw className="w-4 h-4 text-muted-foreground" />
}

function SevPill({ value, label, accent }: { value: number; label: string; accent: string }) {
  if (value === 0) return null
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${accent}`}>
      {value} {label}
    </span>
  )
}

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// ── Row ───────────────────────────────────────────────────────────────

function ScanRow({ scan, onDelete }: { scan: FirestoreSastScan; onDelete: (s: FirestoreSastScan) => void }) {
  const router = useRouter()

  return (
    <tr className="border-b border-foreground/8 hover:bg-foreground/5 transition-colors group">
      <td className="px-4 py-3">
        <button
          onClick={() => router.push(`/app/sast/scans/${scan.scanId}`)}
          className="flex items-center gap-3 text-left w-full"
        >
          <div className="w-8 h-8 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
            <Code2 className="w-3.5 h-3.5 text-violet-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium text-foreground truncate">{scan.projectName}</p>
            <p className="text-xs text-muted-foreground">{scan.uploadMethod === 'zip' ? 'ZIP upload' : 'Directory upload'}</p>
          </div>
        </button>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-foreground font-medium">{scan.language || '—'}</span>
      </td>
      <td className="px-4 py-3">
        <p className="text-xs text-muted-foreground">{fmtDate(scan.createdAt)}</p>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-muted-foreground">
          {scan.duration ?? (SAST_ACTIVE_STATUSES.has(scan.status) ? `${scan.progress}%` : '—')}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1 flex-wrap">
          {scan.status === 'completed' ? (
            <>
              <SevPill value={scan.criticalFindings} label="C"  accent="bg-red-500/15 text-red-400" />
              <SevPill value={scan.highFindings}     label="H"  accent="bg-orange-500/15 text-orange-400" />
              <SevPill value={scan.mediumFindings}   label="M"  accent="bg-yellow-500/15 text-yellow-400" />
              <SevPill value={scan.lowFindings}      label="L"  accent="bg-blue-500/15 text-blue-400" />
              {scan.totalFindings === 0 && <span className="text-xs text-green-400">Clean</span>}
            </>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          <StatusIcon status={scan.status} />
          <span className="text-xs capitalize text-muted-foreground">{scan.status}</span>
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            onClick={() => router.push(`/app/sast/scans/${scan.scanId}`)}
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-destructive"
            onClick={() => onDelete(scan)}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </td>
    </tr>
  )
}

// ── Page ──────────────────────────────────────────────────────────────

export default function SastScansPage() {
  const { user }  = useAuth()
  const router    = useRouter()
  const [scans, setScans]     = useState<FirestoreSastScan[]>([])
  const [loading, setLoading] = useState(true)
  const showSkeleton = useDelayedLoading(loading)

  useEffect(() => {
    if (!user) return
    setLoading(true)
    const unsub = listenToSastScans(user.organizationId, (s) => {
      setScans(s)
      setLoading(false)
    })
    return unsub
  }, [user])

  async function handleDelete(scan: FirestoreSastScan) {
    if (!user) return
    const ok = window.confirm(`Delete scan "${scan.projectName}"? This cannot be undone.`)
    if (!ok) return
    try {
      await Promise.all([
        deleteSastScan(user.organizationId, scan.scanId),
        deleteSastFindingsByScan(user.organizationId, scan.scanId),
        deleteSastScanApi(scan.scanId).catch(() => {}),
      ])
      toast.success('Scan deleted')
    } catch {
      toast.error('Failed to delete scan')
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground">Scan History</h1>
          <p className="text-sm text-muted-foreground mt-0.5">All SAST scans and their results</p>
        </div>
        <Button
          onClick={() => router.push('/app/sast')}
          className="bg-violet-600 hover:bg-violet-700 text-white gap-2"
        >
          <Code2 className="w-4 h-4" />
          New Scan
        </Button>
      </div>

      <div className="bg-card border border-foreground/10 rounded-xl overflow-hidden">
        {showSkeleton ? (
          <div className="p-4">
            <TableSkeleton rows={5} cols={6} />
          </div>
        ) : loading ? null : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <FileCode2 className="w-10 h-10 text-muted-foreground/30 mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No scans yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Start a new scan from the SAST dashboard</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Project', 'Language', 'Started', 'Duration', 'Findings', 'Status', ''].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <ScanRow key={s.scanId} scan={s} onDelete={handleDelete} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
