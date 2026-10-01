'use client'

import { useState } from 'react'
import { Search, RefreshCw, Activity, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listTasks, type AdminTask } from '@/lib/api-admin'
import { AdminError, statusClasses, fmtTime, fmtDuration } from '@/components/admin/admin-shared'

const SCAN_TYPES = [
  { id: 'all',     label: 'All types' },
  { id: 'web',     label: 'Web Security' },
  { id: 'network', label: 'Network Security' },
  { id: 'sast',    label: 'SAST' },
]

const STATUSES = [
  { id: 'all',       label: 'All' },
  { id: 'running',   label: 'Running' },
  { id: 'queued',    label: 'Queued' },
  { id: 'completed', label: 'Completed' },
  { id: 'failed',    label: 'Failed' },
  { id: 'cancelled', label: 'Cancelled' },
]

const TYPE_LABEL: Record<string, string> = {
  web: 'Web Security', network: 'Network Security', sast: 'SAST',
}

function TaskDetail({ task, onClose }: { task: AdminTask; onClose: () => void }) {
  const rows: [string, string][] = [
    ['Scan ID',      task.scanId],
    ['Type',         TYPE_LABEL[task.scanType] ?? task.scanType],
    ['User',         task.userId],
    ['Target',       task.target ?? '—'],
    ['Status',       task.status ?? 'unknown'],
    ['Current stage', task.currentStep ?? '—'],
    ['Progress',     task.progress != null ? `${task.progress}%` : '—'],
    ['Created',      fmtTime(task.createdAt)],
    ['Completed',    fmtTime(task.completedAt)],
    ['Duration',     fmtDuration(task.createdAt, task.completedAt)],
    ['Findings',     String(task.findings ?? 0)],
    ['CVEs',         String(task.cves ?? 0)],
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-foreground/10 bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-foreground/8">
          <h2 className="text-base font-semibold text-foreground">Task details</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose}>
            <X className="w-4 h-4" />
          </Button>
        </div>
        <div className="px-5 py-4 space-y-1.5 max-h-[70vh] overflow-y-auto">
          {rows.map(([k, v], i) => (
            <div key={k} className={`flex justify-between gap-4 text-xs py-1.5 ${i % 2 ? '' : 'bg-foreground/2'} px-2 rounded`}>
              <span className="text-muted-foreground shrink-0">{k}</span>
              <span className="text-foreground font-mono text-right break-all">{v}</span>
            </div>
          ))}
          {task.error && (
            <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/5 p-3">
              <p className="text-xs font-medium text-red-400 mb-1">Error</p>
              <p className="text-[11px] text-muted-foreground break-all">{task.error}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AdminTasksPage() {
  const [status, setStatus]     = useState('all')
  const [scanType, setScanType] = useState('all')
  const [search, setSearch]     = useState('')
  const [query, setQuery]       = useState('')
  const [selected, setSelected] = useState<AdminTask | null>(null)

  const { data, loading, error, refresh } = useAdminData(
    () => listTasks({ status, scanType, search: query, limit: 200 }),
    { deps: [status, scanType, query], pollMs: 10_000 },
  )
  const showSkeleton = useDelayedLoading(loading && !data)

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Tasks &amp; Scans</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Live and recent scans across every organization. Auto-refreshes every 10s.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refresh}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {error && <AdminError message={error} />}

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex gap-1">
          {STATUSES.map((s) => (
            <button
              key={s.id}
              onClick={() => setStatus(s.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                status === s.id
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-foreground/10 text-muted-foreground hover:border-foreground/25'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="h-8 rounded-lg bg-foreground/5 border border-foreground/15 px-2 text-xs text-foreground"
        >
          {SCAN_TYPES.map((t) => (
            <option key={t.id} value={t.id} className="bg-card">{t.label}</option>
          ))}
        </select>
        <form
          onSubmit={(e) => { e.preventDefault(); setQuery(search.trim()) }}
          className="relative ml-auto"
        >
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Target, scan ID or user…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 h-8 w-64 bg-foreground/5 border-foreground/20 text-xs"
          />
        </form>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={6} cols={7} /></div>
          ) : loading && !data ? null : !data?.tasks.length ? (
            <div className="text-center py-16">
              <Activity className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No tasks match these filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Type', 'Target', 'User', 'Status', 'Stage', 'Started', 'Duration'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.tasks.map((t) => (
                    <tr
                      key={`${t.scanType}-${t.scanId}`}
                      onClick={() => setSelected(t)}
                      className="border-b border-foreground/5 hover:bg-foreground/5 cursor-pointer"
                    >
                      <td className="py-3 px-4 text-xs text-foreground">{TYPE_LABEL[t.scanType] ?? t.scanType}</td>
                      <td className="py-3 px-4 text-xs font-mono text-foreground truncate max-w-[200px]">{t.target ?? '—'}</td>
                      <td className="py-3 px-4 text-xs font-mono text-muted-foreground truncate max-w-[150px]">{t.userId}</td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${statusClasses(t.status)}`}>
                          {t.status ?? 'unknown'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground truncate max-w-[160px]">{t.currentStep ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-muted-foreground">{fmtTime(t.createdAt)}</td>
                      <td className="py-3 px-4 text-xs text-muted-foreground">{fmtDuration(t.createdAt, t.completedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {data && <p className="text-xs text-muted-foreground">{data.total} task(s)</p>}
      {selected && <TaskDetail task={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
