'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Clock, Plus, Loader2, Play, Pause, Trash2, Edit2,
  CheckCircle2, Calendar, Wifi, Radio, X, Save,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog'
import { useAuth } from '@/context/auth-context'
import {
  listSchedules, createSchedule, updateSchedule, deleteSchedule, triggerSchedule,
  type NetworkSchedule, type ScheduleInterval, type ScheduleCreateBody,
} from '@/lib/api-network-schedules'

// ── Helpers ───────────────────────────────────────────────────────────

const INTERVAL_LABELS: Record<ScheduleInterval, string> = {
  once:    'Run Once',
  daily:   'Daily',
  weekly:  'Weekly',
  monthly: 'Monthly',
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function nextRunLabel(iso: string | null): string {
  if (!iso) return 'Completed'
  const dt   = new Date(iso)
  const now  = new Date()
  const diff = dt.getTime() - now.getTime()
  if (diff < 0) return 'Due now'
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(mins / 60)
  const days  = Math.floor(hours / 24)
  if (days > 0)  return `in ${days}d`
  if (hours > 0) return `in ${hours}h`
  return `in ${mins}m`
}

// ── Schedule form ─────────────────────────────────────────────────────

interface ScheduleFormState {
  target: string
  profile: 'QUICK_SCAN' | 'FULL_SCAN'
  interval: ScheduleInterval
  label: string
  enabled: boolean
}

const EMPTY_FORM: ScheduleFormState = {
  target: '', profile: 'QUICK_SCAN', interval: 'weekly', label: '', enabled: true,
}

function ScheduleFormModal({
  open,
  onClose,
  onSaved,
  userId,
  editing,
}: {
  open: boolean
  onClose: () => void
  onSaved: () => void
  userId: string
  editing: NetworkSchedule | null
}) {
  const [form,    setForm]   = useState<ScheduleFormState>(EMPTY_FORM)
  const [saving,  setSaving] = useState(false)
  const [err,     setErr]    = useState<string | null>(null)

  useEffect(() => {
    if (editing) {
      setForm({
        target:   editing.target,
        profile:  editing.profile,
        interval: editing.interval,
        label:    editing.label,
        enabled:  editing.enabled,
      })
    } else {
      setForm(EMPTY_FORM)
    }
    setErr(null)
  }, [editing, open])

  async function handleSave() {
    if (!form.target.trim()) { setErr('Target is required'); return }
    setSaving(true); setErr(null)
    try {
      const body: ScheduleCreateBody = {
        userId,
        target:   form.target.trim(),
        profile:  form.profile,
        interval: form.interval,
        enabled:  form.enabled,
        label:    form.label.trim() || form.target.trim(),
      }
      if (editing) {
        await updateSchedule(editing.scheduleId, body)
        toast.success('Schedule updated')
      } else {
        await createSchedule(body)
        toast.success('Schedule created')
      }
      onSaved()
      onClose()
    } catch (e: any) {
      setErr(e?.message ?? 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold flex items-center gap-2">
            <Clock className="w-4 h-4 text-primary" />
            {editing ? 'Edit Schedule' : 'New Scheduled Scan'}
          </DialogTitle>
          <DialogDescription className="sr-only">Configure a recurring network scan schedule</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Label (optional)</label>
            <Input
              placeholder="e.g. Production Network"
              value={form.label}
              onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
              className="bg-background border-foreground/20 h-9 text-sm"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Target</label>
            <Input
              placeholder="192.168.1.0/24  ·  10.0.0.5  ·  192.168.1.1-20"
              value={form.target}
              onChange={(e) => setForm((f) => ({ ...f, target: e.target.value }))}
              className="font-mono bg-background border-foreground/20 h-9 text-sm"
              autoFocus={!editing}
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Scan Profile</label>
            <div className="grid grid-cols-2 gap-2">
              {(['QUICK_SCAN', 'FULL_SCAN'] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setForm((f) => ({ ...f, profile: p }))}
                  className={`p-2.5 rounded-lg border text-left transition-colors ${
                    form.profile === p ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'
                  }`}
                >
                  <p className="text-sm font-medium text-foreground">{p === 'QUICK_SCAN' ? 'Quick' : 'Full'}</p>
                  <p className="text-[11px] text-muted-foreground">{p === 'QUICK_SCAN' ? 'Top 1000 ports' : 'All 65535 ports'}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Interval</label>
            <div className="grid grid-cols-2 gap-2">
              {(Object.entries(INTERVAL_LABELS) as [ScheduleInterval, string][]).map(([id, label]) => (
                <button
                  key={id}
                  onClick={() => setForm((f) => ({ ...f, interval: id }))}
                  className={`p-2.5 rounded-lg border text-left transition-colors ${
                    form.interval === id ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'
                  }`}
                >
                  <p className="text-sm font-medium text-foreground">{label}</p>
                </button>
              ))}
            </div>
          </div>

          {err && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">{err}</div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" onClick={onClose} className="h-9 text-sm rounded-lg">
              <X className="w-3.5 h-3.5 mr-1.5" /> Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={saving || !form.target.trim()}
              className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-9 px-4 text-sm gap-2 disabled:opacity-40"
            >
              {saving
                ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving…</>
                : <><Save className="w-3.5 h-3.5" /> {editing ? 'Update' : 'Create'}</>
              }
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function NetworkSchedulesPage() {
  const router      = useRouter()
  const { user }    = useAuth()
  const [schedules, setSchedules] = useState<NetworkSchedule[]>([])
  const [loading,   setLoading]   = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing,   setEditing]   = useState<NetworkSchedule | null>(null)
  const [busy,      setBusy]      = useState<string | null>(null)

  async function loadSchedules() {
    if (!user) return
    try {
      const list = await listSchedules(user.uid)
      setSchedules(list)
    } catch {
      toast.error('Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadSchedules() }, [user]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleToggle(sched: NetworkSchedule) {
    setBusy(sched.scheduleId)
    try {
      await updateSchedule(sched.scheduleId, { enabled: !sched.enabled })
      toast.success(sched.enabled ? 'Schedule disabled' : 'Schedule enabled')
      await loadSchedules()
    } catch { toast.error('Failed to update') }
    finally { setBusy(null) }
  }

  async function handleDelete(sched: NetworkSchedule) {
    if (!confirm(`Delete schedule for "${sched.label}"?`)) return
    setBusy(sched.scheduleId)
    try {
      await deleteSchedule(sched.scheduleId)
      toast.success('Schedule deleted')
      await loadSchedules()
    } catch { toast.error('Failed to delete') }
    finally { setBusy(null) }
  }

  async function handleTrigger(sched: NetworkSchedule) {
    setBusy(sched.scheduleId)
    try {
      const res = await triggerSchedule(sched.scheduleId)
      toast.success('Scan triggered')
      router.push(`/app/network-security/scans/${res.scanId}`)
    } catch { toast.error('Failed to trigger') }
    finally { setBusy(null) }
  }

  const enabledCount  = schedules.filter((s) => s.enabled).length
  const disabledCount = schedules.length - enabledCount
  const dueCount      = schedules.filter((s) => s.enabled && s.nextRun && new Date(s.nextRun) <= new Date()).length

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <div className="w-11 h-11 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <Clock className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Scheduled Scans</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Automate recurring network scans — runs while the backend is active
            </p>
          </div>
        </div>
        <Button
          onClick={() => { setEditing(null); setModalOpen(true) }}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5 text-sm gap-2"
        >
          <Plus className="w-4 h-4" /> New Schedule
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Active Schedules', value: enabledCount,  cls: 'text-green-500'  },
          { label: 'Paused',           value: disabledCount, cls: 'text-muted-foreground' },
          { label: 'Due Now',          value: dueCount,      cls: 'text-orange-400' },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Schedule list */}
      <Card className="bg-card border-foreground/10">
        <CardHeader className="pb-2 pt-4 px-5">
          <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Calendar className="w-4 h-4 text-muted-foreground" />
            Schedules
            <span className="text-xs font-normal text-muted-foreground ml-1">({schedules.length})</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : schedules.length === 0 ? (
            <div className="text-center py-16 space-y-3">
              <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
                <Clock className="w-6 h-6 text-muted-foreground" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">No schedules yet</p>
              <Button
                onClick={() => { setEditing(null); setModalOpen(true) }}
                variant="outline"
                className="rounded-lg border-foreground/20 h-9 text-sm"
              >
                <Plus className="w-3.5 h-3.5 mr-1.5" /> Create First Schedule
              </Button>
            </div>
          ) : (
            <div className="divide-y divide-foreground/5">
              {schedules.map((sched) => {
                const isDue = sched.enabled && sched.nextRun && new Date(sched.nextRun) <= new Date()
                const isBusy = busy === sched.scheduleId
                return (
                  <div key={sched.scheduleId} className="flex items-center gap-4 px-5 py-4 hover:bg-foreground/2 transition-colors">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                      !sched.enabled ? 'bg-foreground/5' : isDue ? 'bg-orange-500/10' : 'bg-green-500/10'
                    }`}>
                      {!sched.enabled
                        ? <Pause className="w-4 h-4 text-muted-foreground" />
                        : isDue
                          ? <Radio className="w-4 h-4 text-orange-400 animate-pulse" />
                          : <CheckCircle2 className="w-4 h-4 text-green-500" />
                      }
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold text-foreground">{sched.label}</p>
                        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                          sched.enabled
                            ? 'bg-green-500/10 text-green-500 border-green-500/20'
                            : 'bg-foreground/8 text-muted-foreground border-foreground/10'
                        }`}>
                          {sched.enabled ? 'ACTIVE' : 'PAUSED'}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded border bg-foreground/8 text-muted-foreground border-foreground/10">
                          {INTERVAL_LABELS[sched.interval]}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded border bg-foreground/8 text-muted-foreground border-foreground/10">
                          {sched.profile === 'QUICK_SCAN' ? 'Quick' : 'Full'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        <span className="font-mono">{sched.target}</span>
                        <span>·</span>
                        <span>Last: {formatDate(sched.lastRun)}</span>
                        <span>·</span>
                        <span className={isDue ? 'text-orange-400' : ''}>
                          Next: {nextRunLabel(sched.nextRun)}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => handleTrigger(sched)}
                        disabled={isBusy}
                        title="Run now"
                        className="h-8 w-8 p-0 rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10"
                      >
                        {isBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                      </Button>
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => handleToggle(sched)}
                        disabled={isBusy}
                        title={sched.enabled ? 'Pause' : 'Enable'}
                        className={`h-8 w-8 p-0 rounded-lg ${
                          sched.enabled
                            ? 'text-muted-foreground hover:text-orange-400 hover:bg-orange-400/10'
                            : 'text-muted-foreground hover:text-green-500 hover:bg-green-500/10'
                        }`}
                      >
                        {sched.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                      </Button>
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => { setEditing(sched); setModalOpen(true) }}
                        disabled={isBusy}
                        title="Edit"
                        className="h-8 w-8 p-0 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/8"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </Button>
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => handleDelete(sched)}
                        disabled={isBusy}
                        title="Delete"
                        className="h-8 w-8 p-0 rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <ScheduleFormModal
        open={modalOpen}
        onClose={() => { setModalOpen(false); setEditing(null) }}
        onSaved={loadSchedules}
        userId={user?.uid ?? ''}
        editing={editing}
      />
    </div>
  )
}
