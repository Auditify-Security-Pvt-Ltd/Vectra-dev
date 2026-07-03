'use client'

import { useEffect, useState } from 'react'
import {
  Activity, Server, Plus, Minus, AlertTriangle, ShieldAlert,
  Lock, TrendingUp, TrendingDown, Wifi,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { useAuth } from '@/context/auth-context'
import {
  listenToNetworkTimeline,
  type FirestoreNetworkTimeline,
  type TimelineChange,
} from '@/lib/firestore-network-timeline'

// ── Helpers ───────────────────────────────────────────────────────────

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60)    return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24)   return `${hours}h ago`
  const days  = Math.floor(hours / 24)
  return `${days}d ago`
}

const CHANGE_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  new_host:       Plus,
  removed_host:   Minus,
  new_port:       Plus,
  closed_port:    Minus,
  service_changed:Activity,
  new_cve:        AlertTriangle,
  risk_increased: TrendingUp,
  risk_decreased: TrendingDown,
  ssl_issue:      Lock,
}

const CHANGE_COLOR: Record<string, string> = {
  new_host:       'text-green-500',
  removed_host:   'text-muted-foreground',
  new_port:       'text-blue-400',
  closed_port:    'text-muted-foreground',
  service_changed:'text-yellow-500',
  new_cve:        'text-red-500',
  risk_increased: 'text-orange-500',
  risk_decreased: 'text-green-500',
  ssl_issue:      'text-orange-400',
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  warning:  'bg-orange-500/10 text-orange-400 border-orange-500/20',
  info:     'bg-foreground/8 text-muted-foreground border-foreground/10',
}

function ChangeItem({ change }: { change: TimelineChange }) {
  const Icon  = CHANGE_ICON[change.type] ?? Activity
  const color = CHANGE_COLOR[change.type] ?? 'text-muted-foreground'
  return (
    <div className="flex items-start gap-2.5 py-1.5">
      <Icon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${color}`} />
      <div className="flex-1 min-w-0">
        <p className="text-[12px] text-foreground/85">{change.details}</p>
      </div>
      <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded border shrink-0 ${SEV_BADGE[change.severity] ?? SEV_BADGE.info}`}>
        {change.severity.toUpperCase()}
      </span>
    </div>
  )
}

function TimelineCard({ event }: { event: FirestoreNetworkTimeline }) {
  const [expanded, setExpanded] = useState(false)
  const hasCritical = event.changes.some((c) => c.severity === 'critical')
  const hasWarning  = !hasCritical && event.changes.some((c) => c.severity === 'warning')

  return (
    <div className={`rounded-lg border transition-colors ${
      hasCritical ? 'border-red-500/20 bg-red-500/3' :
      hasWarning  ? 'border-orange-500/20 bg-orange-500/3' :
      'border-foreground/8 bg-foreground/2'
    }`}>
      <div
        className="flex items-start gap-4 p-4 cursor-pointer"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
          hasCritical ? 'bg-red-500/10' : hasWarning ? 'bg-orange-500/10' : 'bg-foreground/5'
        }`}>
          <Activity className={`w-4 h-4 ${
            hasCritical ? 'text-red-500' : hasWarning ? 'text-orange-400' : 'text-muted-foreground'
          }`} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-mono font-semibold text-foreground">{event.target}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded border bg-foreground/8 text-muted-foreground border-foreground/10">
              {event.changeCount} change{event.changeCount !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground flex-wrap">
            <span>{formatDate(event.timestamp)}</span>
            <span className="text-muted-foreground/50">·</span>
            <span>{timeAgo(event.timestamp)}</span>
            {event.newHosts > 0 && (
              <span className="text-green-500"><Plus className="w-3 h-3 inline" /> {event.newHosts} host{event.newHosts !== 1 ? 's' : ''}</span>
            )}
            {event.removedHosts > 0 && (
              <span className="text-muted-foreground"><Minus className="w-3 h-3 inline" /> {event.removedHosts} removed</span>
            )}
            {event.portChanges > 0 && (
              <span className="text-blue-400">{event.portChanges} port change{event.portChanges !== 1 ? 's' : ''}</span>
            )}
            {event.riskChanges > 0 && (
              <span className="text-orange-400"><ShieldAlert className="w-3 h-3 inline mr-0.5" />{event.riskChanges} risk change{event.riskChanges !== 1 ? 's' : ''}</span>
            )}
          </div>
        </div>

        <span className="text-[10px] text-muted-foreground/60 shrink-0">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-0.5 border-t border-foreground/5 pt-3">
          {event.changes.map((change, i) => (
            <ChangeItem key={i} change={change} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function NetworkTimelinePage() {
  const { user }   = useAuth()
  const [events,   setEvents] = useState<FirestoreNetworkTimeline[]>([])
  const [search,   setSearch] = useState('')

  useEffect(() => {
    if (!user) return
    return listenToNetworkTimeline(user.organizationId, setEvents)
  }, [user])

  const filtered = events.filter((e) =>
    e.target.includes(search) ||
    e.changes.some((c) => c.details.toLowerCase().includes(search.toLowerCase())),
  )

  const totalChanges  = events.reduce((n, e) => n + e.changeCount, 0)
  const criticalCount = events.filter((e) => e.changes.some((c) => c.severity === 'critical')).length
  const newHostsTotal = events.reduce((n, e) => n + e.newHosts, 0)

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      <div className="flex items-start gap-4">
        <div className="w-11 h-11 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
          <Activity className="w-5 h-5 text-violet-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Network Timeline</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Asset change tracking — new hosts, port changes, risk shifts, and SSL issues between scans
          </p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Changes',    value: totalChanges,  cls: 'text-foreground'  },
          { label: 'Critical Events',  value: criticalCount, cls: 'text-red-500'     },
          { label: 'New Hosts Found',  value: newHostsTotal, cls: 'text-green-500'   },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="relative">
        <Activity className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by target or change details…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-background border-foreground/15 h-10"
        />
      </div>

      {filtered.length === 0 ? (
        <Card className="bg-card border-foreground/10">
          <CardContent className="py-16 text-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
              <Activity className="w-6 h-6 text-muted-foreground" />
            </div>
            <p className="text-sm text-muted-foreground">
              {search ? 'No events match your search' : 'No timeline events yet — run multiple scans on the same target to track changes'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((event) => (
            <TimelineCard key={event.eventId} event={event} />
          ))}
        </div>
      )}
    </div>
  )
}
