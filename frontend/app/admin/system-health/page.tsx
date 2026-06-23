'use client'

import { useState } from 'react'
import { RefreshCw, Activity, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const services = [
  { id: 'api', name: 'API Gateway', desc: 'Primary REST API & GraphQL endpoint', status: 'Operational', uptime: 99.98, responseTime: 42, lastCheck: 'Just now', region: 'us-east-1' },
  { id: 'db', name: 'Database (PostgreSQL)', desc: 'Primary relational database cluster', status: 'Operational', uptime: 99.99, responseTime: 8, lastCheck: '30s ago', region: 'us-east-1' },
  { id: 'redis', name: 'Task Queue (Redis)', desc: 'Distributed job queue and session store', status: 'Degraded', uptime: 98.72, responseTime: 124, lastCheck: '1 min ago', region: 'us-east-1' },
  { id: 'workers', name: 'Scan Workers', desc: 'Distributed vulnerability scan executor cluster', status: 'Operational', uptime: 99.85, responseTime: 0, lastCheck: '45s ago', region: 'Multi-region' },
  { id: 'cloud-scanner', name: 'Cloud Scanner', desc: 'AWS / Azure / GCP posture assessment engine', status: 'Operational', uptime: 99.41, responseTime: 210, lastCheck: '2 min ago', region: 'Multi-region' },
  { id: 'ai', name: 'AI Service (OpenAI)', desc: 'GPT-4o powered analysis and report generation', status: 'Operational', uptime: 99.30, responseTime: 880, lastCheck: '20s ago', region: 'External' },
]

const responseTimeTrend = [
  { time: '15:30', api: 38, db: 7, ai: 820 }, { time: '15:35', api: 41, db: 9, ai: 850 },
  { time: '15:40', api: 45, db: 8, ai: 900 }, { time: '15:45', api: 39, db: 7, ai: 870 },
  { time: '15:50', api: 43, db: 11, ai: 940 }, { time: '15:55', api: 42, db: 8, ai: 880 },
  { time: '16:00', api: 42, db: 8, ai: 880 },
]

const uptimeTrend = [
  { day: 'Mon', uptime: 100 }, { day: 'Tue', uptime: 99.9 }, { day: 'Wed', uptime: 99.7 },
  { day: 'Thu', uptime: 100 }, { day: 'Fri', uptime: 99.8 }, { day: 'Sat', uptime: 100 }, { day: 'Sun', uptime: 99.98 },
]

const statusConfig: Record<string, { badge: string; icon: any; dot: string; text: string }> = {
  Operational: { badge: 'bg-green-500/10 text-green-500 border-green-500/20', icon: CheckCircle2, dot: 'bg-green-500', text: 'text-green-500' },
  Degraded: { badge: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20', icon: AlertTriangle, dot: 'bg-yellow-500', text: 'text-yellow-500' },
  Down: { badge: 'bg-red-500/10 text-red-500 border-red-500/20', icon: XCircle, dot: 'bg-red-500', text: 'text-red-500' },
}

export default function AdminSystemHealthPage() {
  const [refreshing, setRefreshing] = useState(false)
  const [lastRefresh, setLastRefresh] = useState('Just now')

  const handleRefresh = () => {
    setRefreshing(true)
    setTimeout(() => { setRefreshing(false); setLastRefresh('Just now') }, 1500)
  }

  const operational = services.filter(s => s.status === 'Operational').length
  const degraded = services.filter(s => s.status === 'Degraded').length
  const down = services.filter(s => s.status === 'Down').length
  const avgUptime = (services.reduce((a, s) => a + s.uptime, 0) / services.length).toFixed(2)

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">System Health</h1>
          <p className="text-muted-foreground mt-1">Real-time status of all platform services and infrastructure</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">Refreshed: {lastRefresh}</span>
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />Refresh
          </Button>
        </div>
      </div>

      {/* Status Banner */}
      <div className={`flex items-center gap-4 p-4 rounded-xl border ${
        down > 0 ? 'bg-red-500/5 border-red-500/20' : degraded > 0 ? 'bg-yellow-500/5 border-yellow-500/20' : 'bg-green-500/5 border-green-500/20'
      }`}>
        <div className={`w-3 h-3 rounded-full animate-pulse ${down > 0 ? 'bg-red-500' : degraded > 0 ? 'bg-yellow-500' : 'bg-green-500'}`} />
        <div>
          <p className="font-semibold text-foreground">{down > 0 ? 'Service Disruption' : degraded > 0 ? 'Partial Degradation' : 'All Systems Operational'}</p>
          <p className="text-sm text-muted-foreground">{operational} operational · {degraded} degraded · {down} down · {avgUptime}% avg uptime</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Services', value: services.length, color: 'text-foreground' },
          { label: 'Operational', value: operational, color: 'text-green-500' },
          { label: 'Degraded', value: degraded, color: 'text-yellow-500' },
          { label: 'Avg Uptime', value: `${avgUptime}%`, color: 'text-primary' },
        ].map(s => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Service Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {services.map(service => {
          const cfg = statusConfig[service.status]
          const StatusIcon = cfg.icon
          return (
            <Card key={service.id} className="bg-card border-foreground/10 hover:border-foreground/20 transition-all">
              <CardContent className="pt-5 pb-5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <div className="w-10 h-10 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center">
                        <Activity className="w-5 h-5 text-primary" />
                      </div>
                      <div className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-card ${cfg.dot}`} />
                    </div>
                    <div>
                      <p className="font-semibold text-foreground text-sm">{service.name}</p>
                      <p className="text-xs text-muted-foreground">{service.region}</p>
                    </div>
                  </div>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded border ${cfg.badge}`}>{service.status}</span>
                </div>
                <p className="text-xs text-muted-foreground mb-4">{service.desc}</p>
                <div className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-muted-foreground">Uptime</span>
                      <span className="font-medium text-foreground">{service.uptime}%</span>
                    </div>
                    <Progress value={service.uptime} className="h-1.5" />
                  </div>
                  {service.responseTime > 0 && (
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Response Time</span>
                      <span className={`font-medium ${service.responseTime > 500 ? 'text-yellow-500' : 'text-green-500'}`}>{service.responseTime}ms</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Last Check</span>
                    <span className="text-foreground">{service.lastCheck}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Response Time Trend</CardTitle>
            <CardDescription>API, Database, and AI latency over the last 30 minutes (ms)</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={responseTimeTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Legend />
                <Line type="monotone" dataKey="api" stroke="oklch(0.52 0.26 264)" strokeWidth={2} name="API (ms)" dot={false} />
                <Line type="monotone" dataKey="db" stroke="#22c55e" strokeWidth={2} name="DB (ms)" dot={false} />
                <Line type="monotone" dataKey="ai" stroke="#f97316" strokeWidth={2} name="AI (ms)" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Weekly Uptime</CardTitle>
            <CardDescription>Platform availability over the past 7 days (%)</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={uptimeTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="day" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} domain={[99, 100]} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Line type="monotone" dataKey="uptime" stroke="#22c55e" strokeWidth={2} name="Uptime %" dot={{ fill: '#22c55e', r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
