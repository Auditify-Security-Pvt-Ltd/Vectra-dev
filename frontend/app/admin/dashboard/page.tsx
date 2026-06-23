'use client'

import Link from 'next/link'
import {
  Building2, Users, DollarSign, Zap, AlertTriangle,
  Cloud, Activity, TrendingUp, TrendingDown,
  ArrowRight, CheckCircle2, XCircle, UserPlus,
  ShieldAlert, BarChart3,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from 'recharts'

const kpis = [
  { title: 'Total Organizations', value: '67', change: '+5', trend: 'up', icon: Building2, color: 'text-blue-500', bg: 'bg-blue-500/10', href: '/admin/organizations' },
  { title: 'Total Users', value: '284', change: '+18', trend: 'up', icon: Users, color: 'text-green-500', bg: 'bg-green-500/10', href: '/admin/users' },
  { title: 'Active Organizations', value: '61', change: '+3', trend: 'up', icon: Activity, color: 'text-primary', bg: 'bg-primary/10', href: '/admin/organizations' },
  { title: 'Monthly Revenue', value: '$48,290', change: '+12%', trend: 'up', icon: DollarSign, color: 'text-emerald-500', bg: 'bg-emerald-500/10', href: '/admin/subscriptions' },
  { title: 'Active Scans', value: '23', change: '+8', trend: 'up', icon: Zap, color: 'text-yellow-500', bg: 'bg-yellow-500/10', href: '/admin/scans' },
  { title: 'Critical Findings', value: '387', change: '-42', trend: 'down', icon: AlertTriangle, color: 'text-red-500', bg: 'bg-red-500/10', href: '/admin/findings' },
  { title: 'Cloud Accounts', value: '16', change: '+2', trend: 'up', icon: Cloud, color: 'text-accent', bg: 'bg-accent/10', href: '/admin/cloud' },
  { title: 'System Health', value: '98.4%', change: '+0.2%', trend: 'up', icon: Activity, color: 'text-emerald-500', bg: 'bg-emerald-500/10', href: '/admin/system-health' },
]

const orgGrowth = [
  { month: 'Aug', orgs: 42, users: 178 }, { month: 'Sep', orgs: 47, users: 201 },
  { month: 'Oct', orgs: 51, users: 218 }, { month: 'Nov', orgs: 56, users: 241 },
  { month: 'Dec', orgs: 62, users: 267 }, { month: 'Jan', orgs: 67, users: 284 },
]

const revenue = [
  { month: 'Aug', mrr: 31200, arr: 374400 }, { month: 'Sep', mrr: 34800, arr: 417600 },
  { month: 'Oct', mrr: 38500, arr: 462000 }, { month: 'Nov', mrr: 41200, arr: 494400 },
  { month: 'Dec', mrr: 44800, arr: 537600 }, { month: 'Jan', mrr: 48290, arr: 579480 },
]

const severityDist = [
  { name: 'Critical', value: 387, color: '#ef4444' },
  { name: 'High', value: 1842, color: '#f97316' },
  { name: 'Medium', value: 4210, color: '#eab308' },
  { name: 'Low', value: 12400, color: '#3b82f6' },
]

const platformUsage = [
  { day: 'Mon', scans: 284, reports: 42, logins: 198 },
  { day: 'Tue', scans: 312, reports: 38, logins: 221 },
  { day: 'Wed', scans: 298, reports: 51, logins: 209 },
  { day: 'Thu', scans: 341, reports: 44, logins: 234 },
  { day: 'Fri', scans: 267, reports: 62, logins: 187 },
  { day: 'Sat', scans: 142, reports: 28, logins: 98 },
  { day: 'Sun', scans: 98, reports: 19, logins: 67 },
]

const cloudRisk = [
  { provider: 'AWS', accounts: 6, critical: 89, high: 214 },
  { provider: 'Azure', accounts: 5, critical: 54, high: 178 },
  { provider: 'GCP', accounts: 5, critical: 71, high: 196 },
]

const recentOrgs = [
  { name: 'FinTech Corp', plan: 'Enterprise', users: 24, status: 'Active', joined: '2d ago' },
  { name: 'MedSecure Ltd', plan: 'Professional', users: 8, status: 'Active', joined: '4d ago' },
  { name: 'CloudNative IO', plan: 'Business', users: 12, status: 'Trial', joined: '5d ago' },
  { name: 'CyberShield Inc', plan: 'Starter', users: 3, status: 'Active', joined: '1w ago' },
  { name: 'DataSafe Corp', plan: 'Enterprise', users: 31, status: 'Active', joined: '2w ago' },
]

const activityFeed = [
  { icon: UserPlus, color: 'text-blue-500', msg: 'New user registered: james.wilson@fintechcorp.io', time: '3 min ago', org: 'FinTech Corp' },
  { icon: Building2, color: 'text-green-500', msg: 'Organization created: MedSecure Ltd (Professional plan)', time: '18 min ago', org: 'Platform' },
  { icon: Zap, color: 'text-yellow-500', msg: 'Global scan initiated: 172.16.0.0/16 across 3 orgs', time: '34 min ago', org: 'CloudNative IO' },
  { icon: BarChart3, color: 'text-primary', msg: 'Monthly compliance report generated for FinTech Corp', time: '1h ago', org: 'FinTech Corp' },
  { icon: Cloud, color: 'text-accent', msg: 'Cloud assessment completed: AWS prod-us-east-1', time: '2h ago', org: 'DataSafe Corp' },
  { icon: ShieldAlert, color: 'text-red-500', msg: 'Critical finding detected: SQL Injection in api.medsecure.io', time: '3h ago', org: 'MedSecure Ltd' },
  { icon: CheckCircle2, color: 'text-emerald-500', msg: 'Database backup completed successfully', time: '4h ago', org: 'Platform' },
]

const planColors: Record<string, string> = {
  Enterprise: 'bg-primary/10 text-primary border-primary/20',
  Professional: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  Business: 'bg-accent/10 text-accent border-accent/20',
  Starter: 'bg-muted text-muted-foreground border-border',
  Trial: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
}

const statusColors: Record<string, string> = {
  Active: 'bg-green-500/10 text-green-500',
  Trial: 'bg-yellow-500/10 text-yellow-500',
  Suspended: 'bg-red-500/10 text-red-500',
}

export default function AdminDashboardPage() {
  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">
              <BarChart3 className="w-4 h-4 text-primary-foreground" />
            </div>
            <h1 className="text-3xl font-bold text-foreground">Platform Dashboard</h1>
          </div>
          <p className="text-muted-foreground ml-11">Enterprise-wide metrics across all tenants</p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10 text-sm">Export Report</Button>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5 text-sm">Run Health Check</Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {kpis.map((kpi) => {
          const Icon = kpi.icon
          return (
            <Link key={kpi.title} href={kpi.href}>
              <Card className="bg-card border-foreground/10 hover:border-foreground/25 hover:shadow-md transition-all cursor-pointer group">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-xs font-medium text-muted-foreground">{kpi.title}</CardTitle>
                    <div className={`p-2 ${kpi.bg} rounded-lg`}>
                      <Icon className={`w-3.5 h-3.5 ${kpi.color}`} />
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-foreground">{kpi.value}</div>
                  <div className={`flex items-center gap-1 mt-1 text-xs font-medium ${kpi.trend === 'up' ? 'text-green-500' : 'text-red-500'}`}>
                    {kpi.trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                    {kpi.change} this month
                  </div>
                </CardContent>
              </Card>
            </Link>
          )
        })}
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Org & User Growth */}
        <Card className="bg-card border-foreground/10 lg:col-span-2">
          <CardHeader>
            <CardTitle>Organization & User Growth</CardTitle>
            <CardDescription>Platform growth over the last 6 months</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={orgGrowth}>
                <defs>
                  <linearGradient id="orgGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="oklch(0.52 0.26 264)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="oklch(0.52 0.26 264)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="userGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="month" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Legend />
                <Area type="monotone" dataKey="orgs" stroke="oklch(0.52 0.26 264)" strokeWidth={2} fill="url(#orgGrad)" name="Organizations" />
                <Area type="monotone" dataKey="users" stroke="#22c55e" strokeWidth={2} fill="url(#userGrad)" name="Users" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Severity Distribution */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
            <CardDescription>Platform-wide vulnerability breakdown</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityDist} cx="50%" cy="45%" innerRadius={52} outerRadius={78} paddingAngle={3} dataKey="value">
                  {severityDist.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Legend iconSize={8} formatter={(v) => <span className="text-xs text-muted-foreground">{v}</span>} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Revenue Trend */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Revenue Trend (MRR)</CardTitle>
            <CardDescription>Monthly recurring revenue over 6 months</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={revenue}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="month" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} tickFormatter={(v) => `$${(v/1000).toFixed(0)}k`} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} formatter={(v: any) => [`$${v.toLocaleString()}`, 'MRR']} />
                <Line type="monotone" dataKey="mrr" stroke="#10b981" strokeWidth={2.5} dot={{ fill: '#10b981', r: 4 }} name="MRR" />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Platform Usage */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Platform Usage</CardTitle>
            <CardDescription>Daily scans, reports and logins this week</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={platformUsage}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="day" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Bar dataKey="scans" fill="oklch(0.52 0.26 264)" name="Scans" radius={[3, 3, 0, 0]} />
                <Bar dataKey="reports" fill="oklch(0.48 0.22 280)" name="Reports" radius={[3, 3, 0, 0]} />
                <Bar dataKey="logins" fill="#22c55e" name="Logins" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Organizations */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Recent Organizations</CardTitle>
                <CardDescription>Latest tenant signups</CardDescription>
              </div>
              <Link href="/admin/organizations">
                <Button variant="ghost" size="sm" className="h-8 rounded-lg text-primary hover:bg-primary/10">
                  <ArrowRight className="w-3.5 h-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {recentOrgs.map((org) => (
              <div key={org.name} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center shrink-0">
                  <Building2 className="w-4 h-4 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{org.name}</p>
                  <p className="text-xs text-muted-foreground">{org.users} users · {org.joined}</p>
                </div>
                <span className={`text-xs font-medium px-2 py-0.5 rounded border shrink-0 ${planColors[org.plan]}`}>{org.plan}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Cloud Risk */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Cloud Risk Distribution</CardTitle>
                <CardDescription>By provider across all tenants</CardDescription>
              </div>
              <Link href="/admin/cloud">
                <Button variant="ghost" size="sm" className="h-8 rounded-lg text-primary hover:bg-primary/10">
                  <ArrowRight className="w-3.5 h-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            {cloudRisk.map((p) => (
              <div key={p.provider} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium text-foreground">{p.provider}</span>
                  <span className="text-xs text-muted-foreground">{p.accounts} accounts</span>
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-foreground/5 rounded-full overflow-hidden">
                      <div className="h-full bg-red-500 rounded-full" style={{ width: `${(p.critical / 100) * 100}%` }} />
                    </div>
                    <span className="text-xs text-red-500 w-14 text-right">{p.critical} crit</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-foreground/5 rounded-full overflow-hidden">
                      <div className="h-full bg-orange-500 rounded-full" style={{ width: `${(p.high / 250) * 100}%` }} />
                    </div>
                    <span className="text-xs text-orange-500 w-14 text-right">{p.high} high</span>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Activity Feed */}
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Activity Feed</CardTitle>
            <CardDescription>Recent platform events</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {activityFeed.map((item, i) => {
              const Icon = item.icon
              return (
                <div key={i} className="flex items-start gap-3">
                  <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${item.color}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-foreground leading-snug">{item.msg}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-muted-foreground">{item.time}</span>
                      <span className="text-[10px] text-muted-foreground">·</span>
                      <span className="text-[10px] text-primary">{item.org}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
