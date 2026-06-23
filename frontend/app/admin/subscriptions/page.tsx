'use client'

import { useState } from 'react'
import { DollarSign, TrendingUp, Users, CreditCard, RefreshCw, ChevronUp, ChevronDown, X, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Legend } from 'recharts'

const subscriptions = [
  { id: 1, org: 'FinTech Corp', plan: 'Enterprise', seats: 24, mrr: 2499, nextBilling: 'Feb 12, 2026', status: 'Active', paymentMethod: 'Visa ••4242' },
  { id: 2, org: 'DataSafe Corp', plan: 'Enterprise', seats: 31, mrr: 2499, nextBilling: 'Feb 8, 2026', status: 'Active', paymentMethod: 'Mastercard ••9988' },
  { id: 3, org: 'Guardian Corp', plan: 'Enterprise', seats: 18, mrr: 2499, nextBilling: 'Feb 15, 2026', status: 'Active', paymentMethod: 'Visa ••7733' },
  { id: 4, org: 'SecOps Co', plan: 'Business', seats: 9, mrr: 1299, nextBilling: 'Feb 22, 2026', status: 'Active', paymentMethod: 'Amex ••0011' },
  { id: 5, org: 'SecureHub MX', plan: 'Business', seats: 7, mrr: 1299, nextBilling: 'Feb 5, 2026', status: 'Active', paymentMethod: 'Visa ••5566' },
  { id: 6, org: 'MedSecure Ltd', plan: 'Professional', seats: 8, mrr: 899, nextBilling: 'Feb 1, 2026', status: 'Active', paymentMethod: 'Mastercard ••3344' },
  { id: 7, org: 'InfraShield GmbH', plan: 'Professional', seats: 6, mrr: 899, nextBilling: 'Feb 28, 2026', status: 'Past Due', paymentMethod: 'Visa ••8877' },
  { id: 8, org: 'Apex Security SG', plan: 'Professional', seats: 11, mrr: 899, nextBilling: 'Feb 20, 2026', status: 'Active', paymentMethod: 'Visa ••2211' },
  { id: 9, org: 'CyberShield Inc', plan: 'Starter', seats: 3, mrr: 299, nextBilling: 'Feb 14, 2026', status: 'Active', paymentMethod: 'Mastercard ••4455' },
  { id: 10, org: 'ZeroSec Labs', plan: 'Starter', seats: 4, mrr: 299, nextBilling: 'Feb 10, 2026', status: 'Active', paymentMethod: 'Visa ••6611' },
  { id: 11, org: 'NetDefend GH', plan: 'Starter', seats: 2, mrr: 299, nextBilling: 'Feb 8, 2026', status: 'Cancelled', paymentMethod: '—' },
  { id: 12, org: 'CloudNative IO', plan: 'Trial', seats: 12, mrr: 0, nextBilling: 'Feb 3, 2026', status: 'Trial', paymentMethod: '—' },
]

const revenueHistory = [
  { month: 'Aug', mrr: 31200, arr: 374400 },
  { month: 'Sep', mrr: 34800, arr: 417600 },
  { month: 'Oct', mrr: 38500, arr: 462000 },
  { month: 'Nov', mrr: 41200, arr: 494400 },
  { month: 'Dec', mrr: 44800, arr: 537600 },
  { month: 'Jan', mrr: 48290, arr: 579480 },
]

const planRevenue = [
  { plan: 'Enterprise', revenue: 7497, accounts: 3 },
  { plan: 'Business', revenue: 2598, accounts: 2 },
  { plan: 'Professional', revenue: 2697, accounts: 3 },
  { plan: 'Starter', revenue: 598, accounts: 2 },
]

const planColors: Record<string, string> = {
  Enterprise: 'bg-primary/10 text-primary border-primary/20',
  Business: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  Professional: 'bg-accent/10 text-accent border-accent/20',
  Starter: 'bg-muted text-muted-foreground border-border',
  Trial: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
}

const statusColors: Record<string, string> = {
  Active: 'bg-green-500/10 text-green-500',
  Trial: 'bg-yellow-500/10 text-yellow-500',
  'Past Due': 'bg-orange-500/10 text-orange-500',
  Cancelled: 'bg-red-500/10 text-red-500',
}

export default function AdminSubscriptionsPage() {
  const [subs] = useState(subscriptions)

  const mrr = subs.filter(s => s.status === 'Active').reduce((a, s) => a + s.mrr, 0)
  const arr = mrr * 12
  const activePlans = subs.filter(s => s.status === 'Active').length
  const trials = subs.filter(s => s.status === 'Trial').length
  const enterprise = subs.filter(s => s.plan === 'Enterprise' && s.status === 'Active').length
  const pastDue = subs.filter(s => s.status === 'Past Due').length

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Subscriptions & Billing</h1>
          <p className="text-muted-foreground mt-1">SaaS revenue management and subscription lifecycle</p>
        </div>
        <Button variant="outline" className="rounded-lg border-foreground/20 h-10">
          <Download className="w-4 h-4 mr-2" />Export Billing Report
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: 'MRR', value: `$${mrr.toLocaleString()}`, color: 'text-emerald-500', icon: DollarSign, bg: 'bg-emerald-500/10' },
          { label: 'ARR', value: `$${(arr/1000).toFixed(0)}k`, color: 'text-emerald-500', icon: TrendingUp, bg: 'bg-emerald-500/10' },
          { label: 'Active Plans', value: activePlans, color: 'text-green-500', icon: CreditCard, bg: 'bg-green-500/10' },
          { label: 'Trials', value: trials, color: 'text-yellow-500', icon: Users, bg: 'bg-yellow-500/10' },
          { label: 'Enterprise', value: enterprise, color: 'text-primary', icon: CreditCard, bg: 'bg-primary/10' },
          { label: 'Past Due', value: pastDue, color: 'text-orange-500', icon: CreditCard, bg: 'bg-orange-500/10' },
        ].map(s => {
          const Icon = s.icon
          return (
            <Card key={s.label} className="bg-card border-foreground/10">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                  <div className={`p-1.5 ${s.bg} rounded`}><Icon className={`w-3 h-3 ${s.color}`} /></div>
                </div>
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>MRR Growth</CardTitle>
            <CardDescription>Monthly recurring revenue over 6 months</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={revenueHistory}>
                <defs>
                  <linearGradient id="mrrGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="month" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} tickFormatter={v => `$${(v/1000).toFixed(0)}k`} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} formatter={(v: any) => [`$${v.toLocaleString()}`, 'MRR']} />
                <Area type="monotone" dataKey="mrr" stroke="#10b981" strokeWidth={2} fill="url(#mrrGrad)" name="MRR" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-card border-foreground/10">
          <CardHeader>
            <CardTitle>Revenue by Plan</CardTitle>
            <CardDescription>MRR contribution per subscription tier</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={planRevenue} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis type="number" stroke="rgba(128,128,128,0.5)" fontSize={12} tickFormatter={v => `$${v}`} />
                <YAxis type="category" dataKey="plan" stroke="rgba(128,128,128,0.5)" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} formatter={(v: any) => [`$${v}`, 'MRR']} />
                <Bar dataKey="revenue" fill="oklch(0.52 0.26 264)" radius={[0, 4, 4, 0]} name="MRR" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Subscriptions Table */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Subscriptions</CardTitle>
          <CardDescription>{subs.length} subscriptions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Organization', 'Plan', 'Seats', 'MRR', 'Next Billing', 'Payment', 'Status', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {subs.map(sub => (
                  <tr key={sub.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3 text-sm font-medium text-foreground">{sub.org}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded border ${planColors[sub.plan]}`}>{sub.plan}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{sub.seats}</td>
                    <td className="py-3 px-3 text-sm font-medium text-emerald-500">{sub.mrr > 0 ? `$${sub.mrr.toLocaleString()}` : '—'}</td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{sub.nextBilling}</td>
                    <td className="py-3 px-3 text-xs font-mono text-muted-foreground">{sub.paymentMethod}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColors[sub.status]}`}>{sub.status}</span></td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1">
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-primary/10 hover:text-primary" title="Upgrade"><ChevronUp className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-foreground/10" title="Downgrade"><ChevronDown className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-foreground/10" title="Renew"><RefreshCw className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-destructive/10 hover:text-destructive" title="Cancel"><X className="w-3.5 h-3.5" /></Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
