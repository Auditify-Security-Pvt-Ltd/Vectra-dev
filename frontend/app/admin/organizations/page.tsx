'use client'

import { useState } from 'react'
import { Search, Plus, Building2, MoreHorizontal, Eye, ShieldOff, TrendingUp, TrendingDown, Trash2, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'

const initOrgs = [
  { id: 1, name: 'FinTech Corp', domain: 'fintechcorp.io', plan: 'Enterprise', users: 24, assets: 412, scans: 184, findings: 892, created: 'Nov 12, 2024', status: 'Active', mrr: 2499 },
  { id: 2, name: 'MedSecure Ltd', domain: 'medsecure.io', plan: 'Professional', users: 8, assets: 127, scans: 62, findings: 341, created: 'Dec 1, 2024', status: 'Active', mrr: 899 },
  { id: 3, name: 'CloudNative IO', domain: 'cloudnative.io', plan: 'Business', users: 12, assets: 228, scans: 97, findings: 524, created: 'Jan 3, 2025', status: 'Trial', mrr: 0 },
  { id: 4, name: 'CyberShield Inc', domain: 'cybershield.io', plan: 'Starter', users: 3, assets: 44, scans: 21, findings: 87, created: 'Jan 14, 2025', status: 'Active', mrr: 299 },
  { id: 5, name: 'DataSafe Corp', domain: 'datasafe.com', plan: 'Enterprise', users: 31, assets: 648, scans: 312, findings: 1247, created: 'Sep 8, 2024', status: 'Active', mrr: 2499 },
  { id: 6, name: 'SecOps Co', domain: 'secopsco.io', plan: 'Business', users: 9, assets: 188, scans: 74, findings: 412, created: 'Oct 22, 2024', status: 'Active', mrr: 1299 },
  { id: 7, name: 'InfraShield GmbH', domain: 'infrashield.de', plan: 'Professional', users: 6, assets: 94, scans: 48, findings: 218, created: 'Nov 30, 2024', status: 'Suspended', mrr: 899 },
  { id: 8, name: 'ZeroSec Labs', domain: 'zerosec.in', plan: 'Starter', users: 4, assets: 52, scans: 28, findings: 134, created: 'Dec 10, 2024', status: 'Active', mrr: 299 },
  { id: 9, name: 'Guardian Corp', domain: 'guardiancorp.net', plan: 'Enterprise', users: 18, assets: 298, scans: 142, findings: 678, created: 'Aug 15, 2024', status: 'Active', mrr: 2499 },
  { id: 10, name: 'SecureHub MX', domain: 'securehub.mx', plan: 'Business', users: 7, assets: 112, scans: 55, findings: 287, created: 'Oct 5, 2024', status: 'Active', mrr: 1299 },
  { id: 11, name: 'Apex Security SG', domain: 'apexsecurity.sg', plan: 'Professional', users: 11, assets: 165, scans: 78, findings: 398, created: 'Sep 20, 2024', status: 'Active', mrr: 899 },
  { id: 12, name: 'NetDefend GH', domain: 'netdefend.gh', plan: 'Starter', users: 2, assets: 28, scans: 12, findings: 54, created: 'Jan 8, 2025', status: 'Inactive', mrr: 299 },
]

const planConfig: Record<string, { badge: string; tier: number }> = {
  Enterprise: { badge: 'bg-primary/10 text-primary border-primary/20', tier: 4 },
  Business: { badge: 'bg-blue-500/10 text-blue-500 border-blue-500/20', tier: 3 },
  Professional: { badge: 'bg-accent/10 text-accent border-accent/20', tier: 2 },
  Starter: { badge: 'bg-muted text-muted-foreground border-border', tier: 1 },
}

const statusConfig: Record<string, string> = {
  Active: 'bg-green-500/10 text-green-500',
  Trial: 'bg-yellow-500/10 text-yellow-500',
  Suspended: 'bg-red-500/10 text-red-500',
  Inactive: 'bg-muted text-muted-foreground',
}

const plans = ['All Plans', 'Enterprise', 'Business', 'Professional', 'Starter']
const statuses = ['All Statuses', 'Active', 'Trial', 'Suspended', 'Inactive']

export default function AdminOrgsPage() {
  const [orgs, setOrgs] = useState(initOrgs)
  const [search, setSearch] = useState('')
  const [planFilter, setPlanFilter] = useState('All Plans')
  const [statusFilter, setStatusFilter] = useState('All Statuses')
  const [createOpen, setCreateOpen] = useState(false)

  const filtered = orgs.filter(o =>
    (o.name.toLowerCase().includes(search.toLowerCase()) ||
     o.domain.toLowerCase().includes(search.toLowerCase())) &&
    (planFilter === 'All Plans' || o.plan === planFilter) &&
    (statusFilter === 'All Statuses' || o.status === statusFilter)
  )

  const toggleSuspend = (id: number) =>
    setOrgs(prev => prev.map(o => o.id === id ? { ...o, status: o.status === 'Suspended' ? 'Active' : 'Suspended' } : o))

  const totalMRR = orgs.filter(o => o.status === 'Active').reduce((acc, o) => acc + o.mrr, 0)
  const enterpriseCount = orgs.filter(o => o.plan === 'Enterprise').length
  const trialCount = orgs.filter(o => o.status === 'Trial').length
  const activeCount = orgs.filter(o => o.status === 'Active').length

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Organizations</h1>
          <p className="text-muted-foreground mt-1">Manage all tenant organizations on the Vectra platform</p>
        </div>
        <div className="flex gap-3">
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5">
                <Plus className="w-4 h-4 mr-2" />New Organization
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-card border-foreground/10">
              <DialogHeader>
                <DialogTitle>Create Organization</DialogTitle>
                <DialogDescription>Onboard a new tenant organization</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-2"><Label>Organization Name</Label><Input placeholder="Acme Corp" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                <div className="space-y-2"><Label>Primary Domain</Label><Input placeholder="acmecorp.io" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                <div className="space-y-2"><Label>Admin Email</Label><Input type="email" placeholder="admin@acmecorp.io" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                <div className="space-y-2">
                  <Label>Subscription Plan</Label>
                  <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                    <option>Starter</option><option>Professional</option><option>Business</option><option>Enterprise</option>
                  </select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateOpen(false)} className="rounded-lg border-foreground/20">Cancel</Button>
                <Button className="bg-primary hover:bg-primary/90 rounded-lg" onClick={() => setCreateOpen(false)}>Create</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Orgs', value: orgs.length, color: 'text-foreground' },
          { label: 'Active', value: activeCount, color: 'text-green-500' },
          { label: 'Enterprise', value: enterpriseCount, color: 'text-primary' },
          { label: 'Trials', value: trialCount, color: 'text-yellow-500' },
        ].map(s => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search organizations, domains..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        <select value={planFilter} onChange={e => setPlanFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {plans.map(p => <option key={p}>{p}</option>)}
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {statuses.map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      {/* Table */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Organizations</CardTitle>
          <CardDescription>{filtered.length} organizations · Total MRR: ${totalMRR.toLocaleString()}/mo</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Organization', 'Plan', 'Users', 'Assets', 'Scans', 'Findings', 'MRR', 'Status', 'Created', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(org => (
                  <tr key={org.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center shrink-0">
                          <Building2 className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-foreground">{org.name}</p>
                          <p className="text-xs text-muted-foreground">{org.domain}</p>
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded border ${planConfig[org.plan]?.badge}`}>{org.plan}</span></td>
                    <td className="py-3 px-3 text-sm text-foreground">{org.users}</td>
                    <td className="py-3 px-3 text-sm text-foreground">{org.assets.toLocaleString()}</td>
                    <td className="py-3 px-3 text-sm text-foreground">{org.scans}</td>
                    <td className="py-3 px-3 text-sm text-orange-500 font-medium">{org.findings.toLocaleString()}</td>
                    <td className="py-3 px-3 text-sm font-medium text-emerald-500">${org.mrr > 0 ? `${org.mrr.toLocaleString()}/mo` : '—'}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusConfig[org.status]}`}>{org.status}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{org.created}</td>
                    <td className="py-3 px-3">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg hover:bg-foreground/10">
                            <MoreHorizontal className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="bg-card border-foreground/10 rounded-lg w-48">
                          <DropdownMenuItem className="cursor-pointer rounded-md"><Eye className="w-3.5 h-3.5 mr-2" />View Details</DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md"><TrendingUp className="w-3.5 h-3.5 mr-2" />Upgrade Plan</DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md"><TrendingDown className="w-3.5 h-3.5 mr-2" />Downgrade Plan</DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md"><Users className="w-3.5 h-3.5 mr-2" />Impersonate Admin</DropdownMenuItem>
                          <DropdownMenuSeparator className="bg-foreground/10" />
                          <DropdownMenuItem className="cursor-pointer rounded-md" onClick={() => toggleSuspend(org.id)}>
                            <ShieldOff className="w-3.5 h-3.5 mr-2" />{org.status === 'Suspended' ? 'Activate' : 'Suspend'}
                          </DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md text-destructive focus:text-destructive focus:bg-destructive/10">
                            <Trash2 className="w-3.5 h-3.5 mr-2" />Reset Organization
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
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
