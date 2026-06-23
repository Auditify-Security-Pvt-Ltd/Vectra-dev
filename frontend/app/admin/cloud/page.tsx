'use client'

import { useState } from 'react'
import { Plus, Cloud, Play, RefreshCw, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

const cloudAccounts = [
  { id: 1, provider: 'AWS', name: 'prod-us-east-1', accountId: '123456789012', region: 'us-east-1', org: 'FinTech Corp', securityScore: 78, critical: 12, high: 34, lastAssessed: '2h ago', status: 'Connected' },
  { id: 2, provider: 'AWS', name: 'dev-us-west-2', accountId: '234567890123', region: 'us-west-2', org: 'DataSafe Corp', securityScore: 91, critical: 3, high: 12, lastAssessed: '6h ago', status: 'Connected' },
  { id: 3, provider: 'AWS', name: 'staging-eu-west-1', accountId: '345678901234', region: 'eu-west-1', org: 'InfraShield GmbH', securityScore: 65, critical: 18, high: 44, lastAssessed: '1d ago', status: 'Connected' },
  { id: 4, provider: 'AWS', name: 'analytics-us-east-2', accountId: '456789012345', region: 'us-east-2', org: 'Guardian Corp', securityScore: 55, critical: 27, high: 61, lastAssessed: '3d ago', status: 'Error' },
  { id: 5, provider: 'AWS', name: 'backup-ap-southeast-1', accountId: '567890123456', region: 'ap-southeast-1', org: 'SecOps Co', securityScore: 88, critical: 2, high: 9, lastAssessed: '4h ago', status: 'Connected' },
  { id: 6, provider: 'AWS', name: 'dr-us-west-1', accountId: '678901234567', region: 'us-west-1', org: 'MedSecure Ltd', securityScore: 82, critical: 4, high: 17, lastAssessed: '3h ago', status: 'Connected' },
  { id: 7, provider: 'Azure', name: 'azure-prod-eastus', accountId: 'sub-a1b2c3d4', region: 'East US', org: 'CloudNative IO', securityScore: 71, critical: 8, high: 24, lastAssessed: '3h ago', status: 'Connected' },
  { id: 8, provider: 'Azure', name: 'azure-dev-westus', accountId: 'sub-b2c3d4e5', region: 'West US', org: 'Apex Security SG', securityScore: 79, critical: 5, high: 19, lastAssessed: '1d ago', status: 'Connected' },
  { id: 9, provider: 'Azure', name: 'azure-staging-northeu', accountId: 'sub-c3d4e5f6', region: 'North Europe', org: 'ZeroSec Labs', securityScore: 0, critical: 0, high: 0, lastAssessed: 'Never', status: 'Disconnected' },
  { id: 10, provider: 'Azure', name: 'azure-analytics', accountId: 'sub-d4e5f6g7', region: 'Central US', org: 'SecureHub MX', securityScore: 84, critical: 3, high: 11, lastAssessed: '5h ago', status: 'Connected' },
  { id: 11, provider: 'Azure', name: 'azure-test-westeu', accountId: 'sub-e5f6g7h8', region: 'West Europe', org: 'Guardian Corp', securityScore: 67, critical: 9, high: 28, lastAssessed: '2h ago', status: 'Connected' },
  { id: 12, provider: 'GCP', name: 'gcp-prod-project', accountId: 'proj-alpha-123', region: 'us-central1', org: 'DataSafe Corp', securityScore: 62, critical: 17, high: 42, lastAssessed: '1h ago', status: 'Connected' },
  { id: 13, provider: 'GCP', name: 'gcp-dev-project', accountId: 'proj-beta-456', region: 'us-east1', org: 'FinTech Corp', securityScore: 76, critical: 7, high: 21, lastAssessed: '8h ago', status: 'Connected' },
  { id: 14, provider: 'GCP', name: 'gcp-ml-cluster', accountId: 'proj-gamma-789', region: 'us-west1', org: 'Guardian Corp', securityScore: 43, critical: 24, high: 58, lastAssessed: '4h ago', status: 'Error' },
  { id: 15, provider: 'GCP', name: 'gcp-analytics', accountId: 'proj-delta-012', region: 'europe-west1', org: 'SecOps Co', securityScore: 90, critical: 1, high: 6, lastAssessed: '2d ago', status: 'Connected' },
  { id: 16, provider: 'GCP', name: 'gcp-backup', accountId: 'proj-epsilon-345', region: 'asia-east1', org: 'MedSecure Ltd', securityScore: 85, critical: 2, high: 8, lastAssessed: '3d ago', status: 'Connected' },
]

const riskByProvider = [
  { provider: 'AWS', critical: cloudAccounts.filter(a => a.provider === 'AWS').reduce((s, a) => s + a.critical, 0), high: cloudAccounts.filter(a => a.provider === 'AWS').reduce((s, a) => s + a.high, 0) },
  { provider: 'Azure', critical: cloudAccounts.filter(a => a.provider === 'Azure').reduce((s, a) => s + a.critical, 0), high: cloudAccounts.filter(a => a.provider === 'Azure').reduce((s, a) => s + a.high, 0) },
  { provider: 'GCP', critical: cloudAccounts.filter(a => a.provider === 'GCP').reduce((s, a) => s + a.critical, 0), high: cloudAccounts.filter(a => a.provider === 'GCP').reduce((s, a) => s + a.high, 0) },
]

const providerColors: Record<string, string> = {
  AWS: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  Azure: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  GCP: 'bg-green-500/10 text-green-500 border-green-500/20',
}
const statusColors: Record<string, string> = {
  Connected: 'bg-green-500/10 text-green-500', Disconnected: 'bg-muted text-muted-foreground', Error: 'bg-red-500/10 text-red-500',
}

export default function AdminCloudPage() {
  const [accounts, setAccounts] = useState(cloudAccounts)
  const [providerFilter, setProviderFilter] = useState('All')
  const [connectOpen, setConnectOpen] = useState(false)

  const filtered = accounts.filter(a => providerFilter === 'All' || a.provider === providerFilter)
  const disconnect = (id: number) => setAccounts(prev => prev.map(a => a.id === id ? { ...a, status: 'Disconnected' } : a))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Cloud Account Management</h1>
          <p className="text-muted-foreground mt-1">16 cloud accounts across AWS, Azure, and GCP — all tenant organizations</p>
        </div>
        <Dialog open={connectOpen} onOpenChange={setConnectOpen}>
          <DialogTrigger asChild>
            <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5">
              <Plus className="w-4 h-4 mr-2" />Connect Account
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-foreground/10">
            <DialogHeader>
              <DialogTitle>Connect Cloud Account</DialogTitle>
              <DialogDescription>Link a cloud provider account to the platform</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label>Cloud Provider</Label>
                <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                  <option>AWS</option><option>Azure</option><option>GCP</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Organization</Label>
                <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                  <option>FinTech Corp</option><option>MedSecure Ltd</option><option>DataSafe Corp</option>
                </select>
              </div>
              <div className="space-y-2"><Label>Account Name</Label><Input placeholder="prod-us-east-1" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
              <div className="space-y-2"><Label>Account ID</Label><Input placeholder="123456789012" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConnectOpen(false)} className="rounded-lg border-foreground/20">Cancel</Button>
              <Button className="bg-primary hover:bg-primary/90 rounded-lg" onClick={() => setConnectOpen(false)}>Connect</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Provider summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {['AWS', 'Azure', 'GCP'].map(p => {
          const pAccounts = accounts.filter(a => a.provider === p)
          const totalCrit = pAccounts.reduce((s, a) => s + a.critical, 0)
          const connected = pAccounts.filter(a => a.status === 'Connected').length
          return (
            <Card key={p} className="bg-card border-foreground/10">
              <CardContent className="pt-5 pb-4">
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-10 h-10 rounded-xl border flex items-center justify-center ${providerColors[p]}`}>
                    <Cloud className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-bold text-foreground">{p}</p>
                    <p className="text-xs text-muted-foreground">{connected}/{pAccounts.length} connected</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-2.5 bg-foreground/5 rounded-lg"><p className="text-xs text-muted-foreground">Accounts</p><p className="text-lg font-bold text-foreground">{pAccounts.length}</p></div>
                  <div className="p-2.5 bg-red-500/5 rounded-lg"><p className="text-xs text-muted-foreground">Critical</p><p className="text-lg font-bold text-red-500">{totalCrit}</p></div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Chart */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Risk by Cloud Provider</CardTitle>
          <CardDescription>Critical and high findings distributed across AWS, Azure, GCP</CardDescription>
        </CardHeader>
        <CardContent className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={riskByProvider}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="provider" stroke="rgba(128,128,128,0.5)" fontSize={12} />
              <YAxis stroke="rgba(128,128,128,0.5)" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: 'var(--card)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
              <Bar dataKey="critical" fill="#ef4444" name="Critical" radius={[4, 4, 0, 0]} />
              <Bar dataKey="high" fill="#f97316" name="High" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Provider filter */}
      <div className="flex gap-3">
        {['All', 'AWS', 'Azure', 'GCP'].map(p => (
          <Button key={p} size="sm" variant={providerFilter === p ? 'default' : 'outline'} onClick={() => setProviderFilter(p)}
            className={`rounded-lg h-9 ${providerFilter === p ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{p}</Button>
        ))}
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Connected Cloud Accounts</CardTitle>
          <CardDescription>{filtered.length} accounts</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Account', 'Provider', 'Organization', 'Region', 'Sec. Score', 'Critical', 'High', 'Status', 'Last Assessed', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(acc => (
                  <tr key={acc.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3">
                      <p className="text-sm font-medium text-foreground">{acc.name}</p>
                      <p className="text-xs font-mono text-muted-foreground">{acc.accountId}</p>
                    </td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded border ${providerColors[acc.provider]}`}>{acc.provider}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{acc.org}</td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{acc.region}</td>
                    <td className="py-3 px-3">
                      {acc.securityScore > 0 ? (
                        <span className={`text-sm font-bold ${acc.securityScore >= 80 ? 'text-green-500' : acc.securityScore >= 65 ? 'text-yellow-500' : 'text-red-500'}`}>{acc.securityScore}</span>
                      ) : <span className="text-sm text-muted-foreground">—</span>}
                    </td>
                    <td className="py-3 px-3">{acc.critical > 0 ? <span className="text-sm font-bold text-red-500">{acc.critical}</span> : <span className="text-sm text-muted-foreground">—</span>}</td>
                    <td className="py-3 px-3">{acc.high > 0 ? <span className="text-sm font-medium text-orange-500">{acc.high}</span> : <span className="text-sm text-muted-foreground">—</span>}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColors[acc.status]}`}>{acc.status}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{acc.lastAssessed}</td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1">
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-primary/10 hover:text-primary" title="Run Assessment"><Play className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-foreground/10" title="Refresh"><RefreshCw className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-destructive/10 hover:text-destructive" title="Disconnect" onClick={() => disconnect(acc.id)}><Trash2 className="w-3.5 h-3.5" /></Button>
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
