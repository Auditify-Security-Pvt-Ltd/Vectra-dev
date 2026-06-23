'use client'

import { useState } from 'react'
import { Search, StopCircle, RefreshCw, FileText, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

const allScans = [
  { id: 'SCN-1289', org: 'FinTech Corp', target: 'api.fintechcorp.io', type: 'Web App', status: 'Running', startedBy: 'James Wilson', duration: '42m', started: 'Today 16:20', findings: 0 },
  { id: 'SCN-1288', org: 'MedSecure Ltd', target: 'db-prod.medsecure.io', type: 'Web App', status: 'Completed', startedBy: 'Sarah Chen', duration: '2h 18m', started: 'Today 14:00', findings: 67 },
  { id: 'SCN-1287', org: 'DataSafe Corp', target: 'aws-prod-cluster', type: 'Cloud', status: 'Completed', startedBy: 'Ryan Torres', duration: '4h 5m', started: 'Today 11:45', findings: 89 },
  { id: 'SCN-1286', org: 'CloudNative IO', target: 'azure-dev-env', type: 'Cloud', status: 'Failed', startedBy: 'Marcus Davis', duration: '12m', started: 'Today 10:30', findings: 0 },
  { id: 'SCN-1285', org: 'Guardian Corp', target: 'vpn.guardiancorp.net', type: 'Network', status: 'Completed', startedBy: 'Noah Johnson', duration: '1h 44m', started: 'Today 09:00', findings: 11 },
  { id: 'SCN-1284', org: 'SecOps Co', target: '192.168.100.0/24', type: 'Network', status: 'Running', startedBy: 'Aisha Patel', duration: '28m', started: 'Today 16:35', findings: 0 },
  { id: 'SCN-1283', org: 'InfraShield GmbH', target: '10.0.0.0/8', type: 'Network', status: 'Completed', startedBy: 'Lucas Müller', duration: '5h 22m', started: 'Yesterday 22:00', findings: 52 },
  { id: 'SCN-1282', org: 'FinTech Corp', target: '10.12.0.0/16', type: 'Network', status: 'Queued', startedBy: 'James Wilson', duration: '—', started: '—', findings: 0 },
  { id: 'SCN-1281', org: 'Apex Security SG', target: 'auth.apexsec.sg', type: 'Web App', status: 'Completed', startedBy: 'Thomas Wu', duration: '1h 12m', started: 'Yesterday 18:00', findings: 14 },
  { id: 'SCN-1280', org: 'ZeroSec Labs', target: 'shop.zerosec.in', type: 'Web App', status: 'Completed', startedBy: 'Priya Sharma', duration: '58m', started: 'Yesterday 14:00', findings: 9 },
]

const statusColors: Record<string, string> = {
  Running: 'bg-blue-500/10 text-blue-500', Completed: 'bg-green-500/10 text-green-500',
  Failed: 'bg-red-500/10 text-red-500', Queued: 'bg-yellow-500/10 text-yellow-500',
}
const typeColors: Record<string, string> = {
  'Web App': 'bg-primary/10 text-primary', Network: 'bg-accent/10 text-accent',
  Cloud: 'bg-blue-500/10 text-blue-500',
}
const statuses = ['All', 'Running', 'Completed', 'Failed', 'Queued']

export default function AdminScansPage() {
  const [scans, setScans] = useState(allScans)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('All')

  const filtered = scans.filter(s =>
    (s.target.toLowerCase().includes(search.toLowerCase()) ||
     s.org.toLowerCase().includes(search.toLowerCase()) ||
     s.id.toLowerCase().includes(search.toLowerCase())) &&
    (statusFilter === 'All' || s.status === statusFilter)
  )

  const terminate = (id: string) => setScans(prev => prev.map(s => s.id === id ? { ...s, status: 'Failed' } : s))
  const restart = (id: string) => setScans(prev => prev.map(s => s.id === id ? { ...s, status: 'Queued', findings: 0, duration: '—' } : s))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Global Scan Monitoring</h1>
          <p className="text-muted-foreground mt-1">Real-time visibility into all scans across every organization</p>
        </div>
        <Button variant="outline" className="rounded-lg border-foreground/20 h-10"><Download className="w-4 h-4 mr-2" />Export</Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans', value: scans.length, color: 'text-foreground' },
          { label: 'Running', value: scans.filter(s => s.status === 'Running').length, color: 'text-blue-500' },
          { label: 'Completed', value: scans.filter(s => s.status === 'Completed').length, color: 'text-green-500' },
          { label: 'Total Findings', value: scans.reduce((a, s) => a + s.findings, 0), color: 'text-orange-500' },
        ].map(s => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search by ID, org, target..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        {statuses.map(s => (
          <Button key={s} size="sm" variant={statusFilter === s ? 'default' : 'outline'} onClick={() => setStatusFilter(s)}
            className={`rounded-lg h-10 ${statusFilter === s ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{s}</Button>
        ))}
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Platform Scans</CardTitle>
          <CardDescription>{filtered.length} scans</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Scan ID', 'Organization', 'Target', 'Type', 'Status', 'Started By', 'Duration', 'Findings', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(scan => (
                  <tr key={scan.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3 font-mono text-xs text-primary">{scan.id}</td>
                    <td className="py-3 px-3 text-sm text-foreground">{scan.org}</td>
                    <td className="py-3 px-3 text-sm font-medium text-foreground">{scan.target}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${typeColors[scan.type]}`}>{scan.type}</span></td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColors[scan.status]}`}>{scan.status}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{scan.startedBy}</td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{scan.duration}</td>
                    <td className="py-3 px-3">{scan.findings > 0 ? <span className="text-sm font-medium text-orange-500">{scan.findings}</span> : <span className="text-sm text-muted-foreground">—</span>}</td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1">
                        {scan.status === 'Running' && <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-red-500/10 hover:text-red-500" onClick={() => terminate(scan.id)}><StopCircle className="w-3.5 h-3.5" /></Button>}
                        {(scan.status === 'Failed' || scan.status === 'Completed') && <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-primary/10 hover:text-primary" onClick={() => restart(scan.id)}><RefreshCw className="w-3.5 h-3.5" /></Button>}
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-foreground/10"><FileText className="w-3.5 h-3.5" /></Button>
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
