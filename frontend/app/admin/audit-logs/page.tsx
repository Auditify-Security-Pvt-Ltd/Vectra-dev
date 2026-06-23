'use client'

import { useState } from 'react'
import { Search, Download, Calendar, Building2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

const allLogs = [
  { id: 1, timestamp: '2026-01-18 16:42:31', user: 'james.wilson@fintechcorp.io', action: 'USER_LOGIN', resource: 'Auth', ip: '203.0.113.42', org: 'FinTech Corp', severity: 'Info' },
  { id: 2, timestamp: '2026-01-18 16:40:18', user: 'admin@vectra.io', action: 'ORG_PLAN_UPGRADED', resource: 'FinTech Corp → Enterprise', ip: '127.0.0.1', org: 'Platform', severity: 'Info' },
  { id: 3, timestamp: '2026-01-18 16:38:14', user: 'sarah.chen@medsecure.io', action: 'SCAN_CREATED', resource: 'Scan SCN-1288', ip: '198.51.100.11', org: 'MedSecure Ltd', severity: 'Info' },
  { id: 4, timestamp: '2026-01-18 16:35:02', user: 'admin@vectra.io', action: 'USER_SUSPENDED', resource: 'User lucas.muller@infrashield.de', ip: '127.0.0.1', org: 'Platform', severity: 'Warning' },
  { id: 5, timestamp: '2026-01-18 16:31:48', user: 'noah.johnson@guardiancorp.net', action: 'FINDING_EXPORTED', resource: 'Report SCN-1285', ip: '192.0.2.88', org: 'Guardian Corp', severity: 'Info' },
  { id: 6, timestamp: '2026-01-18 16:28:22', user: 'unknown', action: 'LOGIN_FAILED', resource: 'Auth /auth/admin-login', ip: '45.33.32.156', org: 'External', severity: 'Critical' },
  { id: 7, timestamp: '2026-01-18 16:22:09', user: 'ryan.torres@datasafe.com', action: 'CLOUD_ASSESSMENT_STARTED', resource: 'AWS prod-us-east-1', ip: '203.0.113.88', org: 'DataSafe Corp', severity: 'Info' },
  { id: 8, timestamp: '2026-01-18 16:18:45', user: 'admin@vectra.io', action: 'INTEGRATION_UPDATED', resource: 'GitHub Integration', ip: '127.0.0.1', org: 'Platform', severity: 'Info' },
  { id: 9, timestamp: '2026-01-18 16:14:33', user: 'aisha.patel@secopsco.io', action: 'SCAN_TERMINATED', resource: 'Scan SCN-1284', ip: '203.0.113.42', org: 'SecOps Co', severity: 'Warning' },
  { id: 10, timestamp: '2026-01-18 16:10:11', user: 'admin@vectra.io', action: 'ORG_CREATED', resource: 'Org: MedSecure Ltd', ip: '127.0.0.1', org: 'Platform', severity: 'Info' },
  { id: 11, timestamp: '2026-01-18 16:06:55', user: 'thomas.wu@apexsec.sg', action: 'REPORT_GENERATED', resource: 'Monthly Compliance Report', ip: '198.51.100.77', org: 'Apex Security SG', severity: 'Info' },
  { id: 12, timestamp: '2026-01-18 16:02:40', user: 'unknown', action: 'BRUTE_FORCE_DETECTED', resource: 'Auth /auth/admin-login', ip: '104.21.0.99', org: 'External', severity: 'Critical' },
  { id: 13, timestamp: '2026-01-18 15:58:19', user: 'marcus.davis@cloudnative.io', action: 'API_KEY_GENERATED', resource: 'API Keys', ip: '192.0.2.55', org: 'CloudNative IO', severity: 'Info' },
  { id: 14, timestamp: '2026-01-18 15:54:02', user: 'admin@vectra.io', action: 'SETTINGS_UPDATED', resource: 'Platform Security Settings', ip: '127.0.0.1', org: 'Platform', severity: 'Info' },
  { id: 15, timestamp: '2026-01-18 15:50:44', user: 'priya.sharma@zerosec.in', action: 'FINDING_STATUS_CHANGED', resource: 'CVE-2024-0112 → Resolved', ip: '203.0.113.61', org: 'ZeroSec Labs', severity: 'Info' },
]

const severityConfig: Record<string, string> = {
  Info: 'bg-blue-500/10 text-blue-500', Warning: 'bg-yellow-500/10 text-yellow-500', Critical: 'bg-red-500/10 text-red-500',
}
const actionConfig: Record<string, string> = {
  USER_LOGIN: 'bg-green-500/10 text-green-500', LOGIN_FAILED: 'bg-red-500/10 text-red-500',
  BRUTE_FORCE_DETECTED: 'bg-red-500/10 text-red-500', USER_SUSPENDED: 'bg-orange-500/10 text-orange-500',
  SCAN_TERMINATED: 'bg-orange-500/10 text-orange-500', ORG_PLAN_UPGRADED: 'bg-primary/10 text-primary',
  ORG_CREATED: 'bg-green-500/10 text-green-500',
}
const severities = ['All', 'Info', 'Warning', 'Critical']

export default function AdminAuditLogsPage() {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('All')
  const [orgFilter, setOrgFilter] = useState('All Orgs')

  const orgs = ['All Orgs', 'Platform', ...Array.from(new Set(allLogs.filter(l => l.org !== 'Platform').map(l => l.org)))]

  const filtered = allLogs.filter(l =>
    (l.user.toLowerCase().includes(search.toLowerCase()) ||
     l.action.toLowerCase().includes(search.toLowerCase()) ||
     l.resource.toLowerCase().includes(search.toLowerCase()) ||
     l.ip.includes(search)) &&
    (sevFilter === 'All' || l.severity === sevFilter) &&
    (orgFilter === 'All Orgs' || l.org === orgFilter)
  )

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Audit Logs</h1>
          <p className="text-muted-foreground mt-1">Complete platform event trail across all organizations</p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10"><Download className="w-4 h-4 mr-2" />Export CSV</Button>
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10"><Download className="w-4 h-4 mr-2" />Export PDF</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Events', value: allLogs.length, color: 'text-foreground' },
          { label: 'Critical', value: allLogs.filter(l => l.severity === 'Critical').length, color: 'text-red-500' },
          { label: 'Warnings', value: allLogs.filter(l => l.severity === 'Warning').length, color: 'text-yellow-500' },
          { label: 'Unique IPs', value: new Set(allLogs.map(l => l.ip)).size, color: 'text-blue-500' },
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
          <Input placeholder="Search by user, action, resource, IP..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        {severities.map(s => (
          <Button key={s} size="sm" variant={sevFilter === s ? 'default' : 'outline'} onClick={() => setSevFilter(s)}
            className={`rounded-lg h-10 ${sevFilter === s ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{s}</Button>
        ))}
        <select value={orgFilter} onChange={e => setOrgFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {orgs.map(o => <option key={o}>{o}</option>)}
        </select>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Platform Event Log</CardTitle>
          <CardDescription>{filtered.length} events</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Timestamp', 'User', 'Organization', 'Action', 'Resource', 'IP', 'Severity'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(log => (
                  <tr key={log.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3 font-mono text-xs text-muted-foreground">{log.timestamp}</td>
                    <td className="py-3 px-3 text-xs text-foreground">{log.user}</td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <Building2 className="w-3 h-3 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">{log.org}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded font-mono ${actionConfig[log.action] || 'bg-foreground/5 text-foreground'}`}>{log.action}</span>
                    </td>
                    <td className="py-3 px-3 text-xs text-muted-foreground max-w-48 truncate">{log.resource}</td>
                    <td className="py-3 px-3 font-mono text-xs text-muted-foreground">{log.ip}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${severityConfig[log.severity]}`}>{log.severity}</span></td>
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
