'use client'

import { useState } from 'react'
import { Search, Download, UserCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

const allFindings = [
  { id: 1, title: 'SQL Injection in Payment API', severity: 'Critical', org: 'FinTech Corp', asset: 'api.fintechcorp.io', cve: 'CVE-2024-0112', status: 'Open', analyst: 'James Wilson' },
  { id: 2, title: 'Unauthenticated Patient Data Access', severity: 'Critical', org: 'MedSecure Ltd', asset: 'db-prod.medsecure.io', cve: 'CVE-2024-0356', status: 'In Review', analyst: 'Sarah Chen' },
  { id: 3, title: 'Exposed S3 Bucket (PII)', severity: 'Critical', org: 'DataSafe Corp', asset: 'aws-prod-cluster', cve: 'CVE-2024-0478', status: 'In Review', analyst: 'Ryan Torres' },
  { id: 4, title: 'Remote Code Execution via Deserialization', severity: 'Critical', org: 'Guardian Corp', asset: 'gcp-ml-cluster', cve: 'CVE-2024-0741', status: 'Open', analyst: 'Unassigned' },
  { id: 5, title: 'Weak TLS 1.0 Configuration', severity: 'High', org: 'InfraShield GmbH', asset: '10.0.0.0/8', cve: 'CVE-2024-0231', status: 'Open', analyst: 'Lucas Müller' },
  { id: 6, title: 'Directory Traversal Vulnerability', severity: 'High', org: 'SecOps Co', asset: '192.168.100.0/24', cve: 'CVE-2024-0512', status: 'Resolved', analyst: 'Aisha Patel' },
  { id: 7, title: 'Leaked API Keys in Git Repository', severity: 'Critical', org: 'CloudNative IO', asset: 'azure-dev-env', cve: 'CVE-2024-0633', status: 'Open', analyst: 'Unassigned' },
  { id: 8, title: 'Outdated Struts Framework', severity: 'High', org: 'Apex Security SG', asset: 'auth.apexsec.sg', cve: 'CVE-2023-5678', status: 'In Review', analyst: 'Thomas Wu' },
  { id: 9, title: 'Insecure CORS Policy', severity: 'Medium', org: 'ZeroSec Labs', asset: 'shop.zerosec.in', cve: 'CVE-2023-9012', status: 'Open', analyst: 'Priya Sharma' },
  { id: 10, title: 'CSRF Token Missing on Admin Panel', severity: 'Medium', org: 'FinTech Corp', asset: 'api.fintechcorp.io', cve: 'CVE-2023-1234', status: 'Resolved', analyst: 'James Wilson' },
  { id: 11, title: 'Sensitive Data in Server Logs', severity: 'Medium', org: 'MedSecure Ltd', asset: 'db-prod.medsecure.io', cve: 'CVE-2023-3456', status: 'Open', analyst: 'Unassigned' },
  { id: 12, title: 'Open Redirect on Login Page', severity: 'Low', org: 'SecureHub MX', asset: 'securehub.mx', cve: 'CVE-2023-7890', status: 'Open', analyst: 'Sofia Reyes' },
]

const severityConfig: Record<string, { badge: string; bar: string }> = {
  Critical: { badge: 'bg-red-500/10 text-red-500 border-red-500/20', bar: 'bg-red-500' },
  High: { badge: 'bg-orange-500/10 text-orange-500 border-orange-500/20', bar: 'bg-orange-500' },
  Medium: { badge: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20', bar: 'bg-yellow-500' },
  Low: { badge: 'bg-blue-500/10 text-blue-500 border-blue-500/20', bar: 'bg-blue-500' },
}

const statusColors: Record<string, string> = {
  Open: 'bg-yellow-500/10 text-yellow-500', 'In Review': 'bg-blue-500/10 text-blue-500',
  Resolved: 'bg-green-500/10 text-green-500',
}

const severities = ['All', 'Critical', 'High', 'Medium', 'Low']
const statuses = ['All Statuses', 'Open', 'In Review', 'Resolved']

export default function AdminFindingsPage() {
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All Statuses')

  const filtered = allFindings.filter(f =>
    (f.title.toLowerCase().includes(search.toLowerCase()) ||
     f.org.toLowerCase().includes(search.toLowerCase()) ||
     f.asset.toLowerCase().includes(search.toLowerCase())) &&
    (sevFilter === 'All' || f.severity === sevFilter) &&
    (statusFilter === 'All Statuses' || f.status === statusFilter)
  )

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Global Findings</h1>
          <p className="text-muted-foreground mt-1">Platform-wide vulnerability findings across all tenants</p>
        </div>
        <Button variant="outline" className="rounded-lg border-foreground/20 h-10"><Download className="w-4 h-4 mr-2" />Export Findings</Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Findings', value: allFindings.length, color: 'text-foreground' },
          { label: 'Critical', value: allFindings.filter(f => f.severity === 'Critical').length, color: 'text-red-500' },
          { label: 'Open', value: allFindings.filter(f => f.status === 'Open').length, color: 'text-yellow-500' },
          { label: 'Unassigned', value: allFindings.filter(f => f.analyst === 'Unassigned').length, color: 'text-orange-500' },
        ].map(s => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Severity bars */}
      <Card className="bg-card border-foreground/10">
        <CardContent className="pt-5 pb-4">
          <div className="grid grid-cols-4 gap-6">
            {severities.filter(s => s !== 'All').map(sev => {
              const count = allFindings.filter(f => f.severity === sev).length
              return (
                <div key={sev}>
                  <div className="flex items-center justify-between text-sm mb-1.5">
                    <span className="text-muted-foreground">{sev}</span>
                    <span className="font-medium text-foreground">{count}</span>
                  </div>
                  <div className="h-2 bg-foreground/5 rounded-full overflow-hidden">
                    <div className={`h-full ${severityConfig[sev]?.bar} rounded-full`} style={{ width: `${(count / allFindings.length) * 100}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search findings, orgs, assets..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        {severities.map(s => (
          <Button key={s} size="sm" variant={sevFilter === s ? 'default' : 'outline'} onClick={() => setSevFilter(s)}
            className={`rounded-lg h-10 ${sevFilter === s ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{s}</Button>
        ))}
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {statuses.map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      <div className="space-y-3">
        {filtered.map(finding => (
          <Card key={finding.id} className="bg-card border-foreground/10 hover:border-foreground/20 transition-all">
            <CardContent className="pt-4 pb-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 flex-1 min-w-0">
                  <div className={`w-1 h-12 rounded-full shrink-0 mt-0.5 ${severityConfig[finding.severity]?.bar}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <h3 className="font-semibold text-foreground text-sm">{finding.title}</h3>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityConfig[finding.severity]?.badge}`}>{finding.severity}</span>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColors[finding.status]}`}>{finding.status}</span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      <span>CVE: <span className="text-foreground font-mono">{finding.cve}</span></span>
                      <span>Asset: <span className="text-foreground">{finding.asset}</span></span>
                      <span className="text-primary font-medium">{finding.org}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <div className="text-right mr-2">
                    <p className="text-xs text-muted-foreground">Analyst</p>
                    <p className={`text-xs font-medium ${finding.analyst === 'Unassigned' ? 'text-orange-500' : 'text-foreground'}`}>{finding.analyst}</p>
                  </div>
                  <Button size="sm" variant="ghost" className="h-8 rounded-lg hover:bg-primary/10 hover:text-primary">
                    <UserCheck className="w-3.5 h-3.5 mr-1" />Assign
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
