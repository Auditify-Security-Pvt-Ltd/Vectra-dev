'use client'

import { useState } from 'react'
import { Search, Globe, Network, Server, Cloud, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

const allAssets = [
  { id: 1, name: 'api.fintechcorp.io', org: 'FinTech Corp', type: 'Domain', riskScore: 87, findings: 42, lastScan: '1h ago', status: 'High Risk' },
  { id: 2, name: '10.12.0.0/16', org: 'FinTech Corp', type: 'CIDR', riskScore: 54, findings: 18, lastScan: '3h ago', status: 'Medium Risk' },
  { id: 3, name: 'db-prod.medsecure.io', org: 'MedSecure Ltd', type: 'Domain', riskScore: 92, findings: 67, lastScan: '2h ago', status: 'Critical' },
  { id: 4, name: '172.20.0.0/24', org: 'MedSecure Ltd', type: 'CIDR', riskScore: 31, findings: 7, lastScan: '6h ago', status: 'Low Risk' },
  { id: 5, name: 'aws-prod-cluster', org: 'DataSafe Corp', type: 'Cloud', riskScore: 78, findings: 89, lastScan: '30min ago', status: 'High Risk' },
  { id: 6, name: 'vpn.guardiancorp.net', org: 'Guardian Corp', type: 'Domain', riskScore: 43, findings: 11, lastScan: '4h ago', status: 'Medium Risk' },
  { id: 7, name: '192.168.100.0/24', org: 'SecOps Co', type: 'CIDR', riskScore: 22, findings: 4, lastScan: '1d ago', status: 'Low Risk' },
  { id: 8, name: 'azure-dev-env', org: 'CloudNative IO', type: 'Cloud', riskScore: 61, findings: 28, lastScan: '5h ago', status: 'Medium Risk' },
  { id: 9, name: 'shop.datasafe.com', org: 'DataSafe Corp', type: 'Domain', riskScore: 75, findings: 35, lastScan: '2h ago', status: 'High Risk' },
  { id: 10, name: '10.0.0.0/8', org: 'InfraShield GmbH', type: 'CIDR', riskScore: 88, findings: 52, lastScan: '4h ago', status: 'High Risk' },
  { id: 11, name: 'gcp-ml-cluster', org: 'Guardian Corp', type: 'Cloud', riskScore: 95, findings: 103, lastScan: '1h ago', status: 'Critical' },
  { id: 12, name: 'auth.apexsec.sg', org: 'Apex Security SG', type: 'Domain', riskScore: 48, findings: 14, lastScan: '8h ago', status: 'Medium Risk' },
]

const typeIcon: Record<string, any> = { Domain: Globe, CIDR: Network, IP: Server, Cloud: Cloud }
const typeColor: Record<string, string> = {
  Domain: 'bg-primary/10 text-primary', CIDR: 'bg-accent/10 text-accent',
  IP: 'bg-blue-500/10 text-blue-500', Cloud: 'bg-orange-500/10 text-orange-500',
}
const riskColor = (score: number) => {
  if (score >= 85) return 'text-red-500'
  if (score >= 60) return 'text-orange-500'
  if (score >= 35) return 'text-yellow-500'
  return 'text-green-500'
}
const statusColor: Record<string, string> = {
  Critical: 'bg-red-500/10 text-red-500',
  'High Risk': 'bg-orange-500/10 text-orange-500',
  'Medium Risk': 'bg-yellow-500/10 text-yellow-500',
  'Low Risk': 'bg-green-500/10 text-green-500',
}
const types = ['All', 'Domain', 'CIDR', 'IP', 'Cloud']

export default function AdminAssetsPage() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('All')

  const filtered = allAssets.filter(a =>
    (a.name.toLowerCase().includes(search.toLowerCase()) ||
     a.org.toLowerCase().includes(search.toLowerCase())) &&
    (typeFilter === 'All' || a.type === typeFilter)
  )

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Global Asset Inventory</h1>
          <p className="text-muted-foreground mt-1">Platform-wide asset visibility across all tenant organizations</p>
        </div>
        <Button variant="outline" className="rounded-lg border-foreground/20 h-10">
          <Download className="w-4 h-4 mr-2" />Export
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Assets', value: allAssets.length, color: 'text-foreground' },
          { label: 'Critical / High Risk', value: allAssets.filter(a => a.riskScore >= 75).length, color: 'text-red-500' },
          { label: 'Cloud Assets', value: allAssets.filter(a => a.type === 'Cloud').length, color: 'text-accent' },
          { label: 'Total Findings', value: allAssets.reduce((s, a) => s + a.findings, 0), color: 'text-orange-500' },
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
          <Input placeholder="Search assets, organizations..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        {types.map(t => (
          <Button key={t} size="sm" variant={typeFilter === t ? 'default' : 'outline'} onClick={() => setTypeFilter(t)}
            className={`rounded-lg h-10 ${typeFilter === t ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{t}</Button>
        ))}
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Assets</CardTitle>
          <CardDescription>{filtered.length} assets</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Asset', 'Organization', 'Type', 'Risk Score', 'Findings', 'Status', 'Last Scan'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(asset => {
                  const Icon = typeIcon[asset.type] || Globe
                  return (
                    <tr key={asset.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          <Icon className="w-4 h-4 text-muted-foreground" />
                          <span className="font-medium text-foreground text-sm">{asset.name}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3 text-sm text-muted-foreground">{asset.org}</td>
                      <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${typeColor[asset.type]}`}>{asset.type}</span></td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-foreground/10 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${asset.riskScore >= 85 ? 'bg-red-500' : asset.riskScore >= 60 ? 'bg-orange-500' : asset.riskScore >= 35 ? 'bg-yellow-500' : 'bg-green-500'}`}
                              style={{ width: `${asset.riskScore}%` }} />
                          </div>
                          <span className={`text-sm font-bold ${riskColor(asset.riskScore)}`}>{asset.riskScore}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3 text-sm font-medium text-orange-500">{asset.findings}</td>
                      <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColor[asset.status]}`}>{asset.status}</span></td>
                      <td className="py-3 px-3 text-sm text-muted-foreground">{asset.lastScan}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
