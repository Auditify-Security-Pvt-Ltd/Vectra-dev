'use client'

import { useState } from 'react'
import { Search, Plus, FileText, Eye, Download, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'

const initReports = [
  { id: 1, title: 'Q1 2026 Executive Security Summary', org: 'FinTech Corp', owner: 'James Wilson', created: 'Jan 31, 2026', format: 'PDF', size: '4.2 MB', status: 'Published' },
  { id: 2, title: 'MedSecure Penetration Test Report', org: 'MedSecure Ltd', owner: 'Sarah Chen', created: 'Jan 28, 2026', format: 'PDF', size: '2.8 MB', status: 'Published' },
  { id: 3, title: 'Cloud Security Posture Assessment', org: 'DataSafe Corp', owner: 'Ryan Torres', created: 'Jan 25, 2026', format: 'HTML', size: '1.1 MB', status: 'Published' },
  { id: 4, title: 'Vulnerability Remediation Tracker', org: 'Guardian Corp', owner: 'Noah Johnson', created: 'Jan 22, 2026', format: 'CSV', size: '640 KB', status: 'Draft' },
  { id: 5, title: 'Network Scan Report - 10.0.0.0/8', org: 'InfraShield GmbH', owner: 'Lucas Müller', created: 'Jan 20, 2026', format: 'PDF', size: '3.5 MB', status: 'Published' },
  { id: 6, title: 'Critical Findings Dashboard Export', org: 'SecOps Co', owner: 'Aisha Patel', created: 'Jan 18, 2026', format: 'JSON', size: '280 KB', status: 'Archived' },
  { id: 7, title: 'Monthly Compliance Report - Jan 2026', org: 'Apex Security SG', owner: 'Thomas Wu', created: 'Jan 15, 2026', format: 'PDF', size: '5.7 MB', status: 'Published' },
  { id: 8, title: 'AI Threat Analysis - January', org: 'CloudNative IO', owner: 'Marcus Davis', created: 'Jan 12, 2026', format: 'HTML', size: '890 KB', status: 'Draft' },
  { id: 9, title: 'Platform-wide Risk Assessment', org: 'ALL ORGS', owner: 'Admin', created: 'Jan 10, 2026', format: 'PDF', size: '12.4 MB', status: 'Published' },
  { id: 10, title: 'CVE Impact Analysis - Q4 2025', org: 'ZeroSec Labs', owner: 'Priya Sharma', created: 'Dec 31, 2025', format: 'PDF', size: '1.8 MB', status: 'Archived' },
]

const formatColors: Record<string, string> = {
  PDF: 'bg-red-500/10 text-red-500', HTML: 'bg-blue-500/10 text-blue-500',
  CSV: 'bg-green-500/10 text-green-500', JSON: 'bg-yellow-500/10 text-yellow-500',
}
const statusColors: Record<string, string> = {
  Published: 'bg-green-500/10 text-green-500', Draft: 'bg-yellow-500/10 text-yellow-500',
  Archived: 'bg-muted text-muted-foreground',
}
const statuses = ['All Statuses', 'Published', 'Draft', 'Archived']

export default function AdminReportsPage() {
  const [reports, setReports] = useState(initReports)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('All Statuses')
  const [generateOpen, setGenerateOpen] = useState(false)

  const filtered = reports.filter(r =>
    (r.title.toLowerCase().includes(search.toLowerCase()) ||
     r.org.toLowerCase().includes(search.toLowerCase()) ||
     r.owner.toLowerCase().includes(search.toLowerCase())) &&
    (statusFilter === 'All Statuses' || r.status === statusFilter)
  )

  const deleteReport = (id: number) => setReports(prev => prev.filter(r => r.id !== id))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Global Reports</h1>
          <p className="text-muted-foreground mt-1">Platform-wide reports across all tenant organizations</p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10"><Download className="w-4 h-4 mr-2" />Export All</Button>
          <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
            <DialogTrigger asChild>
              <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5">
                <Plus className="w-4 h-4 mr-2" />Generate Report
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-card border-foreground/10">
              <DialogHeader>
                <DialogTitle>Generate Platform Report</DialogTitle>
                <DialogDescription>Create a new platform or tenant report</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-2"><Label>Report Title</Label><Input placeholder="Q2 2026 Security Summary" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                <div className="space-y-2">
                  <Label>Organization</Label>
                  <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                    <option>ALL ORGS (Platform Report)</option><option>FinTech Corp</option><option>MedSecure Ltd</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Format</Label>
                  <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                    <option>PDF</option><option>HTML</option><option>CSV</option><option>JSON</option><option>DOCX</option>
                  </select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2"><Label>From Date</Label><Input type="date" className="bg-foreground/5 border-foreground/20 rounded-lg text-sm" /></div>
                  <div className="space-y-2"><Label>To Date</Label><Input type="date" className="bg-foreground/5 border-foreground/20 rounded-lg text-sm" /></div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setGenerateOpen(false)} className="rounded-lg border-foreground/20">Cancel</Button>
                <Button className="bg-primary hover:bg-primary/90 rounded-lg" onClick={() => setGenerateOpen(false)}>Generate</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Reports', value: reports.length },
          { label: 'Published', value: reports.filter(r => r.status === 'Published').length },
          { label: 'Drafts', value: reports.filter(r => r.status === 'Draft').length },
          { label: 'Archived', value: reports.filter(r => r.status === 'Archived').length },
        ].map((s, i) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className="text-2xl font-bold mt-1 text-foreground">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search reports, organizations..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {statuses.map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Reports</CardTitle>
          <CardDescription>{filtered.length} reports</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['Report', 'Organization', 'Owner', 'Created', 'Format', 'Size', 'Status', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(report => (
                  <tr key={report.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
                        <span className="font-medium text-foreground text-sm">{report.title}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{report.org}</td>
                    <td className="py-3 px-3 text-sm text-foreground">{report.owner}</td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{report.created}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${formatColors[report.format]}`}>{report.format}</span></td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{report.size}</td>
                    <td className="py-3 px-3"><span className={`text-xs font-medium px-2 py-0.5 rounded ${statusColors[report.status]}`}>{report.status}</span></td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1">
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-primary/10 hover:text-primary" title="View"><Eye className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-foreground/10" title="Download"><Download className="w-3.5 h-3.5" /></Button>
                        <Button size="icon" variant="ghost" className="h-7 w-7 rounded hover:bg-destructive/10 hover:text-destructive" title="Delete" onClick={() => deleteReport(report.id)}><Trash2 className="w-3.5 h-3.5" /></Button>
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
