'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ChevronLeft, ChevronRight, RefreshCw, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { TableSkeleton } from '@/components/app/loading-states'
import { useDelayedLoading } from '@/hooks/use-loading'
import {
  listCloudFindings, listIntegrations, providerLabel, type FindingQuery,
} from '@/lib/api-cloud'
import {
  CloudErrorState, ProviderBadge, SeverityBadge, StatusBadge, formatRelative, useCloudData,
} from '@/components/cloud/cloud-shared'

const PAGE_SIZE = 50
const selectCls = 'h-9 px-2.5 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-xs max-w-[12rem]'

export default function CloudFindingsPage() {
  const router = useRouter()
  const [searchInput, setSearchInput] = useState('')
  const [filters, setFilters] = useState<FindingQuery>({ status: 'open', sort: 'severity' })
  const [offset, setOffset] = useState(0)

  // Debounce free-text search so typing does not issue a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setOffset(0)
      setFilters((f) => (f.search === searchInput.trim() ? f : { ...f, search: searchInput.trim() || undefined }))
    }, 350)
    return () => clearTimeout(t)
  }, [searchInput])

  const findings = useCloudData(() => listCloudFindings({ ...filters, limit: PAGE_SIZE, offset }), [JSON.stringify(filters), offset])
  const integrations = useCloudData(() => listIntegrations(true))
  const showSkeleton = useDelayedLoading(findings.loading && !findings.data)

  function set<K extends keyof FindingQuery>(key: K, value: FindingQuery[K] | '') {
    setOffset(0)
    setFilters((f) => ({ ...f, [key]: value || undefined }))
  }

  const data = findings.data
  const facets = data?.facets
  const total = data?.total ?? 0
  const integrationName = (id: string) => integrations.data?.integrations.find((i) => i.integrationId === id)?.displayName ?? id
  // The default view (open findings) is not counted as a user-applied filter.
  const active = Object.entries(filters).filter(([k, v]) => v && k !== 'sort' && k !== 'search' && !(k === 'status' && v === 'open')).length

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-foreground">Cloud Findings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Normalized findings from AWS Security Hub and Google Security Command Center.</p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={findings.reload}>
          <RefreshCw className={`w-3.5 h-3.5 ${findings.loading ? 'animate-spin' : ''}`} /> Refresh
        </Button>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} maxLength={200}
            placeholder="Search title, resource, account, CVE…" className="pl-9 h-9 w-72 bg-foreground/5 border-foreground/20 text-sm" />
        </div>
        <select aria-label="Provider" className={selectCls} value={filters.provider ?? ''} onChange={(e) => set('provider', e.target.value)}>
          <option value="" className="bg-card">All providers</option>
          {(facets?.providers ?? []).map((p) => <option key={p} value={p} className="bg-card">{providerLabel(p)}</option>)}
        </select>
        <select aria-label="Severity" className={selectCls} value={filters.severity ?? ''} onChange={(e) => set('severity', e.target.value)}>
          <option value="" className="bg-card">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s} className="bg-card">{s[0].toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select aria-label="Status" className={selectCls} value={filters.status ?? ''} onChange={(e) => set('status', e.target.value)}>
          <option value="" className="bg-card">All statuses</option>
          {['open', 'resolved', 'suppressed'].map((s) => <option key={s} value={s} className="bg-card">{s[0].toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select aria-label="Resource type" className={selectCls} value={filters.resourceType ?? ''} onChange={(e) => set('resourceType', e.target.value)}>
          <option value="" className="bg-card">All resource types</option>
          {(facets?.resourceTypes ?? []).map((r) => <option key={r} value={r} className="bg-card">{r}</option>)}
        </select>
        <select aria-label="Region" className={selectCls} value={filters.region ?? ''} onChange={(e) => set('region', e.target.value)}>
          <option value="" className="bg-card">All regions</option>
          {(facets?.regions ?? []).map((r) => <option key={r} value={r} className="bg-card">{r}</option>)}
        </select>
        <select aria-label="Finding type" className={selectCls} value={filters.findingType ?? ''} onChange={(e) => set('findingType', e.target.value)}>
          <option value="" className="bg-card">All finding types</option>
          {(facets?.findingTypes ?? []).map((r) => <option key={r} value={r} className="bg-card">{r}</option>)}
        </select>
        <select aria-label="Integration" className={selectCls} value={filters.integrationId ?? ''} onChange={(e) => set('integrationId', e.target.value)}>
          <option value="" className="bg-card">All integrations</option>
          {(facets?.integrationIds ?? []).map((id) => <option key={id} value={id} className="bg-card">{integrationName(id)}</option>)}
        </select>
        <Input value={filters.cve ?? ''} onChange={(e) => set('cve', e.target.value)} maxLength={40}
          placeholder="CVE" className="h-9 w-32 bg-foreground/5 border-foreground/20 text-xs font-mono" />
        <select aria-label="Sort" className={selectCls} value={filters.sort ?? 'severity'} onChange={(e) => set('sort', e.target.value as FindingQuery['sort'])}>
          <option value="severity" className="bg-card">Sort: Severity</option>
          <option value="newest" className="bg-card">Sort: Newest</option>
          <option value="updated" className="bg-card">Sort: Last updated</option>
        </select>
        {active > 0 && (
          <Button variant="ghost" size="sm" className="h-9 text-xs gap-1" onClick={() => { setOffset(0); setFilters({ status: 'open', sort: filters.sort }) }}>
            <X className="w-3 h-3" /> Clear filters
          </Button>
        )}
      </div>

      {findings.error ? <CloudErrorState error={findings.error} /> : null}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={8} cols={8} /></div>
          ) : !data ? null : data.findings.length === 0 ? (
            <div className="text-center py-16">
              <p className="text-sm text-muted-foreground">
                {facets?.providers.length ? 'No findings match these filters.' : 'No cloud findings yet. Connect a provider and run a sync.'}
              </p>
            </div>
          ) : (
            <div className={`overflow-x-auto transition-opacity ${findings.loading ? 'opacity-60' : ''}`}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Severity', 'Finding', 'Provider', 'Resource', 'Location', 'CVE', 'Status', 'Last seen'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.findings.map((f) => (
                    <tr key={f.fingerprint} className="border-b border-foreground/5 hover:bg-foreground/3 cursor-pointer"
                      onClick={() => router.push(`/app/cloud-security/findings/${f.fingerprint}`)}>
                      <td className="py-3 px-4"><SeverityBadge severity={f.severity} /></td>
                      <td className="py-3 px-4 max-w-[24rem]">
                        <p className="truncate text-foreground">{f.title}</p>
                        <p className="truncate text-[11px] text-muted-foreground">{f.providerProduct ?? ''}{f.findingType ? ` · ${f.findingType}` : ''}</p>
                      </td>
                      <td className="py-3 px-4"><ProviderBadge provider={f.provider} /></td>
                      <td className="py-3 px-4 max-w-[16rem]">
                        <p className="truncate text-xs font-mono text-foreground">{f.resourceName ?? f.resourceId ?? '—'}</p>
                        <p className="truncate text-[11px] text-muted-foreground">{f.resourceType ?? ''}</p>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">
                        {f.region ?? '—'}<br /><span className="text-[11px]">{f.accountId ?? ''}</span>
                      </td>
                      <td className="py-3 px-4 text-xs font-mono whitespace-nowrap">
                        {f.cveId ? <span className="text-violet-400">{f.cveId}{f.cveIds.length > 1 ? ` +${f.cveIds.length - 1}` : ''}</span> : '—'}
                        {f.cvssScore != null && <span className="block text-[11px] text-muted-foreground">CVSS {f.cvssScore.toFixed(1)}</span>}
                      </td>
                      <td className="py-3 px-4"><StatusBadge status={f.status} /></td>
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">{formatRelative(f.lastSeenAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {total > 0 && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset === 0 || findings.loading}
              onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
              <ChevronLeft className="w-3.5 h-3.5" /> Previous
            </Button>
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset + PAGE_SIZE >= total || findings.loading}
              onClick={() => setOffset(offset + PAGE_SIZE)}>
              Next <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
