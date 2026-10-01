'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { TableSkeleton } from '@/components/app/loading-states'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listCloudAssets, providerLabel } from '@/lib/api-cloud'
import { CloudErrorState, ProviderBadge, formatRelative, useCloudData } from '@/components/cloud/cloud-shared'

const PAGE_SIZE = 50
const selectCls = 'h-9 px-2.5 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-xs max-w-[14rem]'

export default function CloudAssetsPage() {
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [provider, setProvider] = useState('')
  const [resourceType, setResourceType] = useState('')
  const [offset, setOffset] = useState(0)

  useEffect(() => {
    const t = setTimeout(() => { setOffset(0); setSearch(searchInput.trim()) }, 350)
    return () => clearTimeout(t)
  }, [searchInput])

  const assets = useCloudData(
    () => listCloudAssets({ search, provider, resourceType, limit: PAGE_SIZE, offset }),
    [search, provider, resourceType, offset],
  )
  const showSkeleton = useDelayedLoading(assets.loading && !assets.data)
  const data = assets.data
  const total = data?.total ?? 0

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-foreground">Cloud Assets</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Cloud resources referenced by imported security findings. Full asset inventory is not yet available.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={assets.reload}>
          <RefreshCw className={`w-3.5 h-3.5 ${assets.loading ? 'animate-spin' : ''}`} /> Refresh
        </Button>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} maxLength={200}
            placeholder="Search resource, account…" className="pl-9 h-9 w-72 bg-foreground/5 border-foreground/20 text-sm" />
        </div>
        <select aria-label="Provider" className={selectCls} value={provider} onChange={(e) => { setOffset(0); setProvider(e.target.value) }}>
          <option value="" className="bg-card">All providers</option>
          <option value="aws" className="bg-card">AWS</option>
          <option value="gcp" className="bg-card">Google Cloud</option>
        </select>
        <select aria-label="Resource type" className={selectCls} value={resourceType} onChange={(e) => { setOffset(0); setResourceType(e.target.value) }}>
          <option value="" className="bg-card">All resource types</option>
          {(data?.facets.resourceTypes ?? []).map((r) => <option key={r} value={r} className="bg-card">{r}</option>)}
        </select>
      </div>

      {assets.error ? <CloudErrorState error={assets.error} /> : null}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={8} cols={6} /></div>
          ) : !data ? null : data.assets.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-16">
              {search || provider || resourceType ? 'No assets match these filters.' : 'No cloud assets yet. Assets appear after a sync imports findings.'}
            </p>
          ) : (
            <div className={`overflow-x-auto ${assets.loading ? 'opacity-60' : ''}`}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['Resource', 'Type', 'Provider', 'Account / project', 'Region', 'Open findings', 'Last seen'].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.assets.map((a) => (
                    <tr key={a.assetId} className="border-b border-foreground/5 hover:bg-foreground/3">
                      <td className="py-3 px-4 max-w-[22rem]">
                        <p className="truncate text-foreground">{a.resourceName ?? a.resourceId}</p>
                        <p className="truncate text-[11px] font-mono text-muted-foreground">{a.resourceId}</p>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground">{a.resourceType}</td>
                      <td className="py-3 px-4"><ProviderBadge provider={a.provider} /></td>
                      <td className="py-3 px-4 text-xs font-mono text-muted-foreground">{a.accountId ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-muted-foreground">{a.region ?? '—'}</td>
                      <td className="py-3 px-4 text-xs">
                        {a.openFindingCount > 0 ? (
                          <Link href={`/app/cloud-security/findings`} className="text-red-400 hover:underline">{a.openFindingCount} open</Link>
                        ) : <span className="text-muted-foreground">0</span>}
                        <span className="text-muted-foreground"> / {a.findingCount}</span>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground whitespace-nowrap">{formatRelative(a.lastSeenAt)}</td>
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
          <p className="text-xs text-muted-foreground">{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total} · {providerLabel(provider || null) === '—' ? 'all providers' : providerLabel(provider)}</p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset === 0} onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}>
              <ChevronLeft className="w-3.5 h-3.5" /> Previous
            </Button>
            <Button variant="outline" size="sm" className="border-foreground/20 h-8" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
              Next <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
