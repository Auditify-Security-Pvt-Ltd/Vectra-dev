'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Search, RefreshCw, ShieldCheck, ShieldOff, ChevronLeft, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { TableSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { useDelayedLoading } from '@/hooks/use-loading'
import { listUsers, updateUser, type AdminUser } from '@/lib/api-admin'
import { AdminError } from '@/components/admin/admin-shared'

const PAGE_SIZE = 25

const STATUS_CLS: Record<string, string> = {
  active:    'bg-green-500/10 text-green-500 border-green-500/20',
  disabled:  'bg-muted text-muted-foreground border-border',
  suspended: 'bg-red-500/10 text-red-500 border-red-500/20',
}

const ORG_ROLE_CLS: Record<string, string> = {
  admin:  'bg-primary/10 text-primary border-primary/20',
  editor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  viewer: 'bg-muted text-muted-foreground border-border',
}

function roleLabel(role: string | null): string {
  return role ? role.replace(/_/g, ' ') : '—'
}

// ── Page ──────────────────────────────────────────────────────────────

export default function AdminUsersPage() {
  const [search, setSearch]   = useState('')
  const [query, setQuery]     = useState('')
  const [offset, setOffset]   = useState(0)
  const [statusBusy, setStatusBusy] = useState<string | null>(null)

  const { data, loading, error, refresh } = useAdminData(
    () => listUsers({ search: query, limit: PAGE_SIZE, offset }),
    { deps: [query, offset] },
  )
  const showSkeleton = useDelayedLoading(loading && !data)

  function submitSearch(e: React.FormEvent) {
    e.preventDefault()
    setOffset(0)
    setQuery(search.trim())
  }

  async function toggleStatus(u: AdminUser) {
    const next = u.status === 'active' ? 'disabled' : 'active'
    if (next === 'disabled' &&
        !window.confirm(`Deactivate ${u.email ?? u.uid}?\n\nTheir scans, findings and reports are kept.`)) {
      return
    }
    setStatusBusy(u.uid)
    try {
      await updateUser(u.uid, { status: next })
      toast.success(next === 'active' ? 'User reactivated' : 'User deactivated')
      refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setStatusBusy(null)
    }
  }

  const total = data?.total ?? 0
  const page  = Math.floor(offset / PAGE_SIZE) + 1
  const pages = Math.max(Math.ceil(total / PAGE_SIZE), 1)

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Users</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Individual accounts. Plans and scan quota are managed per{' '}
            <Link href="/admin/organizations" className="text-primary hover:underline">organization</Link>.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <form onSubmit={submitSearch} className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              placeholder="Search name, email, UID or org…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 h-9 w-64 bg-foreground/5 border-foreground/20 text-sm"
            />
          </form>
          <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refresh}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {error && <AdminError message={error} />}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {showSkeleton ? (
            <div className="p-4"><TableSkeleton rows={6} cols={6} /></div>
          ) : loading && !data ? null : !data?.users.length ? (
            <div className="text-center py-16">
              <p className="text-sm text-muted-foreground">
                {query ? 'No users match your search.' : 'No users found.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-foreground/10">
                    {['User', 'Organization', 'Org Role', 'Platform Role', 'Status', ''].map((h) => (
                      <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.users.map((u) => (
                    <tr key={u.uid} className="border-b border-foreground/5 hover:bg-foreground/3">
                      <td className="py-3 px-4">
                        <p className="text-sm font-medium text-foreground">{u.name ?? '—'}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{u.email ?? u.uid}</p>
                      </td>
                      <td className="py-3 px-4">
                        {u.organizationId ? (
                          <>
                            <p className="text-xs text-foreground">{u.organizationName ?? u.organizationId}</p>
                            <p className="text-[11px] text-muted-foreground capitalize">{u.orgPlan ?? '—'} plan</p>
                          </>
                        ) : (
                          <span className="text-xs text-muted-foreground">No organization</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {u.orgRole ? (
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${
                            ORG_ROLE_CLS[u.orgRole] ?? ORG_ROLE_CLS.viewer
                          }`}>
                            {u.orgRole}
                          </span>
                        ) : <span className="text-xs text-muted-foreground">—</span>}
                      </td>
                      <td className="py-3 px-4 text-xs capitalize text-muted-foreground">{roleLabel(u.role)}</td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border capitalize ${
                          STATUS_CLS[u.status] ?? STATUS_CLS.disabled
                        }`}>
                          {u.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1 justify-end">
                          <Button
                            variant="ghost" size="sm"
                            className={`h-7 text-xs gap-1 ${
                              u.status === 'active'
                                ? 'text-muted-foreground hover:text-destructive'
                                : 'text-muted-foreground hover:text-green-500'
                            }`}
                            loading={statusBusy === u.uid}
                            onClick={() => toggleStatus(u)}
                          >
                            {u.status === 'active'
                              ? <><ShieldOff className="w-3 h-3" /> Disable</>
                              : <><ShieldCheck className="w-3 h-3" /> Enable</>}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline" size="sm" className="border-foreground/20 h-8"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(offset - PAGE_SIZE, 0))}
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Previous
            </Button>
            <span className="text-xs text-muted-foreground self-center">Page {page} of {pages}</span>
            <Button
              variant="outline" size="sm" className="border-foreground/20 h-8"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
