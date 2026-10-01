'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Info, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { CardSkeleton } from '@/components/app/loading-states'
import { useAdminData } from '@/hooks/use-admin-data'
import { getQuotaConfig, setPlanAllowance } from '@/lib/api-admin'
import { AdminError } from '@/components/admin/admin-shared'

/**
 * Plans & Quotas.
 *
 * Only the *default allowance* per plan is editable here. Organization bonuses
 * and recorded usage are deliberately not touched from this screen — raising a
 * plan default grants headroom to every organization on that plan without
 * rewriting anyone's history. Per-organization grants live on Organizations.
 */
export default function AdminQuotasPage() {
  const { data, loading, error, refresh } = useAdminData(getQuotaConfig)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<string | null>(null)

  function draftFor(plan: string, current: number): string {
    return drafts[plan] ?? String(current)
  }

  async function save(plan: string, current: number) {
    const raw = draftFor(plan, current).trim()
    const value = Number.parseInt(raw, 10)
    if (!Number.isFinite(value) || (value < 0 && value !== -1)) {
      toast.error('Allowance must be 0 or more, or -1 for unlimited')
      return
    }
    setSaving(plan)
    try {
      await setPlanAllowance(plan, value)
      toast.success(`${plan} default allowance updated`)
      setDrafts((d) => { const n = { ...d }; delete n[plan]; return n })
      refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Update failed')
    } finally {
      setSaving(null)
    }
  }

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Plans &amp; Quotas</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Default scan allowance per plan, per organization, enforced server-side across all scan types.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={refresh}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {error && <AdminError message={error} />}

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-4 flex items-start gap-3">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <p>
              <span className="text-foreground font-medium">Effective allowance</span>{' '}
              = plan default + the organization&apos;s bonus scans. All members of an organization
              share one budget covering Web Security, Network Security and SAST — not a limit
              per user or per module.
            </p>
            {data && <p className="text-muted-foreground/70">{data.consumptionRule}</p>}
            <p className="text-muted-foreground/70">
              Changing a default never resets any organization&apos;s recorded usage. Grant extra
              scans to an organization from the{' '}
              <Link href="/admin/organizations" className="text-primary hover:underline">Organizations</Link> page.
            </p>
          </div>
        </CardContent>
      </Card>

      {loading && !data ? (
        <CardSkeleton lines={4} />
      ) : data ? (
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Default allowance per plan</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {Object.entries(data.planAllowances).map(([plan, allowance]) => {
              const dirty = drafts[plan] !== undefined && drafts[plan] !== String(allowance)
              return (
                <div
                  key={plan}
                  className="flex items-end gap-3 pb-4 border-b border-foreground/8 last:border-0 last:pb-0"
                >
                  <div className="flex-1">
                    <Label className="text-xs text-muted-foreground capitalize">
                      {plan}
                      {plan === data.defaultPlan && (
                        <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                          default for new organizations
                        </span>
                      )}
                    </Label>
                    <p className="text-[11px] text-muted-foreground/60 mt-0.5">
                      {allowance < 0 ? 'Currently unlimited' : `Currently ${allowance} total scans`}
                    </p>
                  </div>
                  <div className="w-32">
                    <Input
                      type="number"
                      min={-1}
                      value={draftFor(plan, allowance)}
                      onChange={(e) => setDrafts((d) => ({ ...d, [plan]: e.target.value }))}
                      className="h-9 text-sm"
                    />
                  </div>
                  <Button
                    size="sm"
                    className="h-9"
                    disabled={!dirty}
                    loading={saving === plan}
                    loadingText="Saving…"
                    onClick={() => save(plan, allowance)}
                  >
                    Save
                  </Button>
                </div>
              )
            })}
            <p className="text-[11px] text-muted-foreground/60">Use -1 for an unlimited plan.</p>
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}
