'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Cloud, Loader2, Plug, RefreshCw, ShieldCheck, Trash2, Clock } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { CardSkeleton, ListSkeleton } from '@/components/app/loading-states'
import { useAuth } from '@/context/auth-context'
import { hasPermission } from '@/lib/rbac'
import {
  disconnectIntegration, listCloudProviders, listIntegrations, startSync, validateIntegration,
  providerLabel, type CloudIntegration, type CloudSync,
} from '@/lib/api-cloud'
import {
  CloudErrorState, GcpCapabilityList, INTEGRATION_STATUS, ProviderBadge, SyncErrorDetail,
  errorMessage, formatRelative, isGcpCapabilities, useCloudData, useSyncPoller,
} from '@/components/cloud/cloud-shared'
import { ConnectAwsDialog, ConnectGcpDialog } from '@/components/cloud/connect-dialogs'

const CAPABILITY_LABEL: Record<string, string> = {
  findings: 'Security findings', vulnerability_metadata: 'CVE & CVSS', compliance: 'Compliance',
  assets: 'Affected assets', asset_inventory: 'Full asset inventory', iam_analysis: 'IAM analysis',
  configuration_analysis: 'Configuration analysis',
}

function IntegrationCard({
  integration, live, canSync, canManage, onSync, onValidate, onDisconnect, busy,
}: {
  integration: CloudIntegration
  live: CloudSync | null | undefined
  canSync: boolean
  canManage: boolean
  onSync: () => void
  onValidate: () => void
  onDisconnect: () => void
  busy: string | null
}) {
  const syncing = live !== undefined || integration.syncStatus === 'queued' || integration.syncStatus === 'running'
  const status = INTEGRATION_STATUS[integration.status] ?? INTEGRATION_STATUS.error
  const c = integration.counts
  const cfg = integration.config as Record<string, unknown>
  const scope = integration.provider === 'aws'
    ? `Regions: ${((cfg.regions as string[]) ?? []).join(', ')}`
    : `${cfg.scopeType ?? 'project'} ${cfg.scopeId ?? ''}${cfg.location ? ` · ${cfg.location}` : ''}`

  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm font-semibold text-foreground truncate">{integration.displayName}</p>
              <ProviderBadge provider={integration.provider} />
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${status.cls}`}>{status.label}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{integration.accountLabel ?? integration.accountId ?? '—'} · {scope}</p>
          </div>
          <div className="flex items-center gap-1.5">
            {canSync && (
              <Button size="sm" variant="outline" className="h-8 border-foreground/20 gap-1.5" disabled={syncing} onClick={onSync}>
                {syncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                {syncing ? (live?.status === 'running' ? 'Syncing…' : 'Queued…') : integration.lastSyncStatus === 'failed' ? 'Retry sync' : 'Sync now'}
              </Button>
            )}
            {canManage && (
              <>
                <Button size="sm" variant="ghost" className="h-8 gap-1.5 text-muted-foreground" loading={busy === `validate:${integration.integrationId}`} onClick={onValidate}>
                  <ShieldCheck className="w-3.5 h-3.5" /> Test
                </Button>
                <Button size="sm" variant="ghost" className="h-8 gap-1.5 text-muted-foreground hover:text-destructive" onClick={onDisconnect}>
                  <Trash2 className="w-3.5 h-3.5" /> Disconnect
                </Button>
              </>
            )}
          </div>
        </div>

        {integration.provider === 'gcp' && isGcpCapabilities(integration.capabilities) && integration.status !== 'disconnected' && (
          <div className="rounded-md border border-foreground/8 p-3">
            <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">Capabilities</p>
            <GcpCapabilityList capabilities={integration.capabilities} compact />
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
          {[['Open findings', c.open], ['Critical', c.critical], ['High', c.high], ['Resolved', c.resolved], ['Assets', c.assets]].map(([k, v]) => (
            <div key={k} className="rounded-md border border-foreground/8 p-2">
              <p className="text-muted-foreground">{k}</p>
              <p className="text-base font-semibold text-foreground">{v}</p>
            </div>
          ))}
        </div>

        <div className="flex items-start gap-2 text-xs text-muted-foreground">
          <Clock className="w-3.5 h-3.5 mt-0.5" />
          <div className="space-y-1">
            <p>
              Last synced: <span className="text-foreground">{formatRelative(integration.lastSyncAt)}</span>
              {integration.lastSyncStatus && <> · Status: <span className={
                integration.lastSyncStatus === 'completed' ? 'text-green-500' : integration.lastSyncStatus === 'failed' ? 'text-red-400' : 'text-orange-400'
              }>{integration.lastSyncStatus === 'completed' ? 'Healthy' : integration.lastSyncStatus === 'partial' ? 'Partially synced' : 'Sync failed'}</span></>}
              {integration.lastSyncStats && integration.lastSyncStatus !== 'failed' && (
                <> · {integration.lastSyncStats.findingsDiscovered} findings, {integration.lastSyncStats.newFindings} new, {integration.lastSyncStats.resolvedFindings} resolved</>
              )}
            </p>
            {integration.lastSyncStatus !== 'completed' && <SyncErrorDetail error={integration.lastSyncError} />}
            {integration.status === 'error' && integration.validation?.error && !integration.lastSyncError && (
              <SyncErrorDetail error={integration.validation.error} />
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function CloudIntegrationsPage() {
  const { orgRole } = useAuth()
  const canSync   = !!orgRole && hasPermission(orgRole, 'syncCloudFindings')
  const canManage = !!orgRole && hasPermission(orgRole, 'manageCloudIntegrations')

  const providers    = useCloudData(listCloudProviders)
  const integrations = useCloudData(() => listIntegrations())
  const [connecting, setConnecting] = useState<'aws' | 'gcp' | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [removing, setRemoving] = useState<CloudIntegration | null>(null)
  const [purge, setPurge] = useState(false)

  const poller = useSyncPoller((sync) => {
    integrations.reload()
    if (sync.status === 'completed') toast.success('Sync completed', {
      description: sync.stats ? `${sync.stats.findingsDiscovered} findings · ${sync.stats.newFindings} new · ${sync.stats.resolvedFindings} resolved` : undefined,
    })
    else if (sync.status === 'partial') toast.warning('Sync partially completed', { description: sync.error?.message })
    else toast.error('Sync failed', { description: sync.error?.message })
  })

  // Resume polling for syncs already running when the page opens.
  useEffect(() => {
    integrations.data?.integrations.forEach((i) => {
      if ((i.syncStatus === 'queued' || i.syncStatus === 'running') && i.currentSyncId && poller.active[i.integrationId] === undefined) {
        poller.track(i.integrationId, i.currentSyncId)
      }
    })
  }, [integrations.data]) // eslint-disable-line react-hooks/exhaustive-deps

  async function sync(i: CloudIntegration) {
    try {
      const { syncId } = await startSync(i.integrationId)
      poller.track(i.integrationId, syncId)
      toast.message('Sync started', { description: i.displayName })
    } catch (err) {
      toast.error('Could not start sync', { description: errorMessage(err) })
    }
  }

  async function validate(i: CloudIntegration) {
    setBusy(`validate:${i.integrationId}`)
    try {
      const { validation } = await validateIntegration(i.integrationId)
      if (validation.ok) toast.success('Connection is healthy', { description: validation.accountLabel ?? undefined })
      else toast.error('Connection check failed', { description: validation.error?.message })
      integrations.reload()
    } catch (err) {
      toast.error('Connection check failed', { description: errorMessage(err) })
    } finally {
      setBusy(null)
    }
  }

  async function disconnect() {
    if (!removing) return
    setBusy('disconnect')
    try {
      await disconnectIntegration(removing.integrationId, purge)
      toast.success(`${removing.displayName} disconnected`)
      setRemoving(null); setPurge(false)
      integrations.reload()
    } catch (err) {
      toast.error('Disconnect failed', { description: errorMessage(err) })
    } finally {
      setBusy(null)
    }
  }

  const list = integrations.data?.integrations ?? []
  const storage = providers.data?.credentialStorageConfigured ?? false

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-foreground">Cloud Integrations</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Connect cloud accounts to import findings from their native security services.
          </p>
        </div>
        <Button variant="outline" size="sm" className="border-foreground/20 gap-2" onClick={() => { providers.reload(); integrations.reload() }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {(providers.error || integrations.error) ? <CloudErrorState error={providers.error ?? integrations.error} /> : null}

      {/* Providers */}
      {providers.loading && !providers.data ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">{Array.from({ length: 5 }).map((_, i) => <CardSkeleton key={i} lines={2} />)}</div>
      ) : providers.data ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {providers.data.providers.map((p) => {
            const available = p.status === 'available'
            const connected = list.filter((i) => i.provider === p.key).length
            const capabilities = Object.entries(p.capabilities).filter(([, v]) => v !== 'future')
            return (
              <Card key={p.key} className={`bg-card border-foreground/10 ${available ? '' : 'opacity-70'}`}>
                <CardContent className="p-4 flex flex-col h-full gap-2">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center"><Cloud className="w-4 h-4 text-blue-400" /></div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-foreground">{providerLabel(p.key)}</p>
                      <p className="text-[11px] text-muted-foreground truncate">{p.securityService ?? 'No native findings service'}</p>
                    </div>
                  </div>
                  {available ? (
                    <p className="text-[11px] text-muted-foreground">{capabilities.map(([k]) => CAPABILITY_LABEL[k] ?? k).join(' · ')}</p>
                  ) : (
                    <p className="text-[11px] text-muted-foreground">{p.note}</p>
                  )}
                  <div className="mt-auto pt-1">
                    {!available ? (
                      <span className="text-[10px] font-semibold px-2 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">Coming Soon</span>
                    ) : canManage ? (
                      <Button size="sm" className="w-full h-8 gap-1.5" onClick={() => setConnecting(p.key as 'aws' | 'gcp')}>
                        <Plug className="w-3.5 h-3.5" /> {connected ? 'Connect another' : 'Connect'}
                      </Button>
                    ) : (
                      <p className="text-[11px] text-muted-foreground">{connected ? `${connected} connected` : 'An organization admin can connect this provider.'}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      ) : null}

      {/* Connected accounts */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Connected accounts</h2>
        {integrations.loading && !integrations.data ? (
          <ListSkeleton rows={2} />
        ) : list.length === 0 ? (
          <Card className="bg-card border-foreground/10">
            <CardContent className="py-12 text-center">
              <Cloud className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No cloud providers connected</p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                {canManage ? 'Connect AWS or Google Cloud above to start importing findings.' : 'Ask an organization admin to connect a cloud provider.'}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {list.map((i) => (
              <IntegrationCard
                key={i.integrationId} integration={i} live={poller.active[i.integrationId]}
                canSync={canSync && i.status !== 'disconnected'} canManage={canManage} busy={busy}
                onSync={() => sync(i)} onValidate={() => validate(i)} onDisconnect={() => setRemoving(i)}
              />
            ))}
          </div>
        )}
        {list.length > 0 && (
          <p className="text-xs text-muted-foreground">
            Imported findings appear in <Link href="/app/cloud-security/findings" className="text-primary hover:underline">Cloud Findings</Link> and{' '}
            <Link href="/app/findings?module=cloud" className="text-primary hover:underline">Vulnerability Management</Link>.
            Cloud syncs do not use your organization&apos;s scan allowance.
          </p>
        )}
      </div>

      <ConnectAwsDialog
        open={connecting === 'aws'} onClose={() => setConnecting(null)} credentialStorageConfigured={storage}
        onConnected={(i, syncId) => { integrations.reload(); if (syncId) poller.track(i.integrationId, syncId) }}
      />
      <ConnectGcpDialog
        open={connecting === 'gcp'} onClose={() => setConnecting(null)} credentialStorageConfigured={storage}
        onConnected={(i, syncId) => { integrations.reload(); if (syncId) poller.track(i.integrationId, syncId) }}
      />

      <Dialog open={removing !== null} onOpenChange={(o) => !o && busy !== 'disconnect' && setRemoving(null)}>
        <DialogContent className="sm:max-w-md bg-card border-foreground/10">
          <DialogHeader>
            <DialogTitle className="text-base">Disconnect {removing?.displayName}?</DialogTitle>
            <DialogDescription className="text-xs">
              Stored credentials are destroyed immediately and syncing stops. Imported findings are kept for history unless you remove them.
            </DialogDescription>
          </DialogHeader>
          <Label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <Checkbox checked={purge} onCheckedChange={(v) => setPurge(v === true)} />
            Also delete this integration&apos;s findings and assets
          </Label>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRemoving(null)} disabled={busy === 'disconnect'}>Cancel</Button>
            <Button variant="destructive" loading={busy === 'disconnect'} loadingText="Disconnecting…" onClick={disconnect}>Disconnect</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
