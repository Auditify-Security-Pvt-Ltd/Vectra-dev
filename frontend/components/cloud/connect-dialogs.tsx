'use client'

/**
 * Connection flows for AWS and Google Cloud.
 *
 * Credentials live only in component state until submitted, are cleared as soon
 * as the request is sent, and are never read back from the backend. A provider
 * is shown as connected only after the backend has validated live access.
 */

import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, CheckCircle2, Copy, KeyRound, Loader2, ShieldCheck, Upload, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { CardSkeleton } from '@/components/app/loading-states'
import {
  CloudApiError, createIntegration, getAwsSetup, getGcpSetup, startSync,
  type AwsSetupInfo, type CloudIntegration, type CloudValidation, type GcpSetupInfo,
} from '@/lib/api-cloud'
import { GcpCapabilityList, errorMessage, isGcpCapabilities } from '@/components/cloud/cloud-shared'

type Phase = 'form' | 'validating' | 'result'

interface ConnectProps {
  open: boolean
  onClose: () => void
  onConnected: (integration: CloudIntegration, syncId?: string) => void
  credentialStorageConfigured: boolean
}

const fieldCls = 'h-9 text-sm bg-background/50 border-foreground/20'

function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex items-center gap-1.5 flex-wrap mb-2">
      {steps.map((s, i) => (
        <li key={s} className="flex items-center gap-1.5">
          <span className={`w-5 h-5 rounded-full text-[10px] font-bold flex items-center justify-center ${
            i < current ? 'bg-primary text-primary-foreground' : i === current ? 'bg-primary/15 text-primary border border-primary' : 'bg-foreground/10 text-muted-foreground'
          }`}>{i < current ? <Check className="w-3 h-3" /> : i + 1}</span>
          <span className={`text-[11px] ${i === current ? 'text-foreground font-medium' : 'text-muted-foreground'}`}>{s}</span>
          {i < steps.length - 1 && <span className="w-4 h-px bg-foreground/15" />}
        </li>
      ))}
    </ol>
  )
}

function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-muted-foreground">{label}</Label>
        <button
          type="button"
          className="text-[11px] text-primary inline-flex items-center gap-1"
          onClick={async () => {
            try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }
            catch { toast.error('Copy failed') }
          }}
        >
          {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />} {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="text-[11px] font-mono bg-foreground/5 border border-foreground/10 rounded-md p-2 max-h-40 overflow-auto whitespace-pre-wrap break-all">{value}</pre>
    </div>
  )
}

function ValidationResult({ validation, error }: { validation: CloudValidation | null; error: unknown }) {
  const ok = !!validation?.ok
  const hint = error instanceof CloudApiError ? error.hint : validation?.error?.hint
  const gcp = isGcpCapabilities(validation?.capabilities) ? validation!.capabilities as Parameters<typeof GcpCapabilityList>[0]['capabilities'] : null
  return (
    <div className="space-y-3">
      <div className={`flex items-start gap-3 p-3 rounded-lg border ${ok ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/20 bg-red-500/5'}`}>
        {ok ? <CheckCircle2 className="w-5 h-5 text-green-500 shrink-0" /> : <XCircle className="w-5 h-5 text-red-400 shrink-0" />}
        <div className="text-sm">
          <p className={`font-medium ${ok ? 'text-green-500' : 'text-red-400'}`}>
            {ok ? (gcp ? 'Google Cloud connected' : 'Connection successful') : 'Connection failed'}
          </p>
          {ok && validation?.accountLabel && <p className="text-xs text-muted-foreground mt-0.5">{validation.accountLabel}</p>}
          {!ok && <p className="text-xs text-muted-foreground mt-0.5">{validation?.error?.message ?? errorMessage(error)}</p>}
          {!ok && hint && <p className="text-xs text-muted-foreground mt-1">{hint}</p>}
        </div>
      </div>
      {ok && gcp ? (
        <GcpCapabilityList capabilities={gcp} />
      ) : validation?.checks?.length ? (
        <ul className="space-y-1.5">
          {validation.checks.map((c) => {
            const state = c.state ?? (c.ok ? 'ok' : 'failed')
            return (
              <li key={c.name} className="flex items-start gap-2 text-xs">
                {state === 'ok' ? <Check className="w-3.5 h-3.5 text-green-500 mt-0.5 shrink-0" />
                  : state === 'warning' ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400 mt-0.5 shrink-0" />
                  : <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />}
                <span className="text-foreground">{c.name}</span>
                <span className="text-muted-foreground">— {c.detail}</span>
              </li>
            )
          })}
        </ul>
      ) : null}
    </div>
  )
}

function useConnectFlow(onConnected: ConnectProps['onConnected']) {
  const [phase, setPhase] = useState<Phase>('form')
  const [validation, setValidation] = useState<CloudValidation | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [integration, setIntegration] = useState<CloudIntegration | null>(null)
  const [syncing, setSyncing] = useState(false)

  async function submit(build: () => Parameters<typeof createIntegration>[0], clearSecrets: () => void) {
    setPhase('validating'); setError(null); setValidation(null)
    const input = build()
    clearSecrets()  // secrets leave component state as soon as they are sent
    try {
      const res = await createIntegration(input)
      setValidation(res.validation)
      setIntegration(res.integration)
    } catch (err) {
      setError(err)
      if (err instanceof CloudApiError && err.validation) setValidation(err.validation)
    } finally {
      setPhase('result')
    }
  }

  async function syncNow(close: () => void) {
    if (!integration) return
    setSyncing(true)
    try {
      const { syncId } = await startSync(integration.integrationId)
      onConnected(integration, syncId)
      toast.success('Sync started')
      close()
    } catch (err) {
      toast.error('Could not start sync', { description: errorMessage(err) })
    } finally {
      setSyncing(false)
    }
  }

  function reset() { setPhase('form'); setValidation(null); setError(null); setIntegration(null) }

  return { phase, setPhase, validation, error, integration, syncing, submit, syncNow, reset }
}

// ── AWS ───────────────────────────────────────────────────────────────

export function ConnectAwsDialog({ open, onClose, onConnected, credentialStorageConfigured }: ConnectProps) {
  const [setup, setSetup] = useState<AwsSetupInfo | null>(null)
  const [setupError, setSetupError] = useState<unknown>(null)
  const [method, setMethod] = useState<'assume_role' | 'access_key'>('assume_role')
  const [name, setName] = useState('')
  const [roleArn, setRoleArn] = useState('')
  const [regions, setRegions] = useState('us-east-1')
  const [accessKeyId, setAccessKeyId] = useState('')
  const [secretAccessKey, setSecretAccessKey] = useState('')
  const flow = useConnectFlow(onConnected)

  useEffect(() => {
    if (!open) return
    setSetup(null); setSetupError(null)
    getAwsSetup().then((s) => {
      setSetup(s)
      if (!s.roleAuthAvailable) setMethod('access_key')
    }).catch(setSetupError)
  }, [open])

  function close() {
    setName(''); setRoleArn(''); setRegions('us-east-1'); setAccessKeyId(''); setSecretAccessKey('')
    flow.reset(); onClose()
  }

  const regionList = regions.split(/[\s,]+/).map((r) => r.trim()).filter(Boolean)
  const canSubmit = regionList.length > 0 && (
    method === 'assume_role' ? /^arn:aws(-us-gov)?:iam::\d{12}:role\/.+/.test(roleArn.trim()) && !!setup?.roleAuthAvailable
      : /^AKIA[A-Z0-9]{16}$/.test(accessKeyId.trim()) && secretAccessKey.trim().length === 40 && credentialStorageConfigured
  )
  const step = flow.phase === 'form' ? 1 : flow.phase === 'validating' ? 2 : flow.validation?.ok ? 4 : 2

  return (
    <Dialog open={open} onOpenChange={(o) => !o && flow.phase !== 'validating' && close()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base">Connect AWS</DialogTitle>
          <DialogDescription className="text-xs">
            Import findings from AWS Security Hub. Vectra only needs read access.
          </DialogDescription>
        </DialogHeader>
        <Stepper steps={['Authentication', 'Account', 'Validate', 'Connected', 'Sync']} current={step} />

        {flow.phase === 'form' && (
          <div className="space-y-4">
            {setupError ? <p className="text-xs text-red-400">{errorMessage(setupError)}</p> : null}
            {!setup && !setupError ? <CardSkeleton lines={3} /> : (
              <>
                <div className="grid sm:grid-cols-2 gap-2">
                  {([
                    ['assume_role', 'IAM role', 'Recommended. No keys are shared.', ShieldCheck, !!setup?.roleAuthAvailable],
                    ['access_key', 'Access key', 'Read-only IAM user key, stored encrypted.', KeyRound, credentialStorageConfigured],
                  ] as const).map(([key, label, desc, Icon, enabled]) => (
                    <button
                      key={key} type="button" disabled={!enabled}
                      onClick={() => setMethod(key)}
                      className={`text-left p-3 rounded-lg border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                        method === key ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'}`}
                    >
                      <Icon className="w-4 h-4 text-primary mb-1.5" />
                      <p className="text-sm font-medium text-foreground">{label}</p>
                      <p className="text-[11px] text-muted-foreground">{enabled ? desc : 'Not available on this deployment.'}</p>
                    </button>
                  ))}
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Display name (optional)</Label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="Production AWS" className={fieldCls} />
                </div>

                {method === 'assume_role' && setup && (
                  <div className="space-y-3">
                    <ol className="text-xs text-muted-foreground list-decimal pl-4 space-y-1">
                      <li>In IAM, create a role that trusts Vectra using the trust policy below.</li>
                      <li>Attach the permissions policy (read-only Security Hub access).</li>
                      <li>Paste the role ARN here.</li>
                    </ol>
                    {setup.externalId && <CopyBlock label="External ID (unique to your organization)" value={setup.externalId} />}
                    {setup.trustPolicy && <CopyBlock label="Trust policy" value={setup.trustPolicy} />}
                    <CopyBlock label="Permissions policy" value={setup.permissionsPolicy} />
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">Role ARN</Label>
                      <Input value={roleArn} onChange={(e) => setRoleArn(e.target.value)} placeholder="arn:aws:iam::123456789012:role/VectraSecurityAudit" className={`${fieldCls} font-mono`} />
                    </div>
                  </div>
                )}

                {method === 'access_key' && setup && (
                  <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                      Create a dedicated IAM user with only this policy. The secret is encrypted by the Vectra backend and never shown again.
                    </p>
                    <CopyBlock label="Permissions policy" value={setup.permissionsPolicy} />
                    <div className="grid sm:grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Access key ID</Label>
                        <Input value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} autoComplete="off" spellCheck={false} className={`${fieldCls} font-mono`} />
                      </div>
                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Secret access key</Label>
                        <Input type="password" value={secretAccessKey} onChange={(e) => setSecretAccessKey(e.target.value)} autoComplete="new-password" spellCheck={false} className={`${fieldCls} font-mono`} />
                      </div>
                    </div>
                  </div>
                )}

                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Regions (comma-separated)</Label>
                  <Input value={regions} onChange={(e) => setRegions(e.target.value)} placeholder="us-east-1, eu-west-1" className={`${fieldCls} font-mono`} />
                  <p className="text-[11px] text-muted-foreground/70">
                    If Security Hub cross-Region aggregation is enabled, the aggregation Region alone is enough.
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {flow.phase === 'validating' && (
          <div className="flex flex-col items-center gap-2 py-10" role="status">
            <Loader2 className="w-7 h-7 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Validating access to Security Hub…</p>
          </div>
        )}

        {flow.phase === 'result' && <ValidationResult validation={flow.validation} error={flow.error} />}

        <DialogFooter>
          {flow.phase === 'form' && (
            <>
              <Button variant="ghost" onClick={close}>Cancel</Button>
              <Button disabled={!canSubmit} onClick={() => flow.submit(() => ({
                provider: 'aws', authMethod: method, displayName: name.trim() || undefined,
                config: method === 'assume_role' ? { regions: regionList, roleArn: roleArn.trim() } : { regions: regionList },
                credentials: method === 'access_key' ? { accessKeyId: accessKeyId.trim(), secretAccessKey: secretAccessKey.trim() } : undefined,
              }), () => { setSecretAccessKey(''); setAccessKeyId('') })}>
                Validate &amp; connect
              </Button>
            </>
          )}
          {flow.phase === 'result' && !flow.validation?.ok && (
            <>
              <Button variant="ghost" onClick={close}>Close</Button>
              <Button onClick={() => flow.setPhase('form')}>Back</Button>
            </>
          )}
          {flow.phase === 'result' && flow.validation?.ok && flow.integration && (
            <>
              <Button variant="ghost" onClick={() => { onConnected(flow.integration!); close() }}>Done</Button>
              <Button loading={flow.syncing} loadingText="Starting…" onClick={() => flow.syncNow(close)}>Sync findings</Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Google Cloud ─────────────────────────────────────────────────────

export function ConnectGcpDialog({ open, onClose, onConnected, credentialStorageConfigured }: ConnectProps) {
  const [setup, setSetup] = useState<GcpSetupInfo | null>(null)
  const [name, setName] = useState('')
  const [keyText, setKeyText] = useState('')
  const [keyEmail, setKeyEmail] = useState<string | null>(null)
  const [scopeType, setScopeType] = useState<'project' | 'folder' | 'organization'>('project')
  const [scopeId, setScopeId] = useState('')
  const [location, setLocation] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const flow = useConnectFlow(onConnected)

  useEffect(() => {
    if (!open) return
    getGcpSetup().then(setSetup).catch(() => setSetup({ requiredRole: 'roles/securitycenter.findingsViewer', requiredApi: 'securitycenter.googleapis.com' }))
  }, [open])

  useEffect(() => {
    try {
      const parsed = keyText ? JSON.parse(keyText) : null
      setKeyEmail(parsed?.type === 'service_account' && typeof parsed.client_email === 'string' ? parsed.client_email : null)
    } catch {
      setKeyEmail(null)
    }
  }, [keyText])

  function close() {
    setName(''); setKeyText(''); setScopeId(''); setLocation(''); setScopeType('project')
    if (fileRef.current) fileRef.current.value = ''
    flow.reset(); onClose()
  }

  async function loadFile(file: File | undefined) {
    if (!file) return
    if (file.size > 16_000) { toast.error('Key file is too large'); return }
    setKeyText(await file.text())
  }

  const scopeValid = scopeType === 'project' ? /^([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{1,20})$/.test(scopeId.trim()) : /^\d{1,20}$/.test(scopeId.trim())
  const canSubmit = credentialStorageConfigured && !!keyEmail && scopeValid
  const step = flow.phase === 'form' ? (keyEmail ? 1 : 0) : flow.phase === 'validating' ? 2 : flow.validation?.ok ? 4 : 2

  return (
    <Dialog open={open} onOpenChange={(o) => !o && flow.phase !== 'validating' && close()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-base">Connect Google Cloud</DialogTitle>
          <DialogDescription className="text-xs">
            Analyze your Google Cloud configuration with a read-only service account. Security Command Center findings are imported too when it is available.
          </DialogDescription>
        </DialogHeader>
        <Stepper steps={['Authentication', 'Scope', 'Validate', 'Connected', 'Sync']} current={step} />

        {flow.phase === 'form' && (
          <div className="space-y-4">
            {!credentialStorageConfigured && (
              <p className="text-xs text-red-400">Credential storage is not configured on this Vectra deployment, so key-based connections are unavailable.</p>
            )}
            <ol className="text-xs text-muted-foreground list-decimal pl-4 space-y-1">
              <li>Create a dedicated service account and give it read-only access with the custom role below. Never grant Owner or Editor.</li>
              <li>
                Optional: if Security Command Center is activated, also grant <span className="font-mono">{setup?.optionalRole ?? setup?.requiredRole ?? 'roles/securitycenter.findingsViewer'}</span>.
                Without it, Vectra still discovers resources and analyzes their configuration.
              </li>
              <li>Create a JSON key for the service account and upload it below. It is encrypted by the backend and never shown again.</li>
            </ol>
            {setup?.customRoleCommand && <CopyBlock label="Least-privilege role (gcloud)" value={setup.customRoleCommand} />}

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Display name (optional)</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="Production GCP" className={fieldCls} />
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label className="text-xs text-muted-foreground">Service account key (JSON)</Label>
                <button type="button" className="text-[11px] text-primary inline-flex items-center gap-1" onClick={() => fileRef.current?.click()}>
                  <Upload className="w-3 h-3" /> Upload file
                </button>
                <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => loadFile(e.target.files?.[0])} />
              </div>
              <Textarea
                value={keyText} onChange={(e) => setKeyText(e.target.value)} rows={4} spellCheck={false} autoComplete="off"
                placeholder='{"type": "service_account", ...}' className="text-[11px] font-mono bg-background/50 border-foreground/20"
              />
              {keyText && (keyEmail
                ? <p className="text-[11px] text-green-500">Service account: {keyEmail}</p>
                : <p className="text-[11px] text-red-400">This is not a service account key JSON file.</p>)}
            </div>

            <div className="grid sm:grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">Scope</Label>
                <select value={scopeType} onChange={(e) => setScopeType(e.target.value as typeof scopeType)}
                  className="w-full h-9 rounded-md bg-background/50 border border-foreground/20 px-2 text-sm text-foreground">
                  <option value="project" className="bg-card">Project</option>
                  <option value="folder" className="bg-card">Folder</option>
                  <option value="organization" className="bg-card">Organization</option>
                </select>
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label className="text-xs text-muted-foreground">{scopeType === 'project' ? 'Project ID or number' : `${scopeType === 'folder' ? 'Folder' : 'Organization'} ID`}</Label>
                <Input value={scopeId} onChange={(e) => setScopeId(e.target.value)} placeholder={scopeType === 'project' ? 'acme-prod' : '123456789012'} className={`${fieldCls} font-mono`} />
              </div>
            </div>
            {scopeType !== 'project' && (
              <p className="text-[11px] text-orange-400">
                Folder and organization scopes import Security Command Center findings only. Resource discovery and configuration analysis run per project.
              </p>
            )}
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Location (optional)</Label>
              <Input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="Leave empty unless you use data residency" className={`${fieldCls} font-mono`} />
            </div>
          </div>
        )}

        {flow.phase === 'validating' && (
          <div className="flex flex-col items-center gap-2 py-10" role="status">
            <Loader2 className="w-7 h-7 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Checking access to your Google Cloud resources…</p>
          </div>
        )}

        {flow.phase === 'result' && <ValidationResult validation={flow.validation} error={flow.error} />}

        <DialogFooter>
          {flow.phase === 'form' && (
            <>
              <Button variant="ghost" onClick={close}>Cancel</Button>
              <Button disabled={!canSubmit} onClick={() => flow.submit(() => ({
                provider: 'gcp', authMethod: 'service_account_key', displayName: name.trim() || undefined,
                config: { scopeType, scopeId: scopeId.trim(), location: location.trim() || undefined },
                credentials: { serviceAccountKey: keyText },
              }), () => { setKeyText(''); if (fileRef.current) fileRef.current.value = '' })}>
                Validate &amp; connect
              </Button>
            </>
          )}
          {flow.phase === 'result' && !flow.validation?.ok && (
            <>
              <Button variant="ghost" onClick={close}>Close</Button>
              <Button onClick={() => flow.setPhase('form')}>Back</Button>
            </>
          )}
          {flow.phase === 'result' && flow.validation?.ok && flow.integration && (
            <>
              <Button variant="ghost" onClick={() => { onConnected(flow.integration!); close() }}>Done</Button>
              <Button loading={flow.syncing} loadingText="Starting…" onClick={() => flow.syncNow(close)}>Analyze now</Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
