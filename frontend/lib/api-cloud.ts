import { API_BASE } from './api'
import { authedFetch } from './api-auth'

/**
 * Cloud Security API client.
 *
 * All cloud data is served by the backend (Firestore rules deny direct client
 * access), so every call carries the Firebase ID token and the backend resolves
 * the organization and role itself. Credentials are only ever sent on connect or
 * rotate and are never returned.
 */

export type CloudProviderKey = 'aws' | 'gcp' | 'azure' | 'vercel' | 'netlify' | string
export type CloudSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type CloudFindingStatus = 'open' | 'resolved' | 'suppressed'
export type CapabilityState = 'available' | 'derived' | 'future'
export type SyncStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed'

export interface CloudAuthMethod {
  key:            string
  label:          string
  description:    string
  recommended:    boolean
  requires_secret: boolean
}

export interface CloudProviderInfo {
  key:             CloudProviderKey
  name:            string
  securityService: string | null
  status:          'available' | 'coming_soon'
  capabilities:    Record<string, CapabilityState>
  authMethods:     CloudAuthMethod[]
  note?:           string
}

export interface CloudError {
  code:    string
  message: string
  hint?:   string | null
  scopes?: { scope: string; code: string; message: string; hint?: string | null }[]
}

export interface ValidationCheck { name: string; ok: boolean; detail: string; state?: 'ok' | 'warning' | 'failed' }

/** State of one capability a connection has (or lacks), with a machine-readable reason. */
export interface CapabilityInfo {
  available: boolean
  status:    'available' | 'unavailable' | 'error'
  reason?:   string
  message?:  string
  hint?:     string | null
  docsUrl?:  string
  label?:    string
  partial?:  boolean
  resources?: number
}

/** Google Cloud capability report (validation and each sync). SCC is optional. */
export interface GcpCapabilities {
  authenticated:          boolean
  project_id?:            string | null
  scope?:                 { type: string; id: string }
  authentication?:        CapabilityInfo
  project?:               CapabilityInfo & { projectId?: string | null; projectNumber?: string | null; displayName?: string | null; hasOrganization?: boolean | null }
  resource_discovery?:    CapabilityInfo & { categories: Record<string, CapabilityInfo> }
  configuration_analysis?: CapabilityInfo
  scc?:                   CapabilityInfo
  checkedAt?:             string
}

export interface CloudValidation {
  ok:           boolean
  accountId:    string | null
  accountLabel: string | null
  checks:       ValidationCheck[]
  scopes:       string[]
  error:        CloudError | null
  validatedAt?: string
  capabilities?: GcpCapabilities | Record<string, never>
}

export interface CloudCounts {
  findings: number; open: number; resolved: number; suppressed: number
  critical: number; high: number; medium: number; low: number; info: number
  assets: number
}

export interface SyncStats {
  findingsDiscovered: number
  newFindings:        number
  updatedFindings:    number
  resolvedFindings:   number
  assetsDiscovered:   number
  apiCalls:           number
  apiLatencyMs:       number
}

export interface CloudIntegration {
  integrationId:        string
  provider:             CloudProviderKey
  displayName:          string
  authMethod:           string
  config:               Record<string, unknown>
  accountId:            string | null
  accountLabel:         string | null
  status:               'connected' | 'error' | 'disconnected'
  validation:           CloudValidation | null
  syncStatus:           'idle' | 'queued' | 'running'
  currentSyncId:        string | null
  lastSyncAt:           string | null
  lastSyncStatus:       SyncStatus | null
  lastSyncError:        CloudError | null
  lastSuccessfulSyncAt: string | null
  lastSyncStats:        SyncStats | null
  counts:               CloudCounts
  createdBy:            string
  createdAt:            string
  updatedAt:            string
  disconnectedAt:       string | null
  capabilities?:        GcpCapabilities | null
}

export interface CloudSync {
  syncId:        string
  integrationId: string
  provider:      string
  status:        SyncStatus
  trigger:       string
  createdAt:     string
  startedAt:     string | null
  completedAt:   string | null
  durationMs:    number | null
  stats:         SyncStats | null
  failedScopes:  { scope: string; code: string; message: string; hint?: string | null }[]
  skippedScopes?: { scope: string; code: string; reason?: string; message: string; hint?: string | null }[]
  truncated:     boolean
  error:         CloudError | null
}

export interface CloudFindingListItem {
  fingerprint:       string
  provider:          CloudProviderKey
  integrationId:     string
  providerProduct:   string | null
  title:             string
  severity:          CloudSeverity
  providerSeverity:  string | null
  status:            CloudFindingStatus
  findingType:       string | null
  findingClass:      string | null
  assetId:           string | null
  resourceType:      string | null
  resourceId:        string | null
  resourceName:      string | null
  accountId:         string | null
  region:            string | null
  cveId:             string | null
  cveIds:            string[]
  cvssScore:         number | null
  firstSeenAt:       string
  lastSeenAt:        string
  updatedAt:         string
  providerUpdatedAt: string | null
  resolvedAt:        string | null
  /** e.g. gcp-configuration-analysis or gcp-security-command-center; absent for older findings. */
  source?:           string | null
  category?:         string | null
}

export interface AffectedPackage {
  name:            string
  version:         string | null
  fixedInVersion?: string | null
  packageManager?: string | null
  packageType?:    string | null
  cpeUri?:         string | null
  cve?:            string | null
}

export interface CloudFinding extends CloudFindingListItem {
  providerFindingId: string
  description:       string
  providerStatus:    string | null
  cvssVector:        string | null
  affectedPackages:  AffectedPackage[]
  compliance:        { status?: string; securityControlId?: string; relatedRequirements?: string[] }
  recommendation:    string | null
  remediationUrl:    string | null
  sourceUrl:         string | null
  providerCreatedAt: string | null
  firstObservedAt:   string | null
  lastObservedAt:    string | null
  resolvedReason:    string | null
  statusHistory:     { status: CloudFindingStatus; at: string; source: string }[]
  createdAt:         string
  /** Configuration values that justify the finding (configuration analysis). */
  evidence?:         Record<string, unknown>
}

export interface CloudAsset {
  assetId:          string
  provider:         CloudProviderKey
  integrationId:    string
  accountId:        string | null
  region:           string | null
  resourceType:     string
  resourceId:       string
  resourceName:     string | null
  service:          string | null
  tags:             Record<string, string>
  firstSeenAt:      string
  lastSeenAt:       string
  findingCount:     number
  openFindingCount: number
}

export interface CloudSummary {
  integrations:   CloudIntegration[]
  totals:         CloudCounts
  byProvider:     Record<string, { integrations: number; findings: number; open: number; assets: number }>
  health:         { connected: number; error: number; syncing: number; failedLastSync: number; lastSyncAt: string | null }
  recentFindings: CloudFindingListItem[]
}

export interface FindingFacets {
  providers:      string[]
  regions:        string[]
  resourceTypes:  string[]
  findingTypes:   string[]
  integrationIds: string[]
}

export interface AwsSetupInfo {
  permissionsPolicy:  string
  roleAuthAvailable:  boolean
  vectraPrincipalArn: string | null
  externalId:         string | null
  trustPolicy?:       string
  setupError?:        CloudError
}

export interface GcpSetupInfo {
  requiredRole: string
  requiredApi:  string
  requiredPermissions?: string[]
  optionalPermissions?: string[]
  optionalRole?:        string
  sccDocsUrl?:          string
  customRoleCommand?:   string
}

/** Backend refusal with a machine-readable code and user-safe message. */
export class CloudApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly hint?: string | null,
    readonly validation?: CloudValidation,
    readonly syncId?: string,
  ) {
    super(message)
    this.name = 'CloudApiError'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await authedFetch(`${API_BASE}/cloud${path}`, init)
  } catch (err) {
    if (err instanceof Error && err.name !== 'TypeError') throw err
    throw new CloudApiError(0, 'NETWORK', 'Could not reach the Vectra backend.')
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    const d = body?.detail
    if (d && typeof d === 'object') {
      throw new CloudApiError(res.status, d.code ?? 'ERROR', d.message ?? `Request failed (${res.status})`,
        d.hint, d.validation, d.syncId)
    }
    if (res.status === 422) throw new CloudApiError(422, 'INVALID_INPUT', 'Some fields are invalid.')
    throw new CloudApiError(res.status, 'ERROR', typeof d === 'string' ? d : `Request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || v === 'all') continue
    p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

// ── Providers ─────────────────────────────────────────────────────────

export function listCloudProviders() {
  return request<{ providers: CloudProviderInfo[]; credentialStorageConfigured: boolean; permissions: string[] }>('/providers')
}

export function getAwsSetup() {
  return request<AwsSetupInfo & { provider: 'aws' }>('/providers/aws/setup')
}

export function getGcpSetup() {
  return request<GcpSetupInfo & { provider: 'gcp' }>('/providers/gcp/setup')
}

// ── Integrations ──────────────────────────────────────────────────────

export function listIntegrations(includeDisconnected = false) {
  return request<{ integrations: CloudIntegration[] }>(`/integrations${qs({ includeDisconnected: includeDisconnected || undefined })}`)
}

export function getIntegration(id: string) {
  return request<{ integration: CloudIntegration }>(`/integrations/${encodeURIComponent(id)}`)
}

export interface CreateIntegrationInput {
  provider:     'aws' | 'gcp'
  displayName?: string
  authMethod:   string
  config:       Record<string, unknown>
  credentials?: Record<string, unknown>
}

export function createIntegration(input: CreateIntegrationInput) {
  return request<{ integration: CloudIntegration; validation: CloudValidation }>('/integrations', json('POST', input))
}

export function updateIntegration(
  id: string,
  changes: { displayName?: string; config?: Record<string, unknown>; credentials?: Record<string, unknown> },
) {
  return request<{ integration: CloudIntegration; validation: CloudValidation | null }>(
    `/integrations/${encodeURIComponent(id)}`, json('PATCH', changes))
}

export function validateIntegration(id: string) {
  return request<{ validation: CloudValidation }>(`/integrations/${encodeURIComponent(id)}/validate`, { method: 'POST' })
}

export function startSync(id: string) {
  return request<{ syncId: string; status: SyncStatus; provider: string }>(
    `/integrations/${encodeURIComponent(id)}/sync`, { method: 'POST' })
}

export function listSyncs(id: string, limit = 10) {
  return request<{ syncs: CloudSync[] }>(`/integrations/${encodeURIComponent(id)}/syncs?limit=${limit}`)
}

export function getSync(syncId: string) {
  return request<{ sync: CloudSync }>(`/syncs/${encodeURIComponent(syncId)}`)
}

export function disconnectIntegration(id: string, deleteFindings = false) {
  return request<{ integrationId: string; status: string; removed: { findings: number; assets: number } }>(
    `/integrations/${encodeURIComponent(id)}${qs({ deleteFindings: deleteFindings || undefined })}`, { method: 'DELETE' })
}

// ── Findings, assets, summary, reports ────────────────────────────────

export interface FindingQuery {
  search?:        string
  provider?:      string
  severity?:      string
  status?:        string
  resourceType?:  string
  region?:        string
  cve?:           string
  findingType?:   string
  integrationId?: string
  sort?:          'severity' | 'newest' | 'updated'
  limit?:         number
  offset?:        number
}

export function listCloudFindings(q: FindingQuery = {}) {
  return request<{ total: number; limit: number; offset: number; findings: CloudFindingListItem[]; facets: FindingFacets }>(
    `/findings${qs({ ...q })}`)
}

/** Every finding matching `q`, paged server-side (capped to protect the browser). */
export async function listAllCloudFindings(q: FindingQuery = {}, cap = 2000): Promise<CloudFindingListItem[]> {
  const out: CloudFindingListItem[] = []
  for (let offset = 0; offset < cap; offset += 200) {
    const page = await listCloudFindings({ ...q, limit: 200, offset })
    out.push(...page.findings)
    if (out.length >= page.total || page.findings.length === 0) break
  }
  return out.slice(0, cap)
}

export function getCloudFinding(fingerprint: string) {
  return request<{
    finding: CloudFinding & { providerMetadata: unknown }
    asset: CloudAsset | null
    integration: Pick<CloudIntegration, 'integrationId' | 'displayName' | 'provider' | 'status' | 'accountLabel'> | null
  }>(`/findings/${encodeURIComponent(fingerprint)}`)
}

export function listCloudAssets(q: { search?: string; provider?: string; resourceType?: string; integrationId?: string; limit?: number; offset?: number } = {}) {
  return request<{ total: number; limit: number; offset: number; assets: CloudAsset[]; facets: { resourceTypes: string[] } }>(
    `/assets${qs({ ...q })}`)
}

export function getCloudSummary() {
  return request<CloudSummary>('/summary')
}

export function getCloudReportData(integrationId = 'all', includeResolved = false) {
  return request<{
    integrations: CloudIntegration[]
    findings:     CloudFinding[]
    assets:       CloudAsset[]
    truncated:    boolean
    totalFindings: number
  }>(`/report-data?integrationId=${encodeURIComponent(integrationId)}${includeResolved ? '&includeResolved=true' : ''}`)
}

// ── Display helpers ───────────────────────────────────────────────────

export const PROVIDER_LABEL: Record<string, string> = {
  aws: 'AWS', gcp: 'Google Cloud', azure: 'Azure', vercel: 'Vercel', netlify: 'Netlify',
}

export function providerLabel(key: string | null | undefined): string {
  return key ? PROVIDER_LABEL[key] ?? key.toUpperCase() : '—'
}
