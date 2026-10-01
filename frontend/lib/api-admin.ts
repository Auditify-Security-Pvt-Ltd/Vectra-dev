import { API_BASE } from './api'
import { authedFetch, type QuotaSnapshot } from './api-auth'

/**
 * Platform administration client.
 *
 * Every call carries the caller's Firebase ID token; the backend re-checks the
 * platform role on each request, so this module is a convenience layer and
 * never the security boundary.
 */

export interface AdminOverview {
  users: { total: number; active: number; inactive: number }
  organizations: { total: number; free: number; nearLimit: number; disabled: number }
  scans: {
    totalTracked: number
    running: number
    queued: number
    completed: number
    failed: number
    cancelled: number
  }
  quota: { planAllowances: Record<string, number>; consumptionRule: string }
}

/** An individual account. Plan and scan quota belong to its organization. */
export interface AdminUser {
  uid:              string
  name:             string | null
  email:            string | null
  role:             string | null   // platform role
  status:           string
  organizationId:   string | null
  organizationName: string | null
  orgRole:          string | null   // role inside the organization
  orgPlan:          string | null
  createdAt:        string | null
  lastLogin:        string | null
}

export interface AdminOrgCounts {
  users:    number | null   // null = could not be computed
  assets:   number | null
  scans:    number | null
  findings: number | null
}

export interface AdminOrganization {
  orgId:      string
  name:       string | null
  website:    string | null
  phone:      string | null
  status:     'active' | 'disabled'
  ownerId:    string | null
  ownerName:  string | null
  ownerEmail: string | null
  createdAt:  string | null
  updatedAt:  string | null
  quota:      QuotaSnapshot
  counts?:    AdminOrgCounts
}

export interface AdminOrgMember {
  uid:           string
  name:          string | null
  email:         string | null
  orgRole:       string | null
  memberStatus:  string
  platformRole:  string | null
  accountStatus: string
  joinedAt:      string | null
}

export interface AdminOrgScan {
  scanId:      string
  scanType:    string
  target:      string | null
  status:      string | null
  userId:      string | null
  createdAt:   string | null
  completedAt: string | null
  findings:    number
}

export interface AdminOrganizationDetail extends AdminOrganization {
  counts:   AdminOrgCounts
  members:  AdminOrgMember[]
  activity: {
    running:   number
    completed: number | null
    failed:    number | null
    live:      AdminTask[]
    recent:    AdminOrgScan[]
  }
}

export interface OrganizationChanges {
  name?:       string
  website?:    string
  phone?:      string
  status?:     'active' | 'disabled'
  plan?:       string
  bonusScans?: number
}

export interface AdminTask {
  scanId:      string
  scanType:    'web' | 'network' | 'sast' | string
  userId:      string
  target:      string | null
  status:      string | null
  progress:    number | null
  currentStep: string | null
  createdAt:   string | null
  completedAt: string | null
  error:       string | null
  findings:    number
  cves:        number
}

export interface AdminAuditLog {
  id:         string
  action:     string
  actorUid:   string
  actorEmail: string | null
  targetUid:  string
  before:     unknown
  after:      unknown
  timestamp:  string
}

/** Surfaces the backend's reason (401/403/503) instead of a generic failure. */
export class AdminApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'AdminApiError'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await authedFetch(`${API_BASE}/admin${path}`, init)
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    const detail = typeof body?.detail === 'string' ? body.detail : body?.detail?.message
    throw new AdminApiError(res.status, detail ?? `Request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export function getOverview(): Promise<AdminOverview> {
  return request<AdminOverview>('/overview')
}

export function listUsers(opts: { search?: string; limit?: number; offset?: number } = {}) {
  const p = new URLSearchParams()
  if (opts.search) p.set('search', opts.search)
  if (opts.limit != null) p.set('limit', String(opts.limit))
  if (opts.offset != null) p.set('offset', String(opts.offset))
  const qs = p.toString()
  return request<{ total: number; limit: number; offset: number; users: AdminUser[] }>(
    `/users${qs ? `?${qs}` : ''}`,
  )
}

export function getUser(uid: string) {
  return request<AdminUser & { tasks: AdminTask[] }>(`/users/${encodeURIComponent(uid)}`)
}

/** Account status only — plan and quota are managed per organization. */
export function updateUser(uid: string, changes: { status: string }) {
  return request<{ uid: string; status: string }>(
    `/users/${encodeURIComponent(uid)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(changes),
    },
  )
}

export function listOrganizations(
  opts: { search?: string; plan?: string; status?: string; limit?: number; offset?: number } = {},
) {
  const p = new URLSearchParams()
  if (opts.search) p.set('search', opts.search)
  if (opts.plan && opts.plan !== 'all') p.set('plan', opts.plan)
  if (opts.status && opts.status !== 'all') p.set('status', opts.status)
  if (opts.limit != null) p.set('limit', String(opts.limit))
  if (opts.offset != null) p.set('offset', String(opts.offset))
  const qs = p.toString()
  return request<{
    total: number; limit: number; offset: number; plans: string[]; organizations: AdminOrganization[]
  }>(`/organizations${qs ? `?${qs}` : ''}`)
}

export function getOrganization(orgId: string) {
  return request<AdminOrganizationDetail>(`/organizations/${encodeURIComponent(orgId)}`)
}

export function updateOrganization(orgId: string, changes: OrganizationChanges) {
  return request<AdminOrganization>(`/organizations/${encodeURIComponent(orgId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(changes),
  })
}

export function getQuotaConfig() {
  return request<{ planAllowances: Record<string, number>; defaultPlan: string; consumptionRule: string }>(
    '/quota/config',
  )
}

export function setPlanAllowance(plan: string, allowance: number) {
  return request<{ planAllowances: Record<string, number> }>('/quota/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plan, allowance }),
  })
}

export function listTasks(
  opts: { status?: string; scanType?: string; userId?: string; search?: string; limit?: number } = {},
) {
  const p = new URLSearchParams()
  if (opts.status && opts.status !== 'all') p.set('status', opts.status)
  if (opts.scanType && opts.scanType !== 'all') p.set('scanType', opts.scanType)
  if (opts.userId) p.set('userId', opts.userId)
  if (opts.search) p.set('search', opts.search)
  if (opts.limit != null) p.set('limit', String(opts.limit))
  const qs = p.toString()
  return request<{ total: number; tasks: AdminTask[] }>(`/tasks${qs ? `?${qs}` : ''}`)
}

export function listAuditLogs(limit = 100) {
  return request<{ total: number; logs: AdminAuditLog[] }>(`/audit-logs?limit=${limit}`)
}

// ── Cloud Security ────────────────────────────────────────────────────

export interface AdminCloudIntegration {
  integrationId:        string
  organizationId:       string
  organizationName:     string | null
  provider:             string
  displayName:          string
  accountId:            string | null
  status:               'connected' | 'error' | 'disconnected'
  syncStatus:           string
  lastSyncAt:           string | null
  lastSyncStatus:       string | null
  lastSyncError:        { code: string; message: string; hint?: string | null } | null
  lastSuccessfulSyncAt: string | null
  lastSyncStats:        { findingsDiscovered: number; apiCalls: number; apiLatencyMs: number } | null
  counts:               { findings: number; open: number; critical: number; high: number; assets: number }
  createdAt:            string
}

/** Integration health across organizations. Never includes credentials. */
export function listCloudIntegrations() {
  return request<{
    total: number
    integrations: AdminCloudIntegration[]
    health: { connected: number; error: number; disconnected: number; failedLastSync: number }
  }>('/cloud/integrations')
}
