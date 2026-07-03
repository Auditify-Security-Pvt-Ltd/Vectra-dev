/**
 * Role-Based Access Control definitions.
 * OrgRole is the canonical role used for all permission checks.
 */

export type OrgRole = 'admin' | 'editor' | 'viewer'

// Map legacy platform roles to OrgRole for backwards compatibility
import type { UserRole } from '@/context/auth-context'

export function platformRoleToOrgRole(role: UserRole): OrgRole {
  if (role === 'team_admin') return 'admin'
  if (role === 'analyst')    return 'editor'
  return 'viewer'
}

export interface Permissions {
  // Pages
  viewDashboard:       boolean
  viewWebSecurity:     boolean
  viewNetworkSecurity: boolean
  viewSast:            boolean
  viewCloud:           boolean
  viewVulnMgmt:        boolean
  viewReports:         boolean
  viewAiAnalysis:      boolean
  viewTeam:            boolean
  viewSettings:        boolean
  // Scan actions
  startScan:           boolean
  stopScan:            boolean
  deleteScan:          boolean
  // Finding actions
  assignFindings:      boolean
  commentFindings:     boolean
  changeStatus:        boolean
  deleteFindings:      boolean
  // Report actions
  generateReports:     boolean
  exportReports:       boolean
  // Team actions
  inviteMembers:       boolean
  removeMembers:       boolean
  changeRoles:         boolean
  disableMembers:      boolean
  viewAuditLogs:       boolean
  // Org settings
  configureSla:        boolean
}

export const ROLE_PERMISSIONS: Record<OrgRole, Permissions> = {
  admin: {
    viewDashboard:       true,
    viewWebSecurity:     true,
    viewNetworkSecurity: true,
    viewSast:            true,
    viewCloud:           true,
    viewVulnMgmt:        true,
    viewReports:         true,
    viewAiAnalysis:      true,
    viewTeam:            true,
    viewSettings:        true,
    startScan:           true,
    stopScan:            true,
    deleteScan:          true,
    assignFindings:      true,
    commentFindings:     true,
    changeStatus:        true,
    deleteFindings:      true,
    generateReports:     true,
    exportReports:       true,
    inviteMembers:       true,
    removeMembers:       true,
    changeRoles:         true,
    disableMembers:      true,
    viewAuditLogs:       true,
    configureSla:        true,
  },
  editor: {
    viewDashboard:       true,
    viewWebSecurity:     true,
    viewNetworkSecurity: true,
    viewSast:            true,
    viewCloud:           false,
    viewVulnMgmt:        true,
    viewReports:         true,
    viewAiAnalysis:      true,
    viewTeam:            false,
    viewSettings:        false,
    startScan:           true,
    stopScan:            true,
    deleteScan:          false,
    assignFindings:      true,
    commentFindings:     true,
    changeStatus:        true,
    deleteFindings:      false,
    generateReports:     true,
    exportReports:       true,
    inviteMembers:       false,
    removeMembers:       false,
    changeRoles:         false,
    disableMembers:      false,
    viewAuditLogs:       false,
    configureSla:        false,
  },
  viewer: {
    viewDashboard:       true,
    viewWebSecurity:     false,
    viewNetworkSecurity: false,
    viewSast:            false,
    viewCloud:           false,
    viewVulnMgmt:        true,
    viewReports:         true,
    viewAiAnalysis:      false,
    viewTeam:            false,
    viewSettings:        false,
    startScan:           false,
    stopScan:            false,
    deleteScan:          false,
    assignFindings:      false,
    commentFindings:     false,
    changeStatus:        false,
    deleteFindings:      false,
    generateReports:     false,
    exportReports:       false,
    inviteMembers:       false,
    removeMembers:       false,
    changeRoles:         false,
    disableMembers:      false,
    viewAuditLogs:       false,
    configureSla:        false,
  },
}

export function getPermissions(orgRole: OrgRole): Permissions {
  return ROLE_PERMISSIONS[orgRole]
}

export function hasPermission(orgRole: OrgRole, perm: keyof Permissions): boolean {
  return ROLE_PERMISSIONS[orgRole]?.[perm] ?? false
}

// Sidebar nav items visible per role
export const ROLE_VISIBLE_MODULES: Record<OrgRole, string[]> = {
  admin:  ['web-security', 'network-security', 'sast', 'cloud-security'],
  editor: ['web-security', 'network-security', 'sast'],
  viewer: [],
}

export const ROLE_VISIBLE_BOTTOM: Record<OrgRole, string[]> = {
  admin:  ['vuln-mgmt', 'reports', 'ai-analysis', 'team'],
  editor: ['vuln-mgmt', 'reports', 'ai-analysis'],
  viewer: ['vuln-mgmt', 'reports'],
}
