import {
  collection,
  getDocs,
  query,
  where,
} from 'firebase/firestore'
import { db } from './firebase'
import type { FirestoreScan } from './firestore-scans'
import type { FirestoreFinding } from './firestore-findings'
import type { FirestoreCve } from './firestore-cves'
import type { FirestoreAsset } from './firestore-assets'

// ── Types ─────────────────────────────────────────────────────────────

export interface ReportData {
  target: string
  scan: FirestoreScan | null
  findings: FirestoreFinding[]
  cves: FirestoreCve[]
  assets: FirestoreAsset[]
  reportId: string
  generatedBy: string
}

export interface ReportTarget {
  target: string
  findingsCount: number
  cveCount: number
  assetCount: number
  latestScan: FirestoreScan | null
  latestScanDate: string
  latestStatus: string
}

// ── Constants ─────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

const CVSS_SCORE: Record<string, number> = { critical: 9.1, high: 7.5, medium: 5.3, low: 3.1, info: 0.0, unknown: 0.0 }
const RISK_SCORE: Record<string, number> = { critical: 92, high: 74, medium: 51, low: 24, info: 8, unknown: 0 }

// Severity fill / text RGB for PDF cells
const SEV_FILL: Record<string, [number, number, number]> = {
  critical: [254, 226, 226],
  high:     [255, 237, 213],
  medium:   [254, 249, 195],
  low:      [219, 234, 254],
  info:     [243, 244, 246],
}
const SEV_TEXT: Record<string, [number, number, number]> = {
  critical: [185, 28, 28],
  high:     [154, 52, 18],
  medium:   [133, 77, 14],
  low:      [29, 78, 216],
  info:     [75, 85, 99],
}

// Key remediation per template (for Excel recommendations sheet)
const TEMPLATE_REM: Record<string, string> = {
  'vectra-clickjacking':           "Add X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none' headers",
  'vectra-git-exposure':           'Block access to .git directory at web server level and rotate all exposed credentials',
  'vectra-backup-exposure':        'Remove all backup files from the web root and audit for similar exposures',
  'vectra-debug-endpoint':         'Disable or restrict all debug/diagnostic endpoints in production environments',
  'vectra-directory-listing':      "Set 'Options -Indexes' (Apache) or ensure 'autoindex off' (Nginx) in server config",
  'vectra-admin-panel':            'Restrict admin panel access to specific IPs/VPN and enforce MFA',
  'vectra-missing-rate-limit':     'Implement token-bucket or sliding-window rate limiting on all API endpoints',
  'vectra-sensitive-file':         'Remove sensitive files from the web root and audit access logs for prior access',
  'vectra-swagger-exposure':       'Restrict Swagger UI and OpenAPI spec to authenticated users or internal networks only',
  'vectra-missing-csp':            "Add Content-Security-Policy header with strict directives (default-src 'self')",
  'vectra-missing-hsts':           'Add Strict-Transport-Security: max-age=31536000; includeSubDomains header',
  'vectra-missing-xfo':            'Add X-Frame-Options: DENY header and CSP frame-ancestors directive',
  'vectra-missing-xcto':           'Add X-Content-Type-Options: nosniff header to all HTTP responses',
  'vectra-missing-referrer-policy':'Add Referrer-Policy: strict-origin-when-cross-origin header',
  'vectra-missing-permissions-policy': 'Add Permissions-Policy header restricting camera, microphone, and geolocation',
}

function getRemediation(f: FirestoreFinding): string {
  return TEMPLATE_REM[f.template ?? ''] ?? `Review and remediate the "${f.title}" vulnerability per your security policy.`
}

// ── Data helpers ──────────────────────────────────────────────────────

function matchesTarget(url: string, target: string): boolean {
  try {
    const src = url.startsWith('http') ? url : `https://${url}`
    const hostname = new URL(src).hostname.replace(/^www\./, '')
    const clean    = target.replace(/^www\./, '').replace(/^https?:\/\//, '').split('/')[0]
    return hostname === clean || hostname.endsWith('.' + clean)
  } catch {
    return url.includes(target)
  }
}

function matchesDomain(domain: string, target: string): boolean {
  const clean = target.replace(/^www\./, '').replace(/^https?:\/\//, '').split('/')[0]
  const d     = domain.replace(/^www\./, '')
  return d === clean || d.endsWith('.' + clean)
}

// ── Reportable targets — built from data collections, not scan status ─

export async function getReportableTargets(uid: string): Promise<ReportTarget[]> {
  const [findingsSnap, cvesSnap, assetsSnap, scansSnap] = await Promise.all([
    getDocs(collection(db, 'users', uid, 'findings')),
    getDocs(collection(db, 'users', uid, 'cves')),
    getDocs(collection(db, 'users', uid, 'assets')),
    getDocs(collection(db, 'users', uid, 'scans')),
  ])

  const allFindings = findingsSnap.docs.map((d) => d.data() as FirestoreFinding)
  const allCves     = cvesSnap.docs.map((d) => d.data() as FirestoreCve)
  const allAssets   = assetsSnap.docs.map((d) => d.data() as FirestoreAsset)
  const allScans    = scansSnap.docs.map((d) => d.data() as FirestoreScan)

  // Collect unique targets: findings are the primary source (they store target directly)
  // Also add scan targets so we catch scans with assets/CVEs but zero findings
  const targetSet = new Set<string>()
  allFindings.forEach((f) => { if (f.target) targetSet.add(f.target) })
  allScans.forEach((s)    => { if (s.target) targetSet.add(s.target) })

  // Index scans by target for quick latest-scan lookup
  const scansByTarget = new Map<string, FirestoreScan[]>()
  allScans.forEach((s) => {
    if (!scansByTarget.has(s.target)) scansByTarget.set(s.target, [])
    scansByTarget.get(s.target)!.push(s)
  })

  const result: ReportTarget[] = []

  for (const target of targetSet) {
    const findingsCount = allFindings.filter((f) => f.target === target).length

    // Scan IDs for this target — used as fallback for CVE/asset matching
    const targetScanIds = new Set(
      (scansByTarget.get(target) ?? []).map((s) => s.scanId),
    )

    const cveCount = allCves.filter((c) => {
      if (c.assetUrl && matchesTarget(c.assetUrl, target)) return true
      if (c.discoveryId && targetScanIds.has(c.discoveryId)) return true
      return false
    }).length

    const assetCount = allAssets.filter((a) => {
      if (matchesDomain(a.domain ?? '', target)) return true
      if (a.discoveryId && targetScanIds.has(a.discoveryId)) return true
      return false
    }).length

    // Skip targets with absolutely no data
    if (findingsCount === 0 && cveCount === 0 && assetCount === 0) continue

    const scans     = (scansByTarget.get(target) ?? [])
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    const latestScan = scans[0] ?? null

    result.push({
      target,
      findingsCount,
      cveCount,
      assetCount,
      latestScan,
      latestScanDate: latestScan?.completedAt ?? latestScan?.createdAt ?? new Date().toISOString(),
      latestStatus:   latestScan?.status ?? 'unknown',
    })
  }

  // Sort: most findings first, then most CVEs
  return result.sort((a, b) => b.findingsCount - a.findingsCount || b.cveCount - a.cveCount)
}

// ── Report data fetch — by target, across all scans ───────────────────

export async function fetchReportDataByTarget(
  uid: string,
  target: string,
): Promise<{ findings: FirestoreFinding[]; cves: FirestoreCve[]; assets: FirestoreAsset[]; latestScan: FirestoreScan | null }> {
  const [findingsSnap, cvesSnap, assetsSnap, scansSnap] = await Promise.all([
    getDocs(query(collection(db, 'users', uid, 'findings'), where('target', '==', target))),
    getDocs(collection(db, 'users', uid, 'cves')),
    getDocs(collection(db, 'users', uid, 'assets')),
    getDocs(collection(db, 'users', uid, 'scans')),
  ])

  const findings = findingsSnap.docs
    .map((d) => d.data() as FirestoreFinding)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  // Collect scan IDs for this target — used as a fallback CVE matcher so CVEs
  // are always linked even when assetUrl format differs from the target string.
  const targetScanIds = new Set(
    scansSnap.docs
      .map((d) => d.data() as FirestoreScan)
      .filter((s) => s.target === target)
      .map((s) => s.scanId),
  )

  const cves = cvesSnap.docs
    .map((d) => d.data() as FirestoreCve)
    .filter((c) => {
      // Primary: URL-hostname match
      if (c.assetUrl && matchesTarget(c.assetUrl, target)) return true
      // Fallback: CVE was found during a scan of this exact target
      if (c.discoveryId && targetScanIds.has(c.discoveryId)) return true
      return false
    })
    .sort((a, b) => b.cvssScore - a.cvssScore)

  const assets = assetsSnap.docs
    .map((d) => d.data() as FirestoreAsset)
    .filter((a) => {
      if (matchesDomain(a.domain ?? '', target)) return true
      // Also match by discoveryId so assets from Full Scans are always included
      if (a.discoveryId && targetScanIds.has(a.discoveryId)) return true
      return false
    })
    .sort((a, b) => (a.alive === b.alive ? 0 : a.alive ? -1 : 1))

  const latestScan = scansSnap.docs
    .map((d) => d.data() as FirestoreScan)
    .filter((s) => s.target === target)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0] ?? null

  return { findings, cves, assets, latestScan }
}

// ── Download helper ───────────────────────────────────────────────────

export function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a   = document.createElement('a')
  a.href    = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ── PDF helpers ───────────────────────────────────────────────────────

function drawPageHeader(doc: any, target: string, PW: number, M: number): number {
  doc.setFillColor(15, 15, 15)
  doc.rect(0, 0, PW, 14, 'F')
  doc.setFillColor(124, 58, 237)
  doc.rect(0, 14, PW, 0.8, 'F')

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(8.5)
  doc.setTextColor(255, 255, 255)
  doc.text('VECTRA', M, 9.5)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7.5)
  doc.setTextColor(170, 170, 170)
  doc.text(`Security Assessment | ${target}`, PW - M, 9.5, { align: 'right' })
  return 22
}

function drawSectionTitle(doc: any, title: string, y: number, M: number, CW: number): number {
  doc.setFillColor(245, 245, 245)
  doc.rect(M, y, CW, 9, 'F')
  doc.setFillColor(124, 58, 237)
  doc.rect(M, y, 3, 9, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(9.5)
  doc.setTextColor(15, 15, 15)
  doc.text(title, M + 8, y + 6)
  return y + 15
}

function statBox(
  doc: any, x: number, y: number, w: number, h: number,
  label: string, value: string, col: [number, number, number],
) {
  doc.setDrawColor(220, 220, 220)
  doc.setLineWidth(0.3)
  doc.rect(x, y, w, h)
  doc.setFillColor(...col)
  doc.rect(x, y, 2.5, h, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(15)
  doc.setTextColor(...col)
  doc.text(value, x + w / 2, y + h / 2 + 1, { align: 'center' })
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(6.5)
  doc.setTextColor(107, 114, 128)
  doc.text(label.toUpperCase(), x + w / 2, y + h - 3, { align: 'center' })
}

// Truncate a URL for display in tables — keeps it readable without overflow
function truncUrl(url: string | null | undefined, maxLen = 55): string {
  if (!url) return '—'
  if (url.length <= maxLen) return url
  // Try to keep hostname + path start
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`)
    const short = u.hostname + u.pathname
    return short.length <= maxLen ? short : short.slice(0, maxLen - 1) + '…'
  } catch {
    return url.slice(0, maxLen - 1) + '…'
  }
}

// ── PDF generator ─────────────────────────────────────────────────────

export async function generatePdf(data: ReportData): Promise<Blob> {
  const { default: jsPDF } = await import('jspdf')
  const { default: autoTable } = await import('jspdf-autotable')

  const { target, scan, findings, cves, assets, reportId, generatedBy } = data

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const PW  = 210
  const PH  = 297
  const M   = 14   // margin
  const CW  = PW - 2 * M

  // Table style defaults applied globally
  const tblHead = { fillColor: [20, 20, 20] as [number, number, number], textColor: [255, 255, 255] as [number, number, number], fontStyle: 'bold' as const, fontSize: 8 }
  const tblBody = { fontSize: 8, cellPadding: 2.8, overflow: 'linebreak' as const }

  const C = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high:     findings.filter((f) => f.severity === 'high').length,
    medium:   findings.filter((f) => f.severity === 'medium').length,
    low:      findings.filter((f) => f.severity === 'low').length,
    info:     findings.filter((f) => f.severity === 'info').length,
  }

  const overallRisk =
    C.critical > 0 ? 'Critical' :
    C.high     > 0 ? 'High'     :
    C.medium   > 0 ? 'Medium'   :
    C.low      > 0 ? 'Low'      : 'Informational'

  const riskRgb: [number, number, number] =
    C.critical > 0 ? [185, 28, 28]  :
    C.high     > 0 ? [154, 52, 18]  :
    C.medium   > 0 ? [133, 77, 14]  :
    C.low      > 0 ? [29, 78, 216]  : [75, 85, 99]

  const scanDate = new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString(
    'en-US', { year: 'numeric', month: 'long', day: 'numeric' },
  )

  // ─── COVER PAGE ───────────────────────────────────────────────────

  doc.setFillColor(12, 12, 12)
  doc.rect(0, 0, PW, 75, 'F')
  doc.setFillColor(124, 58, 237)
  doc.rect(0, 75, PW, 2.5, 'F')

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(28)
  doc.setTextColor(255, 255, 255)
  doc.text('VECTRA', M, 30)

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(160, 160, 160)
  doc.text('SECURITY PLATFORM', M, 39)

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(11.5)
  doc.setTextColor(210, 210, 210)
  doc.text('SECURITY ASSESSMENT REPORT', PW - M, 55, { align: 'right' })

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.setTextColor(124, 58, 237)
  doc.text('Web Application Security', PW - M, 64, { align: 'right' })

  // Target block
  doc.setTextColor(100, 100, 100)
  doc.setFontSize(7.5)
  doc.setFont('helvetica', 'bold')
  doc.text('ASSESSMENT TARGET', M, 92)

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(16)
  doc.setTextColor(15, 15, 15)
  // Truncate very long targets so they don't overflow
  const displayTarget = target.length > 50 ? target.slice(0, 48) + '…' : target
  doc.text(displayTarget, M, 103)

  doc.setDrawColor(220, 220, 220)
  doc.setLineWidth(0.25)
  doc.line(M, 108, PW - M, 108)

  // Stat boxes (2 rows × 4)
  const BW  = (CW - 9) / 4
  const BH  = 22
  const BY1 = 114
  const BY2 = 140

  statBox(doc, M,            BY1, BW, BH, 'Total Findings', String(findings.length), [15, 15, 15])
  statBox(doc, M + BW + 3,   BY1, BW, BH, 'Critical',       String(C.critical),      [185, 28, 28])
  statBox(doc, M+(BW+3)*2,   BY1, BW, BH, 'High',           String(C.high),          [154, 52, 18])
  statBox(doc, M+(BW+3)*3,   BY1, BW, BH, 'CVEs Found',     String(cves.length),     [124, 58, 237])
  statBox(doc, M,            BY2, BW, BH, 'Medium',          String(C.medium),        [133, 77, 14])
  statBox(doc, M + BW + 3,   BY2, BW, BH, 'Low',            String(C.low),           [29, 78, 216])
  statBox(doc, M+(BW+3)*2,   BY2, BW, BH, 'Info',           String(C.info),          [75, 85, 99])
  statBox(doc, M+(BW+3)*3,   BY2, BW, BH, 'Assets',         String(assets.length),   [15, 15, 15])

  // Metadata
  let my = 172
  const meta: [string, string][] = [
    ['Assessment Date',   scanDate],
    ['Scan Profile',      scan?.scanProfile ?? scan?.scanType ?? 'Web Security'],
    ['Generated By',      generatedBy],
    ['Report ID',         reportId],
    ['Classification',    'CONFIDENTIAL'],
  ]
  meta.forEach(([label, value], i) => {
    const bg = i % 2 === 0 ? 250 : 255
    doc.setFillColor(bg, bg, bg)
    doc.rect(M, my - 5, CW, 9, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(7.5)
    doc.setTextColor(100, 100, 100)
    doc.text(label, M + 3, my)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(20, 20, 20)
    doc.text(value, M + 56, my)
    my += 9
  })

  doc.setTextColor(190, 190, 190)
  doc.setFontSize(6.5)
  doc.text(
    'This document contains confidential security assessment information. Unauthorized distribution is prohibited.',
    PW / 2, PH - 10, { align: 'center' },
  )

  // ─── PAGE 2: EXECUTIVE SUMMARY ────────────────────────────────────

  doc.addPage()
  let y = drawPageHeader(doc, target, PW, M)
  y = drawSectionTitle(doc, 'Executive Summary', y, M, CW)

  const intro = `This security assessment was conducted against ${target} on ${scanDate}. ` +
    `The assessment identified ${findings.length} security finding${findings.length !== 1 ? 's' : ''} across ` +
    `${assets.length} discovered asset${assets.length !== 1 ? 's' : ''}. ` +
    (cves.length > 0
      ? `CVE correlation analysis identified ${cves.length} known vulnerabilities in the detected technology stack. `
      : '') +
    `Findings are classified by severity and prioritized for remediation.`

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(40, 40, 40)
  const introLines = doc.splitTextToSize(intro, CW)
  doc.text(introLines, M, y)
  y += introLines.length * 5.2 + 7

  // Risk badge
  doc.setFillColor(...riskRgb)
  doc.roundedRect(M, y, 70, 11, 2, 2, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(8.5)
  doc.setTextColor(255, 255, 255)
  doc.text(`OVERALL RISK: ${overallRisk.toUpperCase()}`, M + 35, y + 7.5, { align: 'center' })
  y += 19

  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Count', '% of Total']],
    body: [
      ['Critical', C.critical, findings.length ? `${Math.round((C.critical / findings.length) * 100)}%` : '0%'],
      ['High',     C.high,     findings.length ? `${Math.round((C.high     / findings.length) * 100)}%` : '0%'],
      ['Medium',   C.medium,   findings.length ? `${Math.round((C.medium   / findings.length) * 100)}%` : '0%'],
      ['Low',      C.low,      findings.length ? `${Math.round((C.low      / findings.length) * 100)}%` : '0%'],
      ['Info',     C.info,     findings.length ? `${Math.round((C.info     / findings.length) * 100)}%` : '0%'],
      ['Total',    findings.length, '100%'],
    ],
    headStyles: tblHead,
    styles:     { ...tblBody, cellPadding: 3 },
    columnStyles: { 0: { cellWidth: 45 }, 1: { cellWidth: 30 }, 2: { cellWidth: 'auto' } },
    margin: { left: M, right: M },
    showHead: 'everyPage',
    didParseCell: (data: any) => {
      if (data.section === 'body' && data.column.index === 0) {
        const s = String(data.cell.raw).toLowerCase()
        if (SEV_FILL[s]) {
          data.cell.styles.fillColor = SEV_FILL[s]
          data.cell.styles.textColor = SEV_TEXT[s]
          data.cell.styles.fontStyle = (s === 'critical' || s === 'high') ? 'bold' : 'normal'
        } else {
          data.cell.styles.fillColor = [235, 235, 235]
          data.cell.styles.fontStyle = 'bold'
        }
      }
    },
  })
  y = (doc as any).lastAutoTable.finalY + 14

  // ─── ASSET INVENTORY ──────────────────────────────────────────────

  if (assets.length > 0) {
    if (y > PH - 55) { doc.addPage(); y = drawPageHeader(doc, target, PW, M) }
    y = drawSectionTitle(doc, 'Asset Inventory', y, M, CW)

    autoTable(doc, {
      startY: y,
      head: [['Subdomain / Host', 'IP Address', 'Server', 'Status', 'Technologies']],
      body: assets.slice(0, 80).map((a) => [
        a.subdomain ?? a.domain ?? '',
        a.ip ?? '—',
        a.server ? a.server.slice(0, 22) : '—',
        a.alive ? `${a.statusCode ?? 200}` : 'Offline',
        (a.technologies ?? []).slice(0, 3).join(', ') || '—',
      ]),
      headStyles: tblHead,
      styles:     tblBody,
      columnStyles: {
        0: { cellWidth: 50 },
        1: { cellWidth: 28 },
        2: { cellWidth: 34 },
        3: { cellWidth: 18 },
        4: { cellWidth: 'auto' },
      },
      margin: { left: M, right: M },
      showHead: 'everyPage',
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const v = String(data.cell.raw)
          data.cell.styles.textColor = v === 'Offline' ? [185, 28, 28] : [22, 101, 52]
          data.cell.styles.fontStyle = 'bold'
        }
      },
    })
    y = (doc as any).lastAutoTable.finalY + 14
  }

  // ─── FINDINGS SUMMARY ─────────────────────────────────────────────

  if (findings.length > 0) {
    doc.addPage()
    y = drawPageHeader(doc, target, PW, M)
    y = drawSectionTitle(doc, 'Findings Summary', y, M, CW)

    autoTable(doc, {
      startY: y,
      head: [['#', 'Vulnerability', 'Severity', 'CVSS', 'Source', 'Affected URL']],
      body: findings.map((f, i) => [
        i + 1,
        f.title,
        f.severity.toUpperCase(),
        CVSS_SCORE[f.severity]?.toFixed(1) ?? '0.0',
        f.source === 'vectra' ? 'Vectra' : f.source === 'wpscan' ? 'WPScan' : 'Nuclei',
        truncUrl(f.matchedAt ?? f.host),
      ]),
      headStyles: tblHead,
      styles:     tblBody,
      columnStyles: {
        0: { cellWidth: 8 },
        1: { cellWidth: 58 },
        2: { cellWidth: 22 },
        3: { cellWidth: 14 },
        4: { cellWidth: 22 },
        5: { cellWidth: 'auto' },
      },
      margin: { left: M, right: M },
      showHead: 'everyPage',
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 2) {
          const s = String(data.cell.raw).toLowerCase()
          if (SEV_FILL[s]) {
            data.cell.styles.fillColor = SEV_FILL[s]
            data.cell.styles.textColor = SEV_TEXT[s]
            data.cell.styles.fontStyle = 'bold'
          }
        }
      },
    })
    y = (doc as any).lastAutoTable.finalY + 14

    // Detailed findings
    if (y > PH - 55) { doc.addPage(); y = drawPageHeader(doc, target, PW, M) }
    y = drawSectionTitle(doc, 'Detailed Findings', y, M, CW)

    for (const f of findings.slice(0, 40)) {
      // Estimate block height to check for page break
      const descLines = f.description
        ? doc.splitTextToSize(f.description, CW - 6).length
        : 0
      const remLines  = doc.splitTextToSize(`Remediation: ${getRemediation(f)}`, CW - 6).length
      const blockH    = 12 + descLines * 4.5 + remLines * 4.2 + 8

      if (y + blockH > PH - 18) {
        doc.addPage()
        y = drawPageHeader(doc, target, PW, M)
        y += 4
      }

      const sev   = f.severity.toLowerCase()
      const fill  = SEV_FILL[sev]  ?? [243, 244, 246]
      const textC = SEV_TEXT[sev]  ?? [75, 85, 99]

      // Header strip
      doc.setFillColor(...fill)
      doc.rect(M, y, CW, 9, 'F')
      doc.setFillColor(...textC)
      doc.rect(M, y, 3, 9, 'F')

      doc.setFont('helvetica', 'bold')
      doc.setFontSize(8.5)
      doc.setTextColor(...textC)
      doc.text(f.title, M + 7, y + 6)

      doc.setFont('helvetica', 'normal')
      doc.setFontSize(7)
      doc.setTextColor(100, 100, 100)
      const metaRight = `${sev.toUpperCase()}  ·  CVSS ${CVSS_SCORE[sev]?.toFixed(1)}  ·  Risk ${RISK_SCORE[sev]}/100`
      doc.text(metaRight, PW - M, y + 6, { align: 'right' })
      y += 11

      // Affected URL
      const affectedUrl = f.matchedAt ?? f.host
      if (affectedUrl) {
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(7.5)
        doc.setTextColor(80, 80, 80)
        const urlLines = doc.splitTextToSize(`URL: ${affectedUrl}`, CW - 6)
        doc.text(urlLines, M + 4, y)
        y += urlLines.length * 4 + 2
      }

      // Description
      if (f.description) {
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(50, 50, 50)
        const dl = doc.splitTextToSize(f.description, CW - 6)
        doc.text(dl, M + 4, y)
        y += dl.length * 4.5 + 3
      }

      // Remediation
      doc.setFont('helvetica', 'italic')
      doc.setFontSize(7.5)
      doc.setTextColor(100, 100, 100)
      const rl = doc.splitTextToSize(`Remediation: ${getRemediation(f)}`, CW - 6)
      doc.text(rl, M + 4, y)
      y += rl.length * 4.2 + 7

      doc.setDrawColor(225, 225, 225)
      doc.setLineWidth(0.15)
      doc.line(M, y - 4, PW - M, y - 4)
    }
  }

  // ─── CVE INTELLIGENCE ─────────────────────────────────────────────

  if (cves.length > 0) {
    doc.addPage()
    y = drawPageHeader(doc, target, PW, M)
    y = drawSectionTitle(doc, 'CVE Intelligence', y, M, CW)

    autoTable(doc, {
      startY: y,
      head: [['CVE ID', 'Technology', 'Version', 'CVSS', 'Severity', 'Exploit', 'Published']],
      body: cves.map((c) => [
        c.cveId,
        c.technology,
        c.version,
        c.cvssScore.toFixed(1),
        (c.severity ?? '').toUpperCase(),
        c.exploitAvailable ? 'YES' : 'No',
        c.published
          ? new Date(c.published).toLocaleDateString('en-US', { year: 'numeric', month: 'short' })
          : '—',
      ]),
      headStyles: tblHead,
      styles:     tblBody,
      columnStyles: {
        0: { cellWidth: 36 },
        1: { cellWidth: 30 },
        2: { cellWidth: 20 },
        3: { cellWidth: 14 },
        4: { cellWidth: 24 },
        5: { cellWidth: 16 },
        6: { cellWidth: 'auto' },
      },
      margin: { left: M, right: M },
      showHead: 'everyPage',
      didParseCell: (data: any) => {
        if (data.section === 'body') {
          if (data.column.index === 4) {
            const s = String(data.cell.raw).toLowerCase()
            if (SEV_FILL[s]) {
              data.cell.styles.fillColor = SEV_FILL[s]
              data.cell.styles.textColor = SEV_TEXT[s]
              data.cell.styles.fontStyle = 'bold'
            }
          }
          if (data.column.index === 5 && String(data.cell.raw) === 'YES') {
            data.cell.styles.textColor = [185, 28, 28]
            data.cell.styles.fontStyle = 'bold'
          }
          if (data.column.index === 0) {
            data.cell.styles.textColor = [109, 40, 217]
            data.cell.styles.fontStyle = 'bold'
          }
        }
      },
    })
    y = (doc as any).lastAutoTable.finalY + 14

    // CVE descriptions
    if (y > PH - 55) { doc.addPage(); y = drawPageHeader(doc, target, PW, M) }
    y = drawSectionTitle(doc, 'CVE Details', y, M, CW)

    for (const c of cves.slice(0, 25)) {
      const descLines = c.description
        ? doc.splitTextToSize(c.description, CW - 6).length
        : 0
      if (y + 10 + descLines * 4.5 > PH - 18) {
        doc.addPage()
        y = drawPageHeader(doc, target, PW, M)
        y += 4
      }

      doc.setFillColor(245, 245, 255)
      doc.rect(M, y, CW, 8, 'F')
      doc.setFillColor(109, 40, 217)
      doc.rect(M, y, 3, 8, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(8.5)
      doc.setTextColor(109, 40, 217)
      doc.text(c.cveId, M + 7, y + 5.5)
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(7.5)
      doc.setTextColor(80, 80, 80)
      doc.text(`${c.technology} ${c.version}  ·  CVSS ${c.cvssScore.toFixed(1)}  ·  ${c.exploitAvailable ? 'EXPLOIT AVAILABLE' : 'No known exploit'}`, PW - M, y + 5.5, { align: 'right' })
      y += 10

      if (c.description) {
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(50, 50, 50)
        const dl = doc.splitTextToSize(c.description, CW - 6)
        doc.text(dl, M + 4, y)
        y += dl.length * 4.5 + 7
      } else {
        y += 5
      }

      doc.setDrawColor(225, 225, 225)
      doc.setLineWidth(0.15)
      doc.line(M, y - 4, PW - M, y - 4)
    }
  }

  // ─── RECOMMENDATIONS ──────────────────────────────────────────────

  doc.addPage()
  y = drawPageHeader(doc, target, PW, M)
  y = drawSectionTitle(doc, 'Remediation Recommendations', y, M, CW)

  const sortedFindings = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  sortedFindings.slice(0, 30).forEach((f, i) => {
    const rem    = getRemediation(f)
    const rl     = doc.splitTextToSize(rem, CW - 24).length
    const blockH = 9 + rl * 4.5 + 6

    if (y + blockH > PH - 18) {
      doc.addPage()
      y = drawPageHeader(doc, target, PW, M)
      y += 4
    }

    const sev   = f.severity.toLowerCase()
    const textC = SEV_TEXT[sev] ?? [75, 85, 99]

    doc.setFillColor(...(SEV_FILL[sev] ?? [243, 244, 246]))
    doc.roundedRect(M, y, 19, 6.5, 1, 1, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(6.5)
    doc.setTextColor(...textC)
    doc.text(sev.toUpperCase(), M + 9.5, y + 4.5, { align: 'center' })

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8.5)
    doc.setTextColor(15, 15, 15)
    doc.text(`${i + 1}. ${f.title}`, M + 23, y + 4.5)
    y += 9

    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(55, 55, 55)
    const remLines = doc.splitTextToSize(rem, CW - 24)
    doc.text(remLines, M + 23, y)
    y += remLines.length * 4.5 + 6
  })

  // ─── PAGE NUMBERS (skip cover) ────────────────────────────────────

  const total = (doc.internal as any).getNumberOfPages()
  for (let p = 2; p <= total; p++) {
    doc.setPage(p)
    doc.setDrawColor(210, 210, 210)
    doc.setLineWidth(0.2)
    doc.line(M, PH - 11, PW - M, PH - 11)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(6.5)
    doc.setTextColor(150, 150, 150)
    doc.text(`Report ID: ${reportId}`, M, PH - 6)
    doc.text(`Page ${p - 1} of ${total - 1}`, PW - M, PH - 6, { align: 'right' })
    doc.text('CONFIDENTIAL', PW / 2, PH - 6, { align: 'center' })
  }

  return doc.output('blob') as unknown as Blob
}

// ── Excel generator ───────────────────────────────────────────────────

export async function generateExcel(data: ReportData): Promise<Blob> {
  const XLSX = await import('xlsx')

  const { target, scan, findings, cves, assets, reportId, generatedBy } = data

  const C = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high:     findings.filter((f) => f.severity === 'high').length,
    medium:   findings.filter((f) => f.severity === 'medium').length,
    low:      findings.filter((f) => f.severity === 'low').length,
    info:     findings.filter((f) => f.severity === 'info').length,
  }

  const overallRisk =
    C.critical > 0 ? 'Critical' :
    C.high     > 0 ? 'High'     :
    C.medium   > 0 ? 'Medium'   :
    C.low      > 0 ? 'Low'      : 'Informational'

  const wb = XLSX.utils.book_new()

  // ── Sheet 1: Executive Summary ───────────────────────────────────

  const summaryRows = [
    ['VECTRA SECURITY ASSESSMENT REPORT'],
    [],
    ['Target',          target],
    ['Assessment Date', new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString()],
    ['Scan Profile',    scan?.scanProfile ?? scan?.scanType ?? 'Web Security'],
    ['Report ID',       reportId],
    ['Generated By',    generatedBy],
    ['Generated At',    new Date().toLocaleString()],
    [],
    ['FINDINGS SUMMARY'],
    ['Severity',    'Count', 'Percentage'],
    ['Critical',    C.critical, findings.length ? `${Math.round((C.critical / findings.length) * 100)}%` : '0%'],
    ['High',        C.high,     findings.length ? `${Math.round((C.high     / findings.length) * 100)}%` : '0%'],
    ['Medium',      C.medium,   findings.length ? `${Math.round((C.medium   / findings.length) * 100)}%` : '0%'],
    ['Low',         C.low,      findings.length ? `${Math.round((C.low      / findings.length) * 100)}%` : '0%'],
    ['Info',        C.info,     findings.length ? `${Math.round((C.info     / findings.length) * 100)}%` : '0%'],
    ['TOTAL',       findings.length, '100%'],
    [],
    ['CVEs Identified', cves.length],
    ['Assets Discovered', assets.length],
    ['Overall Risk Rating', overallRisk],
  ]
  const ws1 = XLSX.utils.aoa_to_sheet(summaryRows)
  ws1['!cols'] = [{ wch: 24 }, { wch: 32 }, { wch: 16 }]
  XLSX.utils.book_append_sheet(wb, ws1, 'Executive Summary')

  // ── Sheet 2: Findings ────────────────────────────────────────────

  const fHeaders = ['#', 'Title', 'Severity', 'CVSS Score', 'Vectra Risk Score', 'Source', 'Affected URL', 'Description', 'Detected At']
  const fRows = findings.map((f, i) => [
    i + 1,
    f.title,
    f.severity.toUpperCase(),
    CVSS_SCORE[f.severity] ?? 0,
    RISK_SCORE[f.severity] ?? 0,
    f.source === 'vectra' ? 'Vectra Checks' : f.source === 'wpscan' ? 'WPScan' : 'Nuclei',
    f.matchedAt ?? f.host ?? '',
    f.description ?? '',
    new Date(f.createdAt).toLocaleString(),
  ])
  const ws2 = XLSX.utils.aoa_to_sheet([fHeaders, ...fRows])
  ws2['!cols'] = [{ wch: 4 }, { wch: 48 }, { wch: 12 }, { wch: 12 }, { wch: 18 }, { wch: 14 }, { wch: 50 }, { wch: 60 }, { wch: 20 }]
  XLSX.utils.book_append_sheet(wb, ws2, 'Findings')

  // ── Sheet 3: CVE Intelligence ─────────────────────────────────────

  const cHeaders = ['CVE ID', 'Technology', 'Affected Version', 'CVSS Score', 'Severity', 'Exploit Available', 'Asset URL', 'Published', 'Description']
  const cRows = cves.map((c) => [
    c.cveId,
    c.technology,
    c.version,
    c.cvssScore,
    c.severity,
    c.exploitAvailable ? 'Yes' : 'No',
    c.assetUrl,
    c.published ? new Date(c.published).toLocaleDateString() : '',
    c.description,
  ])
  const ws3 = XLSX.utils.aoa_to_sheet([cHeaders, ...cRows])
  ws3['!cols'] = [{ wch: 22 }, { wch: 16 }, { wch: 18 }, { wch: 12 }, { wch: 12 }, { wch: 18 }, { wch: 50 }, { wch: 14 }, { wch: 60 }]
  XLSX.utils.book_append_sheet(wb, ws3, 'CVE Intelligence')

  // ── Sheet 4: Assets ───────────────────────────────────────────────

  const aHeaders = ['Subdomain', 'Domain', 'IP Address', 'Server', 'Status Code', 'Alive', 'Technologies', 'URL']
  const aRows = assets.map((a) => [
    a.subdomain ?? '',
    a.domain ?? '',
    a.ip ?? '',
    a.server ?? '',
    a.statusCode ?? '',
    a.alive ? 'Yes' : 'No',
    (a.technologies ?? []).join(', '),
    a.url ?? '',
  ])
  const ws4 = XLSX.utils.aoa_to_sheet([aHeaders, ...aRows])
  ws4['!cols'] = [{ wch: 36 }, { wch: 24 }, { wch: 16 }, { wch: 24 }, { wch: 14 }, { wch: 8 }, { wch: 40 }, { wch: 50 }]
  XLSX.utils.book_append_sheet(wb, ws4, 'Assets')

  // ── Sheet 5: Recommendations ──────────────────────────────────────

  const rHeaders = ['Priority', 'Vulnerability', 'Severity', 'CVSS', 'Affected URL', 'Remediation']
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
  const rRows = sorted.map((f, i) => [
    i + 1,
    f.title,
    f.severity.toUpperCase(),
    CVSS_SCORE[f.severity] ?? 0,
    f.matchedAt ?? f.host ?? '',
    getRemediation(f),
  ])
  const ws5 = XLSX.utils.aoa_to_sheet([rHeaders, ...rRows])
  ws5['!cols'] = [{ wch: 10 }, { wch: 48 }, { wch: 12 }, { wch: 10 }, { wch: 50 }, { wch: 80 }]
  XLSX.utils.book_append_sheet(wb, ws5, 'Recommendations')

  const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' })
  return new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}
