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
import type { FirestoreNetworkScan }     from './firestore-network-scans'
import type { FirestoreNetworkHost }     from './firestore-network-assets'
import type { FirestoreNetworkFinding }  from './firestore-network-findings'
import type { FirestoreNetworkCve }      from './firestore-network-cves'
import type { FirestoreNetworkTimeline } from './firestore-network-timeline'
import type { FirestoreSastScan }        from './firestore-sast-scans'
import type { FirestoreSastFinding }     from './firestore-sast-findings'
import type { CloudAsset, CloudFinding, CloudIntegration } from './api-cloud'
import { providerLabel } from './api-cloud'
import {
  ReportDoc,
  drawCover,
  truncUrl,
  severityCounts,
  overallRisk as computeOverallRisk,
  SEV_FILL,
  SEV_TEXT,
  SEV_ORDER,
  COLOR,
  SPACE,
  type Rgb,
} from './pdf-layout'

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

// Severity ordering, fills and text colours are owned by the layout engine
// (lib/pdf-layout.ts) so every report renders severities identically.

const CVSS_SCORE: Record<string, number> = { critical: 9.1, high: 7.5, medium: 5.3, low: 3.1, info: 0.0, unknown: 0.0 }
const RISK_SCORE: Record<string, number> = { critical: 92, high: 74, medium: 51, low: 24, info: 8, unknown: 0 }

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
//
// Page chrome, section titles, stat boxes, text measurement and page breaks
// all live in lib/pdf-layout.ts (ReportDoc). The report bodies below describe
// *what* belongs in the document; the engine decides *where* it lands.

/** Create a jsPDF instance wired to the shared layout engine. */
async function createReportDoc(headerLabel: string): Promise<ReportDoc> {
  const { default: jsPDF }     = await import('jspdf')
  const { default: autoTable } = await import('jspdf-autotable')
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  return new ReportDoc(doc, autoTable, headerLabel)
}

/** Severity distribution table — identical across every report type. */
function severityBreakdownTable(
  rd: ReportDoc,
  counts: { critical: number; high: number; medium: number; low: number; info: number },
  total: number,
): void {
  const pct = (n: number) => (total ? `${Math.round((n / total) * 100)}%` : '0%')
  rd.table(
    [
      { header: 'Severity',   width: 40 },
      { header: 'Count',      width: 25, align: 'center' },
      { header: '% of Total', width: 35, align: 'center' },
    ],
    [
      ['Critical', counts.critical, pct(counts.critical)],
      ['High',     counts.high,     pct(counts.high)],
      ['Medium',   counts.medium,   pct(counts.medium)],
      ['Low',      counts.low,      pct(counts.low)],
      ['Info',     counts.info,     pct(counts.info)],
      ['Total',    total,           '100%'],
    ],
    {
      didParseCell: (data: any) => {
        if (data.section !== 'body' || data.column.index !== 0) return
        const s = String(data.cell.raw).toLowerCase()
        if (SEV_FILL[s]) {
          data.cell.styles.fillColor = SEV_FILL[s]
          data.cell.styles.textColor = SEV_TEXT[s]
          data.cell.styles.fontStyle = s === 'critical' || s === 'high' ? 'bold' : 'normal'
        } else {
          data.cell.styles.fillColor = [235, 235, 235]
          data.cell.styles.fontStyle = 'bold'
        }
      },
    },
  )
}

/**
 * Numbered remediation entry: severity pill, title beside it, then the
 * recommendation indented underneath. Flows across pages via the engine.
 */
function remediationEntry(
  rd: ReportDoc, index: number, severity: string, title: string, body: string,
): void {
  const sev    = (severity ?? '').toLowerCase()
  const textC  = SEV_TEXT[sev] ?? SEV_TEXT.unknown
  const indent = 23
  const pillH  = 6.5

  // Keep the pill with at least the opening lines of its body.
  rd.ensure(pillH + rd.lineHeight(8) * 2)

  const d = rd.doc
  d.setFillColor(...(SEV_FILL[sev] ?? SEV_FILL.unknown))
  d.roundedRect(rd.left, rd.y, 19, pillH, 1, 1, 'F')
  d.setFont('helvetica', 'bold')
  d.setFontSize(6.5)
  d.setTextColor(...textC)
  d.text(sev.toUpperCase(), rd.left + 9.5, rd.y + pillH / 2, { baseline: 'middle', align: 'center' })

  // Title wraps to the space beside the pill, so it cannot run past the margin.
  // Every wrapped line is drawn — long titles were previously cut after line one.
  const titleLines = rd.wrap(`${index}. ${title}`, rd.CW - indent, 8.5, 'bold')
  const titleLh    = rd.lineHeight(8.5)
  d.setFont('helvetica', 'bold')
  d.setFontSize(8.5)
  d.setTextColor(...COLOR.ink)
  titleLines.forEach((line, i) => {
    d.text(line, rd.left + indent, rd.y + pillH / 2 + i * titleLh, { baseline: 'middle' })
  })
  rd.y += Math.max(pillH, pillH / 2 + (titleLines.length - 0.5) * titleLh) + SPACE.tight

  rd.paragraph(body, { size: 8, indent, color: [55, 55, 55] })
  rd.space(SPACE.paragraph)
}

/** Detail card: coloured header strip plus labelled body paragraphs. */
function detailCard(
  rd: ReportDoc,
  opts: {
    title: string
    meta?: string
    fill: Rgb
    accent: Rgb
    rows: { label?: string; text: string; style?: 'normal' | 'italic'; size?: number }[]
  },
): void {
  rd.cardHeader(opts.title, opts.meta ?? '', opts.fill, opts.accent)
  for (const row of opts.rows) {
    if (!row.text) continue
    rd.paragraph(row.label ? `${row.label}: ${row.text}` : row.text, {
      size:   row.size ?? 8,
      style:  row.style ?? 'normal',
      indent: 4,
      color:  row.style === 'italic' ? COLOR.muted : [50, 50, 50],
    })
    rd.space(SPACE.tight)
  }
  rd.space(SPACE.tight)
  rd.divider()
}

// ── PDF generator ─────────────────────────────────────────────────────

export async function generatePdf(data: ReportData): Promise<Blob> {
  const { target, scan, findings, cves, assets, reportId, generatedBy } = data

  const rd = await createReportDoc(`Security Assessment | ${target}`)
  const C  = severityCounts(findings)
  const risk = computeOverallRisk(C)

  const scanDate = new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString(
    'en-US', { year: 'numeric', month: 'long', day: 'numeric' },
  )

  // ─── COVER ────────────────────────────────────────────────────────

  drawCover(rd, {
    kicker:   'SECURITY ASSESSMENT REPORT',
    subtitle: 'Web Application Security',
    target,
    stats: [
      { label: 'Total Findings', value: String(findings.length), color: COLOR.ink },
      { label: 'Critical',       value: String(C.critical),      color: SEV_TEXT.critical },
      { label: 'High',           value: String(C.high),          color: SEV_TEXT.high },
      { label: 'CVEs Found',     value: String(cves.length),     color: COLOR.accent },
      { label: 'Medium',         value: String(C.medium),        color: SEV_TEXT.medium },
      { label: 'Low',            value: String(C.low),           color: SEV_TEXT.low },
      { label: 'Info',           value: String(C.info),          color: SEV_TEXT.info },
      { label: 'Assets',         value: String(assets.length),   color: COLOR.ink },
    ],
    meta: [
      ['Assessment Date', scanDate],
      ['Scan Profile',    scan?.scanProfile ?? scan?.scanType ?? 'Web Security'],
      ['Generated By',    generatedBy],
      ['Report ID',       reportId],
      ['Classification',  'CONFIDENTIAL'],
    ],
  })

  // ─── EXECUTIVE SUMMARY ────────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Executive Summary')

  rd.paragraph(
    `This security assessment was conducted against ${target} on ${scanDate}. ` +
    `The assessment identified ${findings.length} security finding${findings.length !== 1 ? 's' : ''} across ` +
    `${assets.length} discovered asset${assets.length !== 1 ? 's' : ''}. ` +
    (cves.length > 0
      ? `CVE correlation analysis identified ${cves.length} known vulnerabilities in the detected technology stack. `
      : '') +
    'Findings are classified by severity and prioritized for remediation.',
    { size: 9 },
  )
  rd.space(SPACE.block)

  rd.badge(`OVERALL RISK: ${risk.label.toUpperCase()}`, risk.rgb)
  rd.space(SPACE.block)

  severityBreakdownTable(rd, C, findings.length)

  // ─── ASSET INVENTORY ──────────────────────────────────────────────

  if (assets.length > 0) {
    rd.sectionTitle('Asset Inventory')
    rd.table(
      [
        { header: 'Subdomain / Host', width: 50 },
        { header: 'IP Address',       width: 26 },
        { header: 'Server',           width: 32 },
        { header: 'Status',           width: 16, align: 'center' },
        { header: 'Technologies',     width: 42 },
      ],
      assets.slice(0, 80).map((a) => [
        a.subdomain ?? a.domain ?? '',
        a.ip ?? '—',
        a.server ?? '—',
        a.alive ? `${a.statusCode ?? 200}` : 'Offline',
        (a.technologies ?? []).slice(0, 3).join(', ') || '—',
      ]),
      {
        didParseCell: (d: any) => {
          if (d.section === 'body' && d.column.index === 3) {
            const v = String(d.cell.raw)
            d.cell.styles.textColor = v === 'Offline' ? [185, 28, 28] : [22, 101, 52]
            d.cell.styles.fontStyle = 'bold'
          }
        },
      },
    )
  }

  // ─── FINDINGS ─────────────────────────────────────────────────────

  if (findings.length > 0) {
    rd.newPage()
    rd.sectionTitle('Findings Summary')

    rd.table(
      [
        { header: '#',             width: 8,  align: 'center' },
        { header: 'Vulnerability', width: 56 },
        { header: 'Severity',      width: 20, align: 'center' },
        { header: 'CVSS',          width: 13, align: 'center' },
        { header: 'Source',        width: 20, align: 'center' },
        { header: 'Affected URL',  width: 49 },
      ],
      findings.map((f, i) => [
        i + 1,
        f.title,
        f.severity.toUpperCase(),
        CVSS_SCORE[f.severity]?.toFixed(1) ?? '0.0',
        f.source === 'vectra' ? 'Vectra' : f.source === 'wpscan' ? 'WPScan' : 'Nuclei',
        truncUrl(f.matchedAt ?? f.host),
      ]),
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 2) },
    )

    rd.sectionTitle('Detailed Findings')

    for (const f of findings.slice(0, 40)) {
      const sev = f.severity.toLowerCase()
      detailCard(rd, {
        title:  f.title,
        meta:   `${sev.toUpperCase()}  ·  CVSS ${CVSS_SCORE[sev]?.toFixed(1) ?? '0.0'}  ·  Risk ${RISK_SCORE[sev] ?? 0}/100`,
        fill:   SEV_FILL[sev] ?? SEV_FILL.unknown,
        accent: SEV_TEXT[sev] ?? SEV_TEXT.unknown,
        rows: [
          ...(f.matchedAt ?? f.host ? [{ label: 'URL', text: truncUrl(f.matchedAt ?? f.host, 120), size: 7.5 }] : []),
          ...(f.description ? [{ text: f.description }] : []),
          { label: 'Remediation', text: getRemediation(f), style: 'italic' as const, size: 7.5 },
        ],
      })
    }
  }

  // ─── CVE INTELLIGENCE ─────────────────────────────────────────────

  if (cves.length > 0) {
    rd.newPage()
    rd.sectionTitle('CVE Intelligence')

    rd.table(
      [
        { header: 'CVE ID',     width: 34 },
        { header: 'Technology', width: 30 },
        { header: 'Version',    width: 20 },
        { header: 'CVSS',       width: 14, align: 'center' },
        { header: 'Severity',   width: 22, align: 'center' },
        { header: 'Exploit',    width: 16, align: 'center' },
        { header: 'Published',  width: 24, align: 'center' },
      ],
      cves.map((c) => [
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
      {
        didParseCell: (d: any) => {
          ReportDoc.severityCell(d, 4)
          if (d.section !== 'body') return
          if (d.column.index === 5 && String(d.cell.raw) === 'YES') {
            d.cell.styles.textColor = [185, 28, 28]
            d.cell.styles.fontStyle = 'bold'
          }
          if (d.column.index === 0) {
            d.cell.styles.textColor = [109, 40, 217]
            d.cell.styles.fontStyle = 'bold'
          }
        },
      },
    )

    rd.sectionTitle('CVE Details')
    for (const c of cves.slice(0, 25)) {
      detailCard(rd, {
        title:  c.cveId,
        meta:   `${c.technology} ${c.version}  ·  CVSS ${c.cvssScore.toFixed(1)}  ·  ${c.exploitAvailable ? 'EXPLOIT AVAILABLE' : 'No known exploit'}`,
        fill:   [245, 245, 255],
        accent: [109, 40, 217],
        rows:   c.description ? [{ text: c.description }] : [],
      })
    }
  }

  // ─── RECOMMENDATIONS ──────────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Remediation Recommendations')

  const sortedFindings = [...findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5),
  )
  sortedFindings.slice(0, 30).forEach((f, i) => {
    remediationEntry(rd, i + 1, f.severity, f.title, getRemediation(f))
  })

  rd.drawFooters(reportId)
  return rd.doc.output('blob') as unknown as Blob
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

// ── Network Security Report ────────────────────────────────────────────

export interface NetworkReportData {
  target: string
  scan: FirestoreNetworkScan | null
  hosts: FirestoreNetworkHost[]
  findings: FirestoreNetworkFinding[]
  cves: FirestoreNetworkCve[]
  timeline: FirestoreNetworkTimeline | null
  reportId: string
  generatedBy: string
}

export interface NetworkReportTarget {
  target: string
  hostCount: number
  findingsCount: number
  cveCount: number
  latestScan: FirestoreNetworkScan | null
  latestScanDate: string
  latestStatus: string
}

export async function getNetworkReportableTargets(uid: string): Promise<NetworkReportTarget[]> {
  const scansSnap = await getDocs(collection(db, 'users', uid, 'network_scans'))
  const allScans  = scansSnap.docs.map((d) => d.data() as FirestoreNetworkScan)

  const byTarget = new Map<string, FirestoreNetworkScan[]>()
  allScans.forEach((s) => {
    if (!byTarget.has(s.target)) byTarget.set(s.target, [])
    byTarget.get(s.target)!.push(s)
  })

  const result: NetworkReportTarget[] = []

  for (const [target, scans] of byTarget) {
    const sorted    = scans.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    const latestScan = sorted[0]
    const hostCount     = latestScan.liveHosts   ?? latestScan.totalHosts   ?? 0
    const findingsCount = latestScan.totalFindings ?? 0
    const cveCount      = latestScan.totalCves     ?? 0
    if (hostCount === 0 && findingsCount === 0 && cveCount === 0) continue
    result.push({
      target,
      hostCount,
      findingsCount,
      cveCount,
      latestScan,
      latestScanDate: latestScan.completedAt ?? latestScan.createdAt,
      latestStatus:   latestScan.status,
    })
  }

  return result.sort((a, b) => b.findingsCount - a.findingsCount || b.cveCount - a.cveCount)
}

export async function fetchNetworkReportData(uid: string, target: string): Promise<{
  hosts: FirestoreNetworkHost[]
  findings: FirestoreNetworkFinding[]
  cves: FirestoreNetworkCve[]
  latestScan: FirestoreNetworkScan | null
  timeline: FirestoreNetworkTimeline | null
}> {
  const scansSnap  = await getDocs(collection(db, 'users', uid, 'network_scans'))
  const allScans   = scansSnap.docs.map((d) => d.data() as FirestoreNetworkScan)
  const latestScan = allScans
    .filter((s) => s.target === target)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0] ?? null

  if (!latestScan) return { hosts: [], findings: [], cves: [], latestScan: null, timeline: null }

  const sid = latestScan.scanId
  const [hostsSnap, findingsSnap, cvesSnap, tlSnap] = await Promise.all([
    getDocs(query(collection(db, 'users', uid, 'network_assets'),   where('scanId', '==', sid))),
    getDocs(query(collection(db, 'users', uid, 'network_findings'), where('scanId', '==', sid))),
    getDocs(query(collection(db, 'users', uid, 'network_cves'),     where('scanId', '==', sid))),
    getDocs(query(collection(db, 'users', uid, 'network_timeline'), where('target', '==', target))),
  ])

  const hosts = hostsSnap.docs
    .map((d) => d.data() as FirestoreNetworkHost)
    .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))

  const findings = findingsSnap.docs
    .map((d) => d.data() as FirestoreNetworkFinding)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  const cves = cvesSnap.docs
    .map((d) => d.data() as FirestoreNetworkCve)
    .sort((a, b) => b.cvssScore - a.cvssScore)

  const timeline = tlSnap.docs.length > 0
    ? tlSnap.docs
        .map((d) => d.data() as FirestoreNetworkTimeline)
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
    : null

  return { hosts, findings, cves, latestScan, timeline }
}

export async function generateNetworkPdf(data: NetworkReportData): Promise<Blob> {
  const { target, scan, hosts, findings, cves, timeline, reportId, generatedBy } = data

  const rd = await createReportDoc(`Network Assessment | ${target}`)
  const FC = severityCounts(findings)
  const risk = computeOverallRisk(FC)

  const scanDate = new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString(
    'en-US', { year: 'numeric', month: 'long', day: 'numeric' },
  )

  const liveHosts   = hosts.filter((h) => h.status === 'up').length
  const totalPorts  = hosts.reduce((n, h) => n + h.ports.length, 0)
  const sslFindings = findings.filter((f) => f.source === 'ssl-analysis')
  const svcFindings = findings.filter((f) => f.source !== 'ssl-analysis')
  const avgRisk     = hosts.length > 0
    ? Math.round(hosts.reduce((n, h) => n + (h.riskScore ?? 0), 0) / hosts.length)
    : 0

  // ─── COVER ────────────────────────────────────────────────────────

  drawCover(rd, {
    kicker:   'NETWORK SECURITY ASSESSMENT',
    subtitle: 'Network Infrastructure Security',
    target,
    stats: [
      { label: 'Total Hosts',       value: String(hosts.length),       color: COLOR.ink },
      { label: 'Live Hosts',        value: String(liveHosts),          color: [22, 101, 52] },
      { label: 'Open Ports',        value: String(totalPorts),         color: [29, 78, 216] },
      { label: 'CVEs Found',        value: String(cves.length),        color: COLOR.accent },
      { label: 'Critical Findings', value: String(FC.critical),        color: SEV_TEXT.critical },
      { label: 'High Findings',     value: String(FC.high),            color: SEV_TEXT.high },
      { label: 'SSL Issues',        value: String(sslFindings.length), color: SEV_TEXT.medium },
      { label: 'Avg Risk Score',    value: String(avgRisk),            color: SEV_TEXT.info },
    ],
    meta: [
      ['Assessment Date', scanDate],
      ['Scan Profile',    scan?.scanProfile ?? 'Network Scan'],
      ['Generated By',    generatedBy],
      ['Report ID',       reportId],
      ['Classification',  'CONFIDENTIAL'],
    ],
  })

  // ─── EXECUTIVE SUMMARY ────────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Executive Summary')

  rd.paragraph(
    `This network security assessment was conducted against ${target} on ${scanDate}. ` +
    `The assessment discovered ${hosts.length} host${hosts.length !== 1 ? 's' : ''} (${liveHosts} live) ` +
    `across ${totalPorts} open port${totalPorts !== 1 ? 's' : ''}. ` +
    (findings.length > 0
      ? `${findings.length} security finding${findings.length !== 1 ? 's' : ''} were identified across the network infrastructure. `
      : '') +
    (cves.length > 0
      ? `CVE correlation identified ${cves.length} known vulnerabilit${cves.length !== 1 ? 'ies' : 'y'} in detected service versions. `
      : '') +
    'Findings are classified by severity and prioritized for remediation.',
    { size: 9 },
  )
  rd.space(SPACE.block)

  rd.badge(`OVERALL RISK: ${risk.label.toUpperCase()}`, risk.rgb)
  rd.space(SPACE.block)

  severityBreakdownTable(rd, FC, findings.length)

  // ─── HOST DISCOVERY ───────────────────────────────────────────────

  if (hosts.length > 0) {
    rd.sectionTitle('Host Discovery & Risk Assessment')
    rd.table(
      [
        { header: 'IP Address',       width: 28 },
        { header: 'Hostname',         width: 32 },
        { header: 'Operating System', width: 38 },
        { header: 'Risk',             width: 12, align: 'center' },
        { header: 'Level',            width: 20, align: 'center' },
        { header: 'Ports',            width: 12, align: 'center' },
        { header: 'Vendor',           width: 24 },
      ],
      hosts.map((h) => [
        h.ip,
        h.hostname ?? '—',
        h.os ?? '—',
        h.riskScore != null ? String(h.riskScore) : '—',
        (h.riskLevel ?? '—').toUpperCase(),
        String(h.ports.length),
        h.vendor ?? '—',
      ]),
      {
        didParseCell: (d: any) => {
          if (d.section !== 'body' || d.column.index !== 4) return
          const lvl = String(d.cell.raw).toLowerCase()
          if (lvl === 'critical')    { d.cell.styles.textColor = [185, 28, 28]; d.cell.styles.fontStyle = 'bold' }
          else if (lvl === 'high')   { d.cell.styles.textColor = [154, 52, 18]; d.cell.styles.fontStyle = 'bold' }
          else if (lvl === 'medium') { d.cell.styles.textColor = [133, 77, 14] }
          else if (lvl === 'low')    { d.cell.styles.textColor = [29, 78, 216] }
        },
      },
    )
  }

  // ─── PORTS & SERVICES ─────────────────────────────────────────────

  const allPorts = hosts.flatMap((h) => h.ports.map((p) => ({ ip: h.ip, ...p })))

  if (allPorts.length > 0) {
    rd.sectionTitle('Open Ports & Service Detection')
    rd.table(
      [
        { header: 'IP Address', width: 28 },
        { header: 'Port',       width: 13, align: 'center' },
        { header: 'Protocol',   width: 18, align: 'center' },
        { header: 'Service',    width: 26 },
        { header: 'Version',    width: 56 },
        { header: 'State',      width: 15, align: 'center' },
      ],
      allPorts.slice(0, 200).map((p) => [
        p.ip,
        String(p.port),
        p.protocol ?? '—',
        p.service  ?? '—',
        p.version  ?? '—',
        p.state    ?? '—',
      ]),
      {
        didParseCell: (d: any) => {
          if (d.section !== 'body' || d.column.index !== 5) return
          const v = String(d.cell.raw).toLowerCase()
          if (v === 'open')        { d.cell.styles.textColor = [22, 101, 52]; d.cell.styles.fontStyle = 'bold' }
          else if (v === 'closed') { d.cell.styles.textColor = [185, 28, 28]; d.cell.styles.fontStyle = 'bold' }
          else                     { d.cell.styles.textColor = [107, 114, 128] }
        },
      },
    )
  }

  // ─── OS DETECTION ─────────────────────────────────────────────────

  const hostsWithOs = hosts.filter((h) => h.os && h.os.toLowerCase() !== 'unknown')
  if (hostsWithOs.length > 0) {
    rd.sectionTitle('Operating System Detection')
    rd.table(
      [
        { header: 'IP Address',    width: 26 },
        { header: 'Hostname',      width: 30 },
        { header: 'Normalized OS', width: 38 },
        { header: 'OS Family',     width: 22, align: 'center' },
        { header: 'Confidence',    width: 20, align: 'center' },
        { header: 'Raw Detection', width: 46 },
      ],
      hostsWithOs.map((h) => [
        h.ip,
        h.hostname ?? '—',
        h.os ?? '—',
        (h.osFamily ?? '—').toUpperCase(),
        h.osConfidence != null ? `${h.osConfidence}%` : '—',
        h.osRaw ?? '—',
      ]),
    )
  }

  // ─── SSL / TLS ────────────────────────────────────────────────────

  const sslEndpoints = hosts.flatMap((h) => (h.ssl ?? []).map((s) => ({ ip: h.ip, ...s })))

  if (sslEndpoints.length > 0) {
    rd.sectionTitle('SSL/TLS Analysis')
    rd.table(
      [
        { header: 'IP Address',   width: 26 },
        { header: 'Port',         width: 11, align: 'center' },
        { header: 'TLS Version',  width: 20, align: 'center' },
        { header: 'Cipher Suite', width: 38 },
        { header: 'Cert Subject', width: 34 },
        { header: 'Days Expiry',  width: 18, align: 'center' },
        { header: 'Issues',       width: 25 },
      ],
      sslEndpoints.map((s) => {
        const issues = [
          s.isExpired    ? 'Expired'     : null,
          s.expiringSoon ? 'Expiring'    : null,
          s.isSelfSigned ? 'Self-signed' : null,
          s.isWeakTls    ? 'Weak TLS'    : null,
          s.isWeakCipher ? 'Weak Cipher' : null,
        ].filter(Boolean).join(', ')
        return [
          s.ip,
          String(s.port),
          s.tlsVersion,
          s.cipherSuite ?? '—',
          s.subject     ?? '—',
          s.daysUntilExpiry != null ? String(s.daysUntilExpiry) : '—',
          issues || 'OK',
        ]
      }),
      {
        didParseCell: (d: any) => {
          if (d.section !== 'body' || d.column.index !== 6) return
          const v = String(d.cell.raw)
          if (v === 'OK')                 { d.cell.styles.textColor = [22, 101, 52]; d.cell.styles.fontStyle = 'bold' }
          else if (v.includes('Expired')) { d.cell.styles.textColor = [185, 28, 28]; d.cell.styles.fontStyle = 'bold' }
          else                            { d.cell.styles.textColor = [154, 52, 18] }
        },
      },
    )
  }

  // ─── DANGEROUS SERVICES ───────────────────────────────────────────

  if (svcFindings.length > 0) {
    rd.sectionTitle('Dangerous Services')
    rd.table(
      [
        { header: 'IP Address',        width: 26 },
        { header: 'Port',              width: 11, align: 'center' },
        { header: 'Severity',          width: 20, align: 'center' },
        { header: 'Service / Finding', width: 44 },
        { header: 'Recommendation',    width: 61 },
      ],
      svcFindings.slice(0, 60).map((f) => [
        f.ip,
        f.port != null ? String(f.port) : '—',
        f.severity.toUpperCase(),
        f.title,
        f.recommendation ?? '—',
      ]),
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 2) },
    )
  }

  // ─── CVE CORRELATION ──────────────────────────────────────────────

  if (cves.length > 0) {
    rd.newPage()
    rd.sectionTitle('CVE Correlation')

    rd.table(
      [
        { header: 'CVE ID',     width: 34 },
        { header: 'IP Address', width: 26 },
        { header: 'Technology', width: 28 },
        { header: 'Version',    width: 20 },
        { header: 'CVSS',       width: 14, align: 'center' },
        { header: 'Severity',   width: 22, align: 'center' },
        { header: 'Exploit',    width: 16, align: 'center' },
      ],
      cves.map((c) => [
        c.cveId,
        c.ip,
        c.technology,
        c.version,
        c.cvssScore.toFixed(1),
        (c.severity ?? '').toUpperCase(),
        c.exploitAvailable ? 'YES' : 'No',
      ]),
      {
        didParseCell: (d: any) => {
          ReportDoc.severityCell(d, 5)
          if (d.section !== 'body') return
          if (d.column.index === 6 && String(d.cell.raw) === 'YES') {
            d.cell.styles.textColor = [185, 28, 28]
            d.cell.styles.fontStyle = 'bold'
          }
          if (d.column.index === 0) {
            d.cell.styles.textColor = [109, 40, 217]
            d.cell.styles.fontStyle = 'bold'
          }
        },
      },
    )

    rd.sectionTitle('CVE Details')
    for (const c of cves.slice(0, 20)) {
      detailCard(rd, {
        title:  c.cveId,
        meta:   `${c.ip}  ·  ${c.technology} ${c.version}  ·  CVSS ${c.cvssScore.toFixed(1)}`,
        fill:   [245, 245, 255],
        accent: [109, 40, 217],
        rows:   c.description ? [{ text: c.description }] : [],
      })
    }
  }

  // ─── TIMELINE ─────────────────────────────────────────────────────

  if (timeline && timeline.changes.length > 0) {
    rd.sectionTitle('Network Timeline')

    const tlDate = new Date(timeline.timestamp).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
    })
    rd.paragraph(
      `Timeline event recorded on ${tlDate}. ` +
      `${timeline.changeCount} change${timeline.changeCount !== 1 ? 's' : ''} detected: ` +
      `${timeline.newHosts} new host${timeline.newHosts !== 1 ? 's' : ''}, ` +
      `${timeline.removedHosts} removed, ` +
      `${timeline.portChanges} port change${timeline.portChanges !== 1 ? 's' : ''}, ` +
      `${timeline.riskChanges} risk change${timeline.riskChanges !== 1 ? 's' : ''}.`,
      { size: 9 },
    )
    rd.space(SPACE.block)

    rd.table(
      [
        { header: 'Event Type', width: 32 },
        { header: 'Host',       width: 28 },
        { header: 'Details',    width: 82 },
        { header: 'Severity',   width: 20, align: 'center' },
      ],
      timeline.changes.slice(0, 30).map((c) => [
        c.type.replace(/_/g, ' ').toUpperCase(),
        c.host,
        c.details,
        c.severity.toUpperCase(),
      ]),
      {
        didParseCell: (d: any) => {
          if (d.section !== 'body' || d.column.index !== 3) return
          const v = String(d.cell.raw).toLowerCase()
          if (v === 'critical')     { d.cell.styles.textColor = [185, 28, 28]; d.cell.styles.fontStyle = 'bold' }
          else if (v === 'warning') { d.cell.styles.textColor = [154, 52, 18] }
        },
      },
    )
  }

  // ─── RECOMMENDATIONS ──────────────────────────────────────────────

  if (findings.length > 0) {
    rd.newPage()
    rd.sectionTitle('Remediation Recommendations')

    const sortedF = [...findings].sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5),
    )
    sortedF.slice(0, 30).forEach((f, i) => {
      remediationEntry(
        rd, i + 1, f.severity, f.title,
        f.recommendation ?? `Review and remediate the "${f.title}" finding per your security policy.`,
      )
    })
  }

  // ─── TECHNICAL APPENDIX ───────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Technical Appendix')

  if (scan?.engines) {
    rd.table(
      [
        { header: 'Scan Engine', width: 60 },
        { header: 'Status',      width: 35, align: 'center' },
        { header: 'Items Found', width: 87, align: 'center' },
      ],
      Object.entries(scan.engines).map(([engine, state]: [string, any]) => [
        engine.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
        (state?.status ?? '—').toUpperCase(),
        String(state?.count ?? 0),
      ]),
      {
        didParseCell: (d: any) => {
          if (d.section !== 'body' || d.column.index !== 1) return
          const v = String(d.cell.raw).toLowerCase()
          if (v === 'completed')     { d.cell.styles.textColor = [22, 101, 52]; d.cell.styles.fontStyle = 'bold' }
          else if (v === 'failed')   { d.cell.styles.textColor = [185, 28, 28]; d.cell.styles.fontStyle = 'bold' }
          else if (v === 'running')  { d.cell.styles.textColor = [29, 78, 216] }
        },
      },
    )
  }

  if (hosts.length > 0) {
    rd.sectionTitle('Risk Score Distribution')
    const rl = (level: string) => hosts.filter((h) => h.riskLevel === level).length
    rd.table(
      [
        { header: 'Risk Level',  width: 45 },
        { header: 'Host Count',  width: 35, align: 'center' },
        { header: '% of Hosts',  width: 35, align: 'center' },
        { header: 'Score Range', width: 67, align: 'center' },
      ],
      [
        ['Critical', rl('critical'), `${Math.round((rl('critical') / hosts.length) * 100)}%`, '71–100'],
        ['High',     rl('high'),     `${Math.round((rl('high')     / hosts.length) * 100)}%`, '41–70'],
        ['Medium',   rl('medium'),   `${Math.round((rl('medium')   / hosts.length) * 100)}%`, '21–40'],
        ['Low',      rl('low'),      `${Math.round((rl('low')      / hosts.length) * 100)}%`, '0–20'],
      ],
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 0) },
    )
  }

  rd.drawFooters(reportId)
  return rd.doc.output('blob') as unknown as Blob
}

export async function generateNetworkExcel(data: NetworkReportData): Promise<Blob> {
  const XLSX = await import('xlsx')

  const { target, scan, hosts, findings, cves, reportId, generatedBy } = data

  const FC = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high:     findings.filter((f) => f.severity === 'high').length,
    medium:   findings.filter((f) => f.severity === 'medium').length,
    low:      findings.filter((f) => f.severity === 'low').length,
    info:     findings.filter((f) => f.severity === 'info').length,
  }

  const liveHosts  = hosts.filter((h) => h.status === 'up').length
  const totalPorts = hosts.reduce((n, h) => n + h.ports.length, 0)
  const avgRisk    = hosts.length > 0
    ? Math.round(hosts.reduce((n, h) => n + (h.riskScore ?? 0), 0) / hosts.length)
    : 0

  const wb = XLSX.utils.book_new()

  // Sheet 1: Executive Summary
  const ws1 = XLSX.utils.aoa_to_sheet([
    ['VECTRA NETWORK SECURITY ASSESSMENT REPORT'],
    [],
    ['Target',          target],
    ['Assessment Date', new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString()],
    ['Scan Profile',    scan?.scanProfile ?? 'Network Scan'],
    ['Report ID',       reportId],
    ['Generated By',    generatedBy],
    ['Generated At',    new Date().toLocaleString()],
    [],
    ['NETWORK SUMMARY'],
    ['Total Hosts',    hosts.length],
    ['Live Hosts',     liveHosts],
    ['Open Ports',     totalPorts],
    ['CVEs Found',     cves.length],
    ['Avg Risk Score', avgRisk],
    [],
    ['FINDINGS SUMMARY'],
    ['Severity', 'Count', 'Percentage'],
    ['Critical', FC.critical, findings.length ? `${Math.round((FC.critical / findings.length) * 100)}%` : '0%'],
    ['High',     FC.high,     findings.length ? `${Math.round((FC.high     / findings.length) * 100)}%` : '0%'],
    ['Medium',   FC.medium,   findings.length ? `${Math.round((FC.medium   / findings.length) * 100)}%` : '0%'],
    ['Low',      FC.low,      findings.length ? `${Math.round((FC.low      / findings.length) * 100)}%` : '0%'],
    ['Info',     FC.info,     findings.length ? `${Math.round((FC.info     / findings.length) * 100)}%` : '0%'],
    ['Total',    findings.length, '100%'],
  ])
  ws1['!cols'] = [{ wch: 24 }, { wch: 32 }, { wch: 16 }]
  XLSX.utils.book_append_sheet(wb, ws1, 'Executive Summary')

  // Sheet 2: Hosts
  const hHeaders = ['IP Address', 'Hostname', 'OS (Normalized)', 'OS Family', 'OS Confidence', 'Risk Score', 'Risk Level', 'Open Ports', 'MAC', 'Vendor', 'Status']
  const hRows = hosts.map((h) => [
    h.ip, h.hostname ?? '', h.os ?? '', h.osFamily ?? '',
    h.osConfidence != null ? `${h.osConfidence}%` : '',
    h.riskScore ?? '', h.riskLevel ?? '', h.ports.length,
    h.mac ?? '', h.vendor ?? '', h.status,
  ])
  const ws2 = XLSX.utils.aoa_to_sheet([hHeaders, ...hRows])
  ws2['!cols'] = [{ wch: 18 }, { wch: 28 }, { wch: 30 }, { wch: 14 }, { wch: 14 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 20 }, { wch: 20 }, { wch: 10 }]
  XLSX.utils.book_append_sheet(wb, ws2, 'Hosts')

  // Sheet 3: Open Ports & Services
  const allPorts = hosts.flatMap((h) => h.ports.map((p) => ({ ip: h.ip, hostname: h.hostname ?? '', ...p })))
  const ws3 = XLSX.utils.aoa_to_sheet([
    ['IP Address', 'Hostname', 'Port', 'Protocol', 'Service', 'Version', 'State'],
    ...allPorts.map((p) => [p.ip, p.hostname, p.port, p.protocol, p.service, p.version, p.state]),
  ])
  ws3['!cols'] = [{ wch: 18 }, { wch: 28 }, { wch: 10 }, { wch: 12 }, { wch: 20 }, { wch: 42 }, { wch: 10 }]
  XLSX.utils.book_append_sheet(wb, ws3, 'Open Ports & Services')

  // Sheet 4: Findings
  const sortedF = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
  const ws4 = XLSX.utils.aoa_to_sheet([
    ['#', 'IP', 'Port', 'Severity', 'Source', 'Finding', 'Description', 'Recommendation', 'Detected At'],
    ...sortedF.map((f, i) => [
      i + 1, f.ip, f.port ?? '', f.severity.toUpperCase(), f.source, f.title,
      f.description ?? '', f.recommendation ?? '', new Date(f.createdAt).toLocaleString(),
    ]),
  ])
  ws4['!cols'] = [{ wch: 4 }, { wch: 18 }, { wch: 8 }, { wch: 12 }, { wch: 16 }, { wch: 48 }, { wch: 60 }, { wch: 60 }, { wch: 20 }]
  XLSX.utils.book_append_sheet(wb, ws4, 'Findings')

  // Sheet 5: CVE Intelligence
  const ws5 = XLSX.utils.aoa_to_sheet([
    ['CVE ID', 'IP Address', 'Technology', 'Version', 'CVSS Score', 'Severity', 'Exploit Available', 'Published', 'Description'],
    ...cves.map((c) => [
      c.cveId, c.ip, c.technology, c.version, c.cvssScore,
      c.severity, c.exploitAvailable ? 'Yes' : 'No',
      c.published ? new Date(c.published).toLocaleDateString() : '',
      c.description,
    ]),
  ])
  ws5['!cols'] = [{ wch: 22 }, { wch: 18 }, { wch: 16 }, { wch: 16 }, { wch: 12 }, { wch: 12 }, { wch: 18 }, { wch: 14 }, { wch: 60 }]
  XLSX.utils.book_append_sheet(wb, ws5, 'CVE Intelligence')

  const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' })
  return new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}

// ── SAST Report ────────────────────────────────────────────────────────
//
// Built on the existing SAST pipeline: scans live in users/{uid}/sast_scans
// and findings in users/{uid}/sast_findings (written by the SAST scanner via
// lib/firestore-sast-*.ts). Nothing here re-scans or re-analyses anything —
// it reads what the scanner already produced and renders it through the same
// ReportDoc layout engine used by the web and network reports.

export interface SastReportData {
  projectName: string
  scan:        FirestoreSastScan | null
  findings:    FirestoreSastFinding[]
  reportId:    string
  generatedBy: string
}

export interface SastReportTarget {
  projectName:    string
  scanId:         string
  findingsCount:  number
  secretsCount:   number
  depVulnCount:   number
  language:       string
  uploadMethod:   string
  latestScan:     FirestoreSastScan | null
  latestScanDate: string
  latestStatus:   string
}

/** Human label for the source of a SAST scan. */
function sastSourceLabel(scan: FirestoreSastScan | null): string {
  if (!scan) return '—'
  if (scan.repoProvider && scan.repoOwner && scan.repoName) {
    return `${scan.repoProvider === 'github' ? 'GitHub' : 'GitLab'}: ${scan.repoOwner}/${scan.repoName}`
  }
  return scan.uploadMethod === 'zip' ? 'ZIP upload'
       : scan.uploadMethod === 'directory' ? 'Directory upload'
       : scan.uploadMethod ?? '—'
}

const SAST_CATEGORY_LABEL: Record<string, string> = {
  secret:     'Secret',
  owasp:      'Code',
  dependency: 'Dependency',
}

/**
 * One reportable entry per SAST project, using its most recent scan — mirrors
 * how web/network reports pick the latest scan for a target.
 */
export async function getSastReportableProjects(uid: string): Promise<SastReportTarget[]> {
  const scansSnap = await getDocs(collection(db, 'users', uid, 'sast_scans'))
  const allScans  = scansSnap.docs.map((d) => d.data() as FirestoreSastScan)

  const byProject = new Map<string, FirestoreSastScan[]>()
  allScans.forEach((s) => {
    const key = s.projectName || s.scanId
    if (!byProject.has(key)) byProject.set(key, [])
    byProject.get(key)!.push(s)
  })

  const result: SastReportTarget[] = []

  for (const [projectName, scans] of byProject) {
    const sorted = scans.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    )
    const latestScan = sorted[0]
    const findingsCount = latestScan.totalFindings ?? 0
    const secretsCount  = latestScan.secretFindings ?? 0
    const depVulnCount  = latestScan.dependencyVulns ?? 0

    // Skip scans that produced nothing at all.
    if (findingsCount === 0 && secretsCount === 0 && depVulnCount === 0) continue

    result.push({
      projectName,
      scanId:         latestScan.scanId,
      findingsCount,
      secretsCount,
      depVulnCount,
      language:       latestScan.language || '—',
      uploadMethod:   latestScan.uploadMethod ?? '—',
      latestScan,
      latestScanDate: latestScan.completedAt ?? latestScan.createdAt,
      latestStatus:   latestScan.status,
    })
  }

  return result.sort((a, b) => b.findingsCount - a.findingsCount || b.secretsCount - a.secretsCount)
}

/** Load a SAST scan plus its findings, scoped to the org/user that owns it. */
export async function fetchSastReportData(uid: string, scanId: string): Promise<{
  scan: FirestoreSastScan | null
  findings: FirestoreSastFinding[]
}> {
  const [scanSnap, findingsSnap] = await Promise.all([
    getDocs(query(collection(db, 'users', uid, 'sast_scans'), where('scanId', '==', scanId))),
    getDocs(query(collection(db, 'users', uid, 'sast_findings'), where('scanId', '==', scanId))),
  ])

  const scan = scanSnap.docs.length > 0
    ? (scanSnap.docs[0].data() as FirestoreSastScan)
    : null

  const findings = findingsSnap.docs
    .map((d) => d.data() as FirestoreSastFinding)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))

  return { scan, findings }
}

export async function generateSastPdf(data: SastReportData): Promise<Blob> {
  const { projectName, scan, findings, reportId, generatedBy } = data

  const rd = await createReportDoc(`SAST Assessment | ${projectName}`)
  const C  = severityCounts(findings)
  const risk = computeOverallRisk(C)

  const scanDate = new Date(scan?.completedAt ?? scan?.createdAt ?? Date.now()).toLocaleDateString(
    'en-US', { year: 'numeric', month: 'long', day: 'numeric' },
  )

  const secrets     = findings.filter((f) => f.category === 'secret')
  const dependency  = findings.filter((f) => f.category === 'dependency')
  const codeIssues  = findings.filter((f) => f.category === 'owasp')
  const withCve     = dependency.filter((f) => f.cveId)
  const languages   = (scan?.language ?? '')
    .split(/[,/]/).map((s) => s.trim()).filter(Boolean)

  // ─── COVER ────────────────────────────────────────────────────────

  drawCover(rd, {
    kicker:   'STATIC APPLICATION SECURITY TESTING',
    subtitle: 'Source Code Security Assessment',
    target:   projectName,
    stats: [
      { label: 'Total Findings',  value: String(findings.length),        color: COLOR.ink },
      { label: 'Critical',        value: String(C.critical),             color: SEV_TEXT.critical },
      { label: 'High',            value: String(C.high),                 color: SEV_TEXT.high },
      { label: 'Secrets',         value: String(secrets.length),         color: COLOR.accent },
      { label: 'Medium',          value: String(C.medium),               color: SEV_TEXT.medium },
      { label: 'Low',             value: String(C.low),                  color: SEV_TEXT.low },
      { label: 'Dependency Vulns', value: String(dependency.length),     color: [29, 78, 216] },
      { label: 'Files Scanned',   value: String(scan?.scannedFiles ?? 0), color: COLOR.ink },
    ],
    meta: [
      ['Assessment Date', scanDate],
      ['Source',          sastSourceLabel(scan)],
      ['Languages',       languages.join(', ') || '—'],
      ['Generated By',    generatedBy],
      ['Report ID',       reportId],
      ['Classification',  'CONFIDENTIAL'],
    ],
  })

  // ─── EXECUTIVE SUMMARY ────────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Executive Summary')

  rd.paragraph(
    `This static application security assessment analysed the source code of ${projectName} on ${scanDate}. ` +
    `${scan?.scannedFiles ?? 0} of ${scan?.totalFiles ?? 0} file${(scan?.totalFiles ?? 0) !== 1 ? 's' : ''} were scanned, ` +
    `identifying ${findings.length} finding${findings.length !== 1 ? 's' : ''}. ` +
    (secrets.length > 0
      ? `${secrets.length} hardcoded secret${secrets.length !== 1 ? 's' : ''} or credential${secrets.length !== 1 ? 's' : ''} were detected and require immediate rotation. `
      : '') +
    (dependency.length > 0
      ? `${dependency.length} vulnerable dependenc${dependency.length !== 1 ? 'ies were' : 'y was'} identified` +
        (withCve.length > 0 ? `, ${withCve.length} with an associated CVE` : '') + '. '
      : '') +
    'Findings are mapped to CWE and OWASP categories and prioritized for remediation.',
    { size: 9 },
  )
  rd.space(SPACE.block)

  rd.badge(`OVERALL RISK: ${risk.label.toUpperCase()}`, risk.rgb)
  rd.space(SPACE.block)

  severityBreakdownTable(rd, C, findings.length)

  // ─── SCAN & SOURCE INFORMATION ────────────────────────────────────

  rd.sectionTitle('Scan & Source Information')

  const scanRows: [string, string][] = [
    ['Project',        projectName],
    ['Scan ID',        scan?.scanId ?? '—'],
    ['Source',         sastSourceLabel(scan)],
    ['Languages',      languages.join(', ') || '—'],
    ['Files Scanned',  `${scan?.scannedFiles ?? 0} of ${scan?.totalFiles ?? 0}`],
    ['Status',         (scan?.status ?? '—').toUpperCase()],
    ['Duration',       scan?.duration ?? '—'],
  ]
  if (scan?.repoBranch)        scanRows.push(['Branch',         scan.repoBranch])
  if (scan?.repoCommitSha)     scanRows.push(['Commit',         scan.repoCommitSha.slice(0, 12)])
  if (scan?.repoCommitAuthor)  scanRows.push(['Commit Author',  scan.repoCommitAuthor])
  if (scan?.repoCommitDate) {
    scanRows.push(['Commit Date', new Date(scan.repoCommitDate).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
    })])
  }
  if (scan?.repoCommitMessage) scanRows.push(['Commit Message', scan.repoCommitMessage])

  rd.metaRows(scanRows, 46)
  rd.space(SPACE.section)

  // ─── FINDINGS SUMMARY ─────────────────────────────────────────────

  if (findings.length > 0) {
    rd.newPage()
    rd.sectionTitle('Findings Summary')

    rd.table(
      [
        { header: '#',        width: 8,  align: 'center' },
        { header: 'Issue',    width: 52 },
        { header: 'Severity', width: 20, align: 'center' },
        { header: 'Type',     width: 22, align: 'center' },
        { header: 'CWE',      width: 20, align: 'center' },
        { header: 'Location', width: 44 },
      ],
      findings.map((f, i) => [
        i + 1,
        f.title,
        (f.severity ?? '').toUpperCase(),
        SAST_CATEGORY_LABEL[f.category] ?? f.category,
        f.cweId || '—',
        f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '—',
      ]),
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 2) },
    )

    // ─── DETAILED FINDINGS ──────────────────────────────────────────

    rd.sectionTitle('Detailed Findings')

    for (const f of findings.slice(0, 40)) {
      const sev = (f.severity ?? '').toLowerCase()
      detailCard(rd, {
        title:  f.title,
        meta:   `${sev.toUpperCase()}  ·  ${SAST_CATEGORY_LABEL[f.category] ?? f.category}`,
        fill:   SEV_FILL[sev] ?? SEV_FILL.unknown,
        accent: SEV_TEXT[sev] ?? SEV_TEXT.unknown,
        rows: [
          ...(f.file ? [{ label: 'Location', text: `${f.file}${f.line ? `:${f.line}` : ''}`, size: 7.5 }] : []),
          ...(f.description ? [{ text: f.description }] : []),
          ...(f.code ? [{ label: 'Code', text: f.code, size: 7.5 }] : []),
          ...(f.cweId ? [{ label: 'CWE', text: `${f.cweId}${f.cweName ? ` — ${f.cweName}` : ''}`, size: 7.5 }] : []),
          ...(f.owaspCategory ? [{ label: 'OWASP', text: f.owaspCategory, size: 7.5 }] : []),
          ...(f.dependencyName
            ? [{ label: 'Dependency', text: `${f.dependencyName}${f.dependencyVersion ? `@${f.dependencyVersion}` : ''}`, size: 7.5 }]
            : []),
          ...(f.cveId
            ? [{ label: 'CVE', text: `${f.cveId}${f.cvssScore != null ? ` (CVSS ${f.cvssScore.toFixed(1)})` : ''}`, size: 7.5 }]
            : []),
          ...(f.recommendation
            ? [{ label: 'Remediation', text: f.recommendation, style: 'italic' as const, size: 7.5 }]
            : []),
        ],
      })
    }
  }

  // ─── SECRETS ──────────────────────────────────────────────────────

  if (secrets.length > 0) {
    rd.newPage()
    rd.sectionTitle('Hardcoded Secrets & Credentials')

    rd.paragraph(
      'Secrets committed to source control must be treated as compromised. Rotate each credential ' +
      'below, then purge it from the repository history.',
      { size: 8.5, color: COLOR.muted },
    )
    rd.space(SPACE.block)

    rd.table(
      [
        { header: 'Secret Type', width: 42 },
        { header: 'Severity',    width: 20, align: 'center' },
        { header: 'File',        width: 68 },
        { header: 'Line',        width: 14, align: 'center' },
        { header: 'CWE',         width: 22, align: 'center' },
      ],
      secrets.map((f) => [
        f.type || f.title,
        (f.severity ?? '').toUpperCase(),
        f.file || '—',
        f.line ? String(f.line) : '—',
        f.cweId || '—',
      ]),
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 1) },
    )
  }

  // ─── DEPENDENCY VULNERABILITIES ───────────────────────────────────

  if (dependency.length > 0) {
    rd.sectionTitle('Dependency Vulnerabilities')

    rd.table(
      [
        { header: 'Dependency', width: 42 },
        { header: 'Version',    width: 22, align: 'center' },
        { header: 'CVE',        width: 32, align: 'center' },
        { header: 'CVSS',       width: 14, align: 'center' },
        { header: 'Severity',   width: 20, align: 'center' },
        { header: 'Issue',      width: 36 },
      ],
      dependency.map((f) => [
        f.dependencyName || '—',
        f.dependencyVersion || '—',
        f.cveId || '—',
        f.cvssScore != null ? f.cvssScore.toFixed(1) : '—',
        (f.severity ?? '').toUpperCase(),
        f.title,
      ]),
      {
        didParseCell: (d: any) => {
          ReportDoc.severityCell(d, 4)
          if (d.section === 'body' && d.column.index === 2 && String(d.cell.raw).startsWith('CVE')) {
            d.cell.styles.textColor = [109, 40, 217]
            d.cell.styles.fontStyle = 'bold'
          }
        },
      },
    )
  }

  // ─── CWE / OWASP DISTRIBUTION ─────────────────────────────────────

  const groupCount = (items: FirestoreSastFinding[], key: (f: FirestoreSastFinding) => string) => {
    const m = new Map<string, number>()
    for (const f of items) {
      const k = key(f)
      if (!k) continue
      m.set(k, (m.get(k) ?? 0) + 1)
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1])
  }

  const cweGroups   = groupCount(findings, (f) => (f.cweId ? `${f.cweId}|${f.cweName ?? ''}` : ''))
  const owaspGroups = groupCount(findings, (f) => f.owaspCategory ?? '')

  if (cweGroups.length > 0) {
    rd.sectionTitle('CWE Distribution')
    rd.table(
      [
        { header: 'CWE ID',   width: 26, align: 'center' },
        { header: 'Weakness', width: 96 },
        { header: 'Findings', width: 20, align: 'center' },
        { header: '% of Total', width: 24, align: 'center' },
      ],
      cweGroups.map(([k, n]) => {
        const [id, name] = k.split('|')
        return [
          id,
          name || '—',
          n,
          findings.length ? `${Math.round((n / findings.length) * 100)}%` : '0%',
        ]
      }),
    )
  }

  if (owaspGroups.length > 0) {
    rd.sectionTitle('OWASP Category Mapping')
    rd.table(
      [
        { header: 'OWASP Category', width: 118 },
        { header: 'Findings',       width: 22, align: 'center' },
        { header: '% of Total',     width: 26, align: 'center' },
      ],
      owaspGroups.map(([name, n]) => [
        name,
        n,
        findings.length ? `${Math.round((n / findings.length) * 100)}%` : '0%',
      ]),
    )
  }

  // ─── RECOMMENDATIONS ──────────────────────────────────────────────

  if (findings.length > 0) {
    rd.newPage()
    rd.sectionTitle('Remediation Recommendations')

    const sorted = [...findings].sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5),
    )
    sorted.slice(0, 30).forEach((f, i) => {
      const where = f.file ? ` (${f.file}${f.line ? `:${f.line}` : ''})` : ''
      remediationEntry(
        rd, i + 1, f.severity, f.title,
        (f.recommendation ?? `Review and remediate the "${f.title}" issue per your secure coding policy.`) + where,
      )
    })
  }

  rd.drawFooters(reportId)
  return rd.doc.output('blob') as unknown as Blob
}

export async function generateSastExcel(data: SastReportData): Promise<Blob> {
  const XLSX = await import('xlsx')

  const { projectName, scan, findings, reportId, generatedBy } = data

  const C          = severityCounts(findings)
  const secrets    = findings.filter((f) => f.category === 'secret')
  const dependency = findings.filter((f) => f.category === 'dependency')

  const wb = XLSX.utils.book_new()

  // Summary
  const ws1 = XLSX.utils.aoa_to_sheet([
    ['Vectra SAST Security Report'],
    [],
    ['Project',        projectName],
    ['Scan ID',        scan?.scanId ?? '—'],
    ['Source',         sastSourceLabel(scan)],
    ['Languages',      scan?.language ?? '—'],
    ['Files Scanned',  `${scan?.scannedFiles ?? 0} of ${scan?.totalFiles ?? 0}`],
    ['Status',         scan?.status ?? '—'],
    ['Duration',       scan?.duration ?? '—'],
    ['Report ID',      reportId],
    ['Generated By',   generatedBy],
    ['Generated At',   new Date().toISOString()],
    [],
    ['Severity', 'Count'],
    ['Critical', C.critical],
    ['High',     C.high],
    ['Medium',   C.medium],
    ['Low',      C.low],
    ['Info',     C.info],
    ['Total',    findings.length],
    [],
    ['Secrets',                secrets.length],
    ['Dependency Vulnerabilities', dependency.length],
  ])
  ws1['!cols'] = [{ wch: 28 }, { wch: 60 }]
  XLSX.utils.book_append_sheet(wb, ws1, 'Summary')

  // Findings
  const ws2 = XLSX.utils.aoa_to_sheet([
    ['#', 'Title', 'Severity', 'Category', 'Type', 'File', 'Line', 'CWE ID', 'CWE Name', 'OWASP', 'Description', 'Code', 'Recommendation'],
    ...findings.map((f, i) => [
      i + 1, f.title, f.severity, f.category, f.type,
      f.file, f.line, f.cweId, f.cweName, f.owaspCategory,
      f.description, f.code, f.recommendation,
    ]),
  ])
  ws2['!cols'] = [
    { wch: 6 }, { wch: 46 }, { wch: 10 }, { wch: 12 }, { wch: 20 },
    { wch: 44 }, { wch: 8 }, { wch: 12 }, { wch: 34 }, { wch: 30 },
    { wch: 70 }, { wch: 50 }, { wch: 70 },
  ]
  XLSX.utils.book_append_sheet(wb, ws2, 'Findings')

  // Secrets
  if (secrets.length > 0) {
    const ws3 = XLSX.utils.aoa_to_sheet([
      ['Secret Type', 'Severity', 'File', 'Line', 'CWE ID', 'Recommendation'],
      ...secrets.map((f) => [f.type || f.title, f.severity, f.file, f.line, f.cweId, f.recommendation]),
    ])
    ws3['!cols'] = [{ wch: 30 }, { wch: 10 }, { wch: 50 }, { wch: 8 }, { wch: 12 }, { wch: 70 }]
    XLSX.utils.book_append_sheet(wb, ws3, 'Secrets')
  }

  // Dependencies
  if (dependency.length > 0) {
    const ws4 = XLSX.utils.aoa_to_sheet([
      ['Dependency', 'Version', 'CVE', 'CVSS', 'Severity', 'Issue', 'Recommendation'],
      ...dependency.map((f) => [
        f.dependencyName, f.dependencyVersion, f.cveId, f.cvssScore,
        f.severity, f.title, f.recommendation,
      ]),
    ])
    ws4['!cols'] = [{ wch: 30 }, { wch: 14 }, { wch: 18 }, { wch: 8 }, { wch: 10 }, { wch: 46 }, { wch: 70 }]
    XLSX.utils.book_append_sheet(wb, ws4, 'Dependencies')
  }

  const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' })
  return new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}

// ── Cloud Security report ─────────────────────────────────────────────
//
// Data comes from GET /cloud/report-data, which the backend scopes to the
// caller's organization (and optionally one integration). Layout reuses the
// same ReportDoc engine, cover, tables and cards as the other reports.

export interface CloudReportData {
  scopeLabel:   string
  integrations: CloudIntegration[]
  findings:     CloudFinding[]
  assets:       CloudAsset[]
  truncated:    boolean
  reportId:     string
  generatedBy:  string
}

function cloudLocation(f: CloudFinding): string {
  return [f.accountId, f.region].filter(Boolean).join(' · ') || '—'
}

export async function generateCloudPdf(data: CloudReportData): Promise<Blob> {
  const { scopeLabel, integrations, findings, assets, truncated, reportId, generatedBy } = data

  const rd   = await createReportDoc(`Cloud Security | ${scopeLabel}`)
  const C    = severityCounts(findings)
  const risk = computeOverallRisk(C)
  const genDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const providers = [...new Set(integrations.map((i) => i.provider))]
  const withCve   = findings.filter((f) => f.cveId)
  const lastSync  = integrations.map((i) => i.lastSyncAt).filter(Boolean).sort().pop()

  // ─── COVER ────────────────────────────────────────────────────────

  drawCover(rd, {
    kicker:   'CLOUD SECURITY',
    subtitle: 'Cloud Security Findings Assessment',
    target:   scopeLabel,
    stats: [
      { label: 'Findings',   value: String(findings.length),     color: COLOR.ink },
      { label: 'Critical',   value: String(C.critical),          color: SEV_TEXT.critical },
      { label: 'High',       value: String(C.high),              color: SEV_TEXT.high },
      { label: 'Assets',     value: String(assets.length),       color: COLOR.accent },
      { label: 'Medium',     value: String(C.medium),            color: SEV_TEXT.medium },
      { label: 'Low',        value: String(C.low),               color: SEV_TEXT.low },
      { label: 'With CVE',   value: String(withCve.length),      color: [109, 40, 217] },
      { label: 'Accounts',   value: String(integrations.length), color: COLOR.ink },
    ],
    meta: [
      ['Report Date',    genDate],
      ['Providers',      providers.map(providerLabel).join(', ') || '—'],
      ['Last Sync',      lastSync ? new Date(lastSync).toLocaleString('en-US') : '—'],
      ['Generated By',   generatedBy],
      ['Report ID',      reportId],
      ['Classification', 'CONFIDENTIAL'],
    ],
  })

  // ─── EXECUTIVE SUMMARY ────────────────────────────────────────────

  rd.newPage()
  rd.sectionTitle('Executive Summary')
  rd.paragraph(
    `This report summarizes the open security findings imported from ${integrations.length} connected cloud ` +
    `account${integrations.length !== 1 ? 's' : ''} (${providers.map(providerLabel).join(' and ') || 'no providers'}) as of ${genDate}. ` +
    `${findings.length} finding${findings.length !== 1 ? 's' : ''} affect ${assets.length} cloud resource${assets.length !== 1 ? 's' : ''}` +
    (withCve.length ? `, including ${withCve.length} linked to a published CVE` : '') + '. ' +
    'Findings are reported by each provider\'s native security service and normalized by Vectra; ' +
    'severity reflects the provider\'s rating.' +
    (truncated ? ' This report was limited to the first 5,000 findings.' : ''),
    { size: 9 },
  )
  rd.space(SPACE.block)
  rd.badge(`OVERALL RISK: ${risk.label.toUpperCase()}`, risk.rgb)
  rd.space(SPACE.block)
  severityBreakdownTable(rd, C, findings.length)

  // ─── PROVIDER SUMMARY ─────────────────────────────────────────────

  rd.sectionTitle('Cloud Provider Summary')
  rd.table(
    [
      { header: 'Integration', width: 44 },
      { header: 'Provider',    width: 24 },
      { header: 'Account',     width: 34 },
      { header: 'Findings',    width: 18, align: 'center' },
      { header: 'Critical',    width: 16, align: 'center' },
      { header: 'Last Sync',   width: 30, align: 'center' },
    ],
    integrations.map((i) => {
      const own = findings.filter((f) => f.integrationId === i.integrationId)
      return [
        i.displayName,
        providerLabel(i.provider),
        i.accountId ?? '—',
        own.length,
        own.filter((f) => f.severity === 'critical').length,
        i.lastSyncAt ? new Date(i.lastSyncAt).toLocaleDateString('en-US') : 'Never',
      ]
    }),
  )

  for (const p of providers) {
    const pf = findings.filter((f) => f.provider === p)
    const pc = severityCounts(pf)
    rd.paragraph(
      `${providerLabel(p)}: ${pf.length} findings — ${pc.critical} critical, ${pc.high} high, ${pc.medium} medium, ${pc.low} low, ${pc.info} informational.`,
      { size: 8.5, color: COLOR.muted },
    )
  }
  rd.space(SPACE.section)

  // ─── AFFECTED ASSETS ──────────────────────────────────────────────

  if (assets.length > 0) {
    rd.sectionTitle('Affected Assets')
    rd.table(
      [
        { header: 'Resource',  width: 62 },
        { header: 'Type',      width: 38 },
        { header: 'Provider',  width: 22 },
        { header: 'Region',    width: 24 },
        { header: 'Open',      width: 20, align: 'center' },
      ],
      assets.slice(0, 60).map((a) => [
        truncUrl(a.resourceName ?? a.resourceId, 48),
        a.resourceType,
        providerLabel(a.provider),
        a.region ?? '—',
        a.openFindingCount,
      ]),
    )
    if (assets.length > 60) {
      rd.paragraph(`${assets.length - 60} additional assets are listed in the Excel export.`, { size: 8, color: COLOR.muted })
    }
  }

  // ─── FINDINGS SUMMARY ─────────────────────────────────────────────

  if (findings.length > 0) {
    rd.newPage()
    rd.sectionTitle('Findings Summary')
    rd.table(
      [
        { header: '#',        width: 8,  align: 'center' },
        { header: 'Finding',  width: 60 },
        { header: 'Severity', width: 20, align: 'center' },
        { header: 'Provider', width: 20, align: 'center' },
        { header: 'Resource', width: 58 },
      ],
      findings.map((f, i) => [
        i + 1,
        f.title,
        f.severity.toUpperCase(),
        providerLabel(f.provider),
        truncUrl(f.resourceName ?? f.resourceId, 44),
      ]),
      { didParseCell: (d: any) => ReportDoc.severityCell(d, 2) },
    )

    // ─── CVE INFORMATION ────────────────────────────────────────────

    if (withCve.length > 0) {
      rd.sectionTitle('Vulnerabilities (CVE)')
      rd.table(
        [
          { header: 'CVE',      width: 32, align: 'center' },
          { header: 'CVSS',     width: 14, align: 'center' },
          { header: 'Severity', width: 20, align: 'center' },
          { header: 'Package',  width: 40 },
          { header: 'Resource', width: 60 },
        ],
        withCve.map((f) => {
          const pkg = f.affectedPackages?.[0]
          return [
            f.cveIds.join(', '),
            f.cvssScore != null ? f.cvssScore.toFixed(1) : '—',
            f.severity.toUpperCase(),
            pkg ? `${pkg.name}${pkg.version ? ` ${pkg.version}` : ''}${pkg.fixedInVersion ? ` (fixed in ${pkg.fixedInVersion})` : ''}` : '—',
            truncUrl(f.resourceName ?? f.resourceId, 44),
          ]
        }),
        { didParseCell: (d: any) => ReportDoc.severityCell(d, 2) },
      )
    }

    // ─── DETAILED FINDINGS ──────────────────────────────────────────

    rd.sectionTitle('Detailed Findings')
    for (const f of findings.slice(0, 40)) {
      const sev = f.severity
      detailCard(rd, {
        title:  f.title,
        meta:   `${sev.toUpperCase()}  ·  ${providerLabel(f.provider)}`,
        fill:   SEV_FILL[sev] ?? SEV_FILL.unknown,
        accent: SEV_TEXT[sev] ?? SEV_TEXT.unknown,
        rows: [
          { label: 'Resource', text: `${f.resourceId ?? '—'}${f.resourceType ? ` (${f.resourceType})` : ''}`, size: 7.5 },
          { label: 'Location', text: cloudLocation(f), size: 7.5 },
          ...(f.findingType ? [{ label: 'Type', text: f.findingType, size: 7.5 }] : []),
          ...(f.description ? [{ text: f.description }] : []),
          ...(f.cveId ? [{ label: 'CVE', text: `${f.cveIds.join(', ')}${f.cvssScore != null ? ` (CVSS ${f.cvssScore.toFixed(1)})` : ''}`, size: 7.5 }] : []),
          ...(f.compliance?.securityControlId ? [{ label: 'Control', text: f.compliance.securityControlId, size: 7.5 }] : []),
          ...(f.recommendation ? [{ label: 'Remediation', text: f.recommendation, style: 'italic' as const, size: 7.5 }] : []),
          ...(f.remediationUrl || f.sourceUrl ? [{ label: 'Reference', text: (f.remediationUrl ?? f.sourceUrl)!, size: 7 }] : []),
          { label: 'Timeline', text: `First seen ${new Date(f.firstSeenAt).toLocaleDateString('en-US')} · last seen ${new Date(f.lastSeenAt).toLocaleDateString('en-US')}`, size: 7 },
        ],
      })
    }
    if (findings.length > 40) {
      rd.paragraph(`${findings.length - 40} further findings are included in the summary table and the Excel export.`, { size: 8, color: COLOR.muted })
    }

    // ─── RECOMMENDATIONS ────────────────────────────────────────────

    rd.newPage()
    rd.sectionTitle('Remediation Recommendations')
    findings.slice(0, 30).forEach((f, i) => {
      remediationEntry(
        rd, i + 1, f.severity, f.title,
        (f.recommendation ?? `Review "${f.title}" in ${providerLabel(f.provider)} and remediate per your cloud security policy.`) +
        ` (${f.resourceName ?? f.resourceId ?? 'resource'}${f.region ? `, ${f.region}` : ''})`,
      )
    })
  }

  rd.drawFooters(reportId)
  return rd.doc.output('blob') as unknown as Blob
}

export async function generateCloudExcel(data: CloudReportData): Promise<Blob> {
  const XLSX = await import('xlsx')
  const { scopeLabel, integrations, findings, assets, reportId, generatedBy, truncated } = data
  const C = severityCounts(findings)
  const wb = XLSX.utils.book_new()

  const ws1 = XLSX.utils.aoa_to_sheet([
    ['Vectra Cloud Security Report'],
    [],
    ['Scope',        scopeLabel],
    ['Report ID',    reportId],
    ['Generated By', generatedBy],
    ['Generated At', new Date().toISOString()],
    ['Truncated',    truncated ? 'Yes (first 5,000 findings)' : 'No'],
    [],
    ['Severity', 'Count'],
    ['Critical', C.critical], ['High', C.high], ['Medium', C.medium], ['Low', C.low], ['Info', C.info],
    ['Total', findings.length],
    [],
    ['Integration', 'Provider', 'Account', 'Status', 'Last Sync'],
    ...integrations.map((i) => [i.displayName, providerLabel(i.provider), i.accountId ?? '', i.status, i.lastSyncAt ?? '']),
  ])
  ws1['!cols'] = [{ wch: 30 }, { wch: 20 }, { wch: 24 }, { wch: 14 }, { wch: 28 }]
  XLSX.utils.book_append_sheet(wb, ws1, 'Summary')

  const ws2 = XLSX.utils.aoa_to_sheet([
    ['#', 'Title', 'Severity', 'Status', 'Provider', 'Product', 'Finding Type', 'Account/Project', 'Region',
     'Resource Type', 'Resource ID', 'CVE', 'CVSS', 'Description', 'Recommendation', 'Reference', 'First Seen', 'Last Seen', 'Provider Finding ID'],
    ...findings.map((f, i) => [
      i + 1, f.title, f.severity, f.status, providerLabel(f.provider), f.providerProduct ?? '', f.findingType ?? '',
      f.accountId ?? '', f.region ?? '', f.resourceType ?? '', f.resourceId ?? '', f.cveIds.join(', '),
      f.cvssScore ?? '', f.description, f.recommendation ?? '', f.remediationUrl ?? f.sourceUrl ?? '',
      f.firstSeenAt, f.lastSeenAt, f.providerFindingId,
    ]),
  ])
  XLSX.utils.book_append_sheet(wb, ws2, 'Findings')

  const ws3 = XLSX.utils.aoa_to_sheet([
    ['Resource', 'Resource ID', 'Type', 'Provider', 'Account/Project', 'Region', 'Open Findings', 'Total Findings', 'Last Seen'],
    ...assets.map((a) => [a.resourceName ?? '', a.resourceId, a.resourceType, providerLabel(a.provider), a.accountId ?? '',
      a.region ?? '', a.openFindingCount, a.findingCount, a.lastSeenAt]),
  ])
  XLSX.utils.book_append_sheet(wb, ws3, 'Assets')

  const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' })
  return new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}
