/**
 * Vectra PDF layout engine.
 *
 * A single flow-layout system shared by every report generator (web, network,
 * SAST). It owns page geometry, the vertical cursor, text measurement and page
 * breaks so that individual reports never compute coordinates by hand.
 *
 * Two invariants make the output reliable:
 *
 *  1. `y` is always the TOP of the next block, never a text baseline. All text
 *     is drawn with `baseline: 'top'`, so advancing the cursor by the measured
 *     height of a block lands exactly on its bottom edge.
 *
 *  2. Height is measured with the same helpers used to draw. A block's
 *     reserved space can therefore never disagree with what is rendered,
 *     which is what allows page breaks to be decided before drawing.
 */

const PT_PER_MM = 72 / 25.4

export const mmFromPt = (pt: number): number => pt / PT_PER_MM

// ── Geometry (A4 portrait, millimetres) ───────────────────────────────

export const PAGE = {
  width:     210,
  height:    297,
  margin:    14,
  /** Dark brand band at the top of every content page (incl. accent rule). */
  headerBand: 14.8,
  /** Gap between the header band and the first block of content. */
  headerGap:  7.2,
  /** Reserved strip at the foot of the page — nothing may enter it. */
  footer:     16,
} as const

// ── Vertical rhythm ───────────────────────────────────────────────────

export const SPACE = {
  section:   12,
  block:      6,
  paragraph:  4,
  tight:      2,
} as const

// ── Palette ───────────────────────────────────────────────────────────

export type Rgb = [number, number, number]

export const COLOR = {
  ink:        [15, 15, 15]    as Rgb,
  body:       [45, 45, 45]    as Rgb,
  muted:      [110, 110, 110] as Rgb,
  faint:      [150, 150, 150] as Rgb,
  rule:       [222, 222, 222] as Rgb,
  bandBg:     [15, 15, 15]    as Rgb,
  coverBg:    [12, 12, 12]    as Rgb,
  accent:     [124, 58, 237]  as Rgb,
  sectionBg:  [245, 245, 245] as Rgb,
  tableHead:  [20, 20, 20]    as Rgb,
  white:      [255, 255, 255] as Rgb,
} as const

export const SEV_FILL: Record<string, Rgb> = {
  critical: [254, 226, 226],
  high:     [255, 237, 213],
  medium:   [254, 249, 195],
  low:      [219, 234, 254],
  info:     [243, 244, 246],
  unknown:  [243, 244, 246],
}

export const SEV_TEXT: Record<string, Rgb> = {
  critical: [185, 28, 28],
  high:     [154, 52, 18],
  medium:   [133, 77, 14],
  low:      [29, 78, 216],
  info:     [75, 85, 99],
  unknown:  [75, 85, 99],
}

export const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
}

// ── Types ─────────────────────────────────────────────────────────────

export type FontStyle = 'normal' | 'bold' | 'italic'

export interface TextOpts {
  size?:   number
  style?:  FontStyle
  color?:  Rgb
  /** Width of the text box; defaults to the full content width. */
  width?:  number
  /** Left offset from the content edge. */
  indent?: number
  align?:  'left' | 'center' | 'right'
}

export interface ColumnSpec {
  header: string
  /** Share of the content width. Fractions are normalised, so they always
   *  sum to exactly the content width and can never overflow the page. */
  width:  number
  align?: 'left' | 'center' | 'right'
}

export interface StatItem {
  label: string
  value: string
  color?: Rgb
}

/** Minimal structural type for the bits of jsPDF this engine uses. */
type Doc = any

// ── Engine ────────────────────────────────────────────────────────────

export class ReportDoc {
  readonly doc: Doc
  private readonly autoTable: any

  readonly W = PAGE.width
  readonly H = PAGE.height
  readonly M = PAGE.margin
  /** Usable content width — every block is laid out against this. */
  readonly CW = PAGE.width - 2 * PAGE.margin

  /** Right-hand caption shown in the running header band. */
  private headerLabel: string
  private y_ = 0
  /** Pages that already carry the header band, so it is never drawn twice. */
  private headerPages = new Set<number>()

  constructor(doc: Doc, autoTable: any, headerLabel: string) {
    this.doc = doc
    this.autoTable = autoTable
    this.headerLabel = headerLabel
  }

  // ── Cursor / bounds ─────────────────────────────────────────────────

  get y(): number { return this.y_ }
  set y(v: number) { this.y_ = v }

  /** First usable y on a content page. */
  get contentTop(): number { return PAGE.headerBand + PAGE.headerGap }

  /** Last usable y — content must never cross this into the footer strip. */
  get contentBottom(): number { return this.H - PAGE.footer }

  get left(): number { return this.M }
  get right(): number { return this.W - this.M }

  // ── Measurement ─────────────────────────────────────────────────────

  /** True rendered height of one line at `size`, in mm. */
  lineHeight(size: number): number {
    return mmFromPt(size * this.doc.getLineHeightFactor())
  }

  private applyFont(size: number, style: FontStyle, color: Rgb): void {
    this.doc.setFont('helvetica', style)
    this.doc.setFontSize(size)
    this.doc.setTextColor(color[0], color[1], color[2])
  }

  /** Wrap `text` to `width` and return the resulting lines. */
  wrap(text: string, width: number, size: number, style: FontStyle = 'normal'): string[] {
    this.doc.setFont('helvetica', style)
    this.doc.setFontSize(size)
    return this.doc.splitTextToSize(String(text ?? ''), width) as string[]
  }

  /** Exact height a paragraph will occupy, without drawing it. */
  measure(text: string, opts: TextOpts = {}): number {
    const size  = opts.size ?? 9
    const width = opts.width ?? (this.CW - (opts.indent ?? 0))
    return this.wrap(text, width, size, opts.style ?? 'normal').length * this.lineHeight(size)
  }

  // ── Page flow ───────────────────────────────────────────────────────

  /** Start a fresh content page and reset the cursor below the header band. */
  newPage(): void {
    this.doc.addPage()
    this.drawRunningHeader()
    this.y_ = this.contentTop
  }

  /** Ensure `h` mm is available; otherwise break to a new page. */
  ensure(h: number): void {
    if (this.y_ + h > this.contentBottom) this.newPage()
  }

  space(h: number = SPACE.block): void { this.y_ += h }

  // ── Chrome ──────────────────────────────────────────────────────────

  /** Current 1-based page number. */
  get pageNumber(): number {
    try { return this.doc.internal.getCurrentPageInfo().pageNumber } catch { return 1 }
  }

  /**
   * Paint the header band. Idempotent per page: both `newPage()` and
   * autoTable's `didDrawPage` ask for it, and a table starting on a freshly
   * created page would otherwise draw it twice.
   */
  drawRunningHeader(): void {
    const page = this.pageNumber
    if (this.headerPages.has(page)) return
    this.headerPages.add(page)

    const d = this.doc
    d.setFillColor(...COLOR.bandBg)
    d.rect(0, 0, this.W, PAGE.headerBand - 0.8, 'F')
    d.setFillColor(...COLOR.accent)
    d.rect(0, PAGE.headerBand - 0.8, this.W, 0.8, 'F')

    const mid = (PAGE.headerBand - 0.8) / 2
    d.setFont('helvetica', 'bold')
    d.setFontSize(8.5)
    d.setTextColor(255, 255, 255)
    d.text('VECTRA', this.M, mid, { baseline: 'middle' })

    d.setFont('helvetica', 'normal')
    d.setFontSize(7.5)
    d.setTextColor(170, 170, 170)
    d.text(this.headerLabel, this.right, mid, { baseline: 'middle', align: 'right' })
  }

  /**
   * Stamp footers on every page except the cover. Runs last so the total page
   * count is known. The footer lives inside the reserved strip that
   * `contentBottom` keeps clear, so it can never overprint content.
   */
  drawFooters(reportId: string): void {
    const d = this.doc
    const total = d.internal.getNumberOfPages()
    for (let p = 2; p <= total; p++) {
      d.setPage(p)
      d.setDrawColor(...COLOR.rule)
      d.setLineWidth(0.2)
      d.line(this.M, this.H - 11, this.right, this.H - 11)

      d.setFont('helvetica', 'normal')
      d.setFontSize(6.5)
      d.setTextColor(...COLOR.faint)
      const baseY = this.H - 7.5
      d.text(`Report ID: ${reportId}`, this.M, baseY, { baseline: 'top' })
      d.text('CONFIDENTIAL', this.W / 2, baseY, { baseline: 'top', align: 'center' })
      d.text(`Page ${p - 1} of ${total - 1}`, this.right, baseY, { baseline: 'top', align: 'right' })
    }
  }

  // ── Text blocks ─────────────────────────────────────────────────────

  /**
   * Draw a paragraph, flowing across page breaks line by line so that
   * arbitrarily long text can never overflow the content box.
   */
  paragraph(text: string, opts: TextOpts = {}): void {
    if (!text) return
    const size   = opts.size  ?? 9
    const style  = opts.style ?? 'normal'
    const color  = opts.color ?? COLOR.body
    const indent = opts.indent ?? 0
    const width  = opts.width ?? (this.CW - indent)
    const lh     = this.lineHeight(size)
    const lines  = this.wrap(text, width, size, style)

    const x =
      opts.align === 'center' ? this.M + indent + width / 2 :
      opts.align === 'right'  ? this.M + indent + width :
      this.M + indent

    for (const line of lines) {
      this.ensure(lh)
      this.applyFont(size, style, color)
      this.doc.text(line, x, this.y_, { baseline: 'top', align: opts.align ?? 'left' })
      this.y_ += lh
    }
  }

  /** Section banner: grey bar with an accent tab, consistent on every page. */
  sectionTitle(title: string): void {
    const h = 9
    this.ensure(h + SPACE.block + 6)
    const d = this.doc
    d.setFillColor(...COLOR.sectionBg)
    d.rect(this.M, this.y_, this.CW, h, 'F')
    d.setFillColor(...COLOR.accent)
    d.rect(this.M, this.y_, 3, h, 'F')

    d.setFont('helvetica', 'bold')
    d.setFontSize(9.5)
    d.setTextColor(...COLOR.ink)
    d.text(title, this.M + 8, this.y_ + h / 2, { baseline: 'middle' })
    this.y_ += h + SPACE.block
  }

  /** Horizontal rule used to separate stacked cards. */
  divider(): void {
    this.ensure(SPACE.paragraph)
    this.doc.setDrawColor(...COLOR.rule)
    this.doc.setLineWidth(0.15)
    this.doc.line(this.M, this.y_, this.right, this.y_)
    this.y_ += SPACE.paragraph
  }

  // ── Composite blocks ────────────────────────────────────────────────

  /**
   * Grid of stat boxes. Widths derive from the content width so the row
   * always spans exactly edge to edge regardless of how many items there are.
   */
  statGrid(items: StatItem[], perRow = 4, boxH = 22): void {
    const gap = 3
    const bw  = (this.CW - gap * (perRow - 1)) / perRow

    for (let i = 0; i < items.length; i += perRow) {
      const row = items.slice(i, i + perRow)
      this.ensure(boxH)
      row.forEach((item, j) => {
        const x = this.M + j * (bw + gap)
        const c = item.color ?? COLOR.ink
        const d = this.doc

        d.setDrawColor(...COLOR.rule)
        d.setLineWidth(0.3)
        d.rect(x, this.y_, bw, boxH)
        d.setFillColor(...c)
        d.rect(x, this.y_, 2.5, boxH, 'F')

        // Value is centred on the box's optical middle, label sits below it —
        // both derived from box height, so they can never collide.
        d.setFont('helvetica', 'bold')
        d.setFontSize(15)
        d.setTextColor(...c)
        d.text(item.value, x + bw / 2, this.y_ + boxH * 0.42, {
          baseline: 'middle', align: 'center',
        })

        d.setFont('helvetica', 'normal')
        d.setFontSize(6.5)
        d.setTextColor(...COLOR.muted)
        d.text(item.label.toUpperCase(), x + bw / 2, this.y_ + boxH - 4.5, {
          baseline: 'top', align: 'center',
        })
      })
      this.y_ += boxH + gap
    }
    this.y_ -= gap
  }

  /** Zebra-striped label/value list (cover metadata, scan info). */
  metaRows(rows: [string, string][], labelW = 46): void {
    const rowH = 9
    rows.forEach(([label, value], i) => {
      this.ensure(rowH)
      const d  = this.doc
      const bg = i % 2 === 0 ? 250 : 255
      d.setFillColor(bg, bg, bg)
      d.rect(this.M, this.y_, this.CW, rowH, 'F')

      const mid = this.y_ + rowH / 2
      d.setFont('helvetica', 'bold')
      d.setFontSize(7.5)
      d.setTextColor(...COLOR.muted)
      d.text(label, this.M + 3, mid, { baseline: 'middle' })

      d.setFont('helvetica', 'normal')
      d.setTextColor(20, 20, 20)
      // Value is clipped to the remaining width so it can never run past the
      // right margin, however long the input is.
      const avail = this.CW - labelW - 6
      const [line] = this.wrap(String(value ?? ''), avail, 7.5)
      d.text(line ?? '', this.M + labelW, mid, { baseline: 'middle' })
      this.y_ += rowH
    })
  }

  /** Pill badge, e.g. the overall-risk chip. */
  badge(text: string, fill: Rgb, opts: { width?: number; textColor?: Rgb } = {}): void {
    const h = 11
    const w = opts.width ?? 70
    this.ensure(h)
    const d = this.doc
    d.setFillColor(...fill)
    d.roundedRect(this.M, this.y_, w, h, 2, 2, 'F')
    d.setFont('helvetica', 'bold')
    d.setFontSize(8.5)
    d.setTextColor(...(opts.textColor ?? COLOR.white))
    d.text(text, this.M + w / 2, this.y_ + h / 2, { baseline: 'middle', align: 'center' })
    this.y_ += h
  }

  /**
   * Coloured header strip used by finding / CVE cards. Returns nothing; the
   * caller continues writing body text below via `paragraph`.
   */
  cardHeader(
    title: string,
    meta: string,
    fill: Rgb,
    accent: Rgb,
    opts: { minBodyH?: number } = {},
  ): void {
    const h = 9
    // Keep the strip with at least the first lines of its body.
    this.ensure(h + (opts.minBodyH ?? this.lineHeight(8) * 2))

    const d = this.doc
    d.setFillColor(...fill)
    d.rect(this.M, this.y_, this.CW, h, 'F')
    d.setFillColor(...accent)
    d.rect(this.M, this.y_, 3, h, 'F')

    const mid = this.y_ + h / 2

    // Reserve room for the right-hand meta so the two can never collide.
    d.setFont('helvetica', 'normal')
    d.setFontSize(7)
    const metaW = meta ? d.getTextWidth(meta) : 0
    const titleAvail = this.CW - 7 - metaW - 6

    d.setFont('helvetica', 'bold')
    d.setFontSize(8.5)
    d.setTextColor(...accent)
    const [titleLine] = this.wrap(title, titleAvail, 8.5, 'bold')
    d.text(titleLine ?? '', this.M + 7, mid, { baseline: 'middle' })

    if (meta) {
      d.setFont('helvetica', 'normal')
      d.setFontSize(7)
      d.setTextColor(...COLOR.muted)
      d.text(meta, this.right - 3, mid, { baseline: 'middle', align: 'right' })
    }
    this.y_ += h + SPACE.tight
  }

  // ── Tables ──────────────────────────────────────────────────────────

  /**
   * Render a table through jspdf-autotable.
   *
   * Column widths are given as shares and normalised to the content width, so
   * a table can never be wider than the page. Explicit top/bottom margins are
   * required: autoTable otherwise falls back to its own default (40/scale ≈
   * 14.1mm), which puts continuation pages above our header band.
   */
  table(columns: ColumnSpec[], rows: (string | number)[][], opts: {
    headFill?: Rgb
    fontSize?: number
    didParseCell?: (data: any) => void
  } = {}): void {
    const totalShare = columns.reduce((s, c) => s + c.width, 0) || 1
    const columnStyles: Record<number, any> = {}
    columns.forEach((c, i) => {
      columnStyles[i] = {
        cellWidth: (c.width / totalShare) * this.CW,
        halign:    c.align ?? 'left',
      }
    })

    this.autoTable(this.doc, {
      startY: this.y_,
      head: [columns.map((c) => c.header)],
      body: rows,
      tableWidth: this.CW,
      // Explicit on all four sides — see note above.
      margin: {
        top:    this.contentTop,
        bottom: PAGE.footer,
        left:   this.M,
        right:  this.M,
      },
      headStyles: {
        fillColor: opts.headFill ?? COLOR.tableHead,
        textColor: COLOR.white,
        fontStyle: 'bold',
        fontSize:  opts.fontSize ?? 8,
      },
      styles: {
        font:        'helvetica',
        fontSize:    opts.fontSize ?? 8,
        cellPadding: 2.6,
        overflow:    'linebreak',
        lineColor:   COLOR.rule,
        lineWidth:   0.1,
        valign:      'middle',
      },
      columnStyles,
      showHead: 'everyPage',
      // Fires for every page the table touches, so continuation pages get the
      // same header band as manually drawn pages.
      didDrawPage: () => this.drawRunningHeader(),
      didParseCell: opts.didParseCell,
    })

    this.y_ = (this.doc as any).lastAutoTable.finalY + SPACE.section
  }

  /** Colour a severity cell in place — shared by every report's tables. */
  static severityCell(data: any, columnIndex: number): void {
    if (data.section !== 'body' || data.column.index !== columnIndex) return
    const s = String(data.cell.raw ?? '').toLowerCase()
    if (!SEV_FILL[s]) return
    data.cell.styles.fillColor = SEV_FILL[s]
    data.cell.styles.textColor = SEV_TEXT[s]
    data.cell.styles.fontStyle = s === 'critical' || s === 'high' ? 'bold' : 'normal'
  }
}

// ── Cover page ────────────────────────────────────────────────────────

export interface CoverOpts {
  kicker:   string
  subtitle: string
  target:   string
  stats:    StatItem[]
  meta:     [string, string][]
}

/**
 * Standard cover: brand block, title, target, stat grid, metadata table.
 * Shared by all report types so covers stay visually identical.
 */
export function drawCover(rd: ReportDoc, o: CoverOpts): void {
  const d = rd.doc

  d.setFillColor(...COLOR.coverBg)
  d.rect(0, 0, rd.W, 75, 'F')
  d.setFillColor(...COLOR.accent)
  d.rect(0, 75, rd.W, 2.5, 'F')

  d.setFont('helvetica', 'bold')
  d.setFontSize(28)
  d.setTextColor(255, 255, 255)
  d.text('VECTRA', rd.M, 26, { baseline: 'top' })

  d.setFont('helvetica', 'normal')
  d.setFontSize(9)
  d.setTextColor(160, 160, 160)
  d.text('SECURITY PLATFORM', rd.M, 36, { baseline: 'top' })

  d.setFont('helvetica', 'bold')
  d.setFontSize(11.5)
  d.setTextColor(210, 210, 210)
  d.text(o.kicker, rd.right, 50, { baseline: 'top', align: 'right' })

  d.setFont('helvetica', 'normal')
  d.setFontSize(8)
  d.setTextColor(...COLOR.accent)
  d.text(o.subtitle, rd.right, 61, { baseline: 'top', align: 'right' })

  d.setFont('helvetica', 'bold')
  d.setFontSize(7.5)
  d.setTextColor(100, 100, 100)
  d.text('ASSESSMENT TARGET', rd.M, 88, { baseline: 'top' })

  // Target is wrapped to the content width rather than truncated at a fixed
  // character count, so long targets stay inside the margins.
  d.setFont('helvetica', 'bold')
  d.setFontSize(16)
  d.setTextColor(...COLOR.ink)
  const [targetLine] = rd.wrap(o.target, rd.CW, 16, 'bold')
  d.text(targetLine ?? '', rd.M, 97, { baseline: 'top' })

  d.setDrawColor(...COLOR.rule)
  d.setLineWidth(0.25)
  d.line(rd.M, 109, rd.right, 109)

  rd.y = 114
  rd.statGrid(o.stats, 4)
  rd.space(SPACE.section)
  rd.metaRows(o.meta, 52)

  d.setFont('helvetica', 'normal')
  d.setFontSize(6.5)
  d.setTextColor(190, 190, 190)
  d.text(
    'This document contains confidential security assessment information. Unauthorized distribution is prohibited.',
    rd.W / 2, rd.H - 12, { baseline: 'top', align: 'center' },
  )
}

// ── Shared formatting helpers ─────────────────────────────────────────

export function truncUrl(url: string | null | undefined, maxLen = 55): string {
  if (!url) return '—'
  if (url.length <= maxLen) return url
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`)
    const short = u.hostname + u.pathname
    return short.length <= maxLen ? short : short.slice(0, maxLen - 1) + '…'
  } catch {
    return url.slice(0, maxLen - 1) + '…'
  }
}

export function severityCounts<T extends { severity?: string }>(items: T[]) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const i of items) {
    const s = (i.severity ?? '').toLowerCase()
    if (s in c) c[s as keyof typeof c]++
  }
  return c
}

export function overallRisk(c: { critical: number; high: number; medium: number; low: number }): {
  label: string
  rgb: Rgb
} {
  if (c.critical > 0) return { label: 'Critical',      rgb: [185, 28, 28] }
  if (c.high     > 0) return { label: 'High',          rgb: [154, 52, 18] }
  if (c.medium   > 0) return { label: 'Medium',        rgb: [133, 77, 14] }
  if (c.low      > 0) return { label: 'Low',           rgb: [29, 78, 216] }
  return                     { label: 'Informational', rgb: [75, 85, 99] }
}
