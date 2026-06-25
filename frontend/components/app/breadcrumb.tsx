'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ChevronRight } from 'lucide-react'

// ── Route map ─────────────────────────────────────────────────────────

interface Crumb {
  label: string
  module?: string
  moduleHref?: string
}

const ROUTE_MAP: Record<string, Crumb> = {
  '/app/dashboard':                       { label: 'Dashboard' },
  '/app/assets':                          { label: 'Assets',    module: 'Web Security', moduleHref: '/app/assets' },
  '/app/targets':                         { label: 'Targets',   module: 'Web Security', moduleHref: '/app/assets' },
  '/app/scans':                           { label: 'Scans',     module: 'Web Security', moduleHref: '/app/assets' },
  '/app/findings':                        { label: 'Findings',  module: 'Web Security', moduleHref: '/app/assets' },
  '/app/cves':                            { label: 'CVEs',      module: 'Web Security', moduleHref: '/app/assets' },
  '/app/network-security':                { label: 'Scans',     module: 'Network Security', moduleHref: '/app/network-security' },
  '/app/network-security/hosts':          { label: 'Hosts',     module: 'Network Security', moduleHref: '/app/network-security' },
  '/app/network-security/findings':       { label: 'Findings',  module: 'Network Security', moduleHref: '/app/network-security' },
  '/app/network-security/cves':           { label: 'CVEs',      module: 'Network Security', moduleHref: '/app/network-security' },
  '/app/network-security/scans':          { label: 'Scan Detail', module: 'Network Security', moduleHref: '/app/network-security' },
  '/app/cloud-security':                  { label: 'Cloud Security', module: 'Cloud Security', moduleHref: '/app/cloud-security' },
  '/app/reports':                         { label: 'Reports' },
  '/app/ai-analysis':                     { label: 'AI Analysis' },
  '/app/team':                            { label: 'Team' },
  '/app/settings':                        { label: 'Settings' },
  '/app/debug':                           { label: 'Debug' },
}

function getBasePath(pathname: string): string {
  // Check 3-segment paths first (e.g. /app/network-security/hosts)
  const threeSegMatch = pathname.match(/^(\/app\/[^/]+\/[^/]+)/)
  if (threeSegMatch && ROUTE_MAP[threeSegMatch[1]]) return threeSegMatch[1]
  // Then fall back to 2-segment (/app/network-security/scans/[id] → /app/network-security/scans)
  const netScanMatch = pathname.match(/^(\/app\/network-security\/scans)\//)
  if (netScanMatch) return netScanMatch[1]
  const match = pathname.match(/^(\/app\/[^/]+)/)
  return match ? match[1] : '/app/dashboard'
}

// ── Component ─────────────────────────────────────────────────────────

export function AppBreadcrumb() {
  const pathname = usePathname()
  const basePath = getBasePath(pathname)
  const crumb    = ROUTE_MAP[basePath]

  if (!crumb || basePath === '/app/dashboard') return null

  const crumbs: { label: string; href?: string }[] = [
    { label: 'Dashboard', href: '/app/dashboard' },
  ]

  if (crumb.module) {
    crumbs.push({ label: crumb.module })
  }

  crumbs.push({ label: crumb.label })

  return (
    <div className="flex items-center gap-1.5 px-6 py-2.5 border-b border-foreground/8 bg-background/60 backdrop-blur-sm sticky top-0 z-10">
      {crumbs.map((c, i) => {
        const isLast = i === crumbs.length - 1
        return (
          <div key={i} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight className="w-3 h-3 text-muted-foreground/40 shrink-0" />}
            {c.href && !isLast ? (
              <Link href={c.href} className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                {c.label}
              </Link>
            ) : (
              <span className={`text-xs ${isLast ? 'text-foreground font-medium' : 'text-muted-foreground'}`}>
                {c.label}
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
