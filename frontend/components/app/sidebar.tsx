'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  BarChart3, Network, Target, Zap, AlertTriangle, ShieldAlert,
  Cloud, FileText, Sparkles, Users, LogOut, Settings,
  ChevronDown, ChevronRight,
  Globe, Wifi, Server, Shield, Lock,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarHeader,
  SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar,
} from '@/components/ui/sidebar'
import { useAuth } from '@/context/auth-context'

// ── Type definitions ──────────────────────────────────────────────────

interface NavItem {
  icon: React.ComponentType<{ className?: string }>
  label: string
  href: string
}

interface NavModule {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  href: string
  items: NavItem[]
  comingSoon?: boolean
}

interface StandaloneItem {
  icon: React.ComponentType<{ className?: string }>
  label: string
  href: string
}

// ── Navigation structure ──────────────────────────────────────────────

const MODULES: NavModule[] = [
  {
    id: 'web-security',
    label: 'Web Security',
    icon: Globe,
    href: '/app/dashboard',
    items: [
      { icon: Network, label: 'Assets',  href: '/app/assets'  },
      { icon: Target,  label: 'Targets', href: '/app/targets' },
      { icon: Zap,     label: 'Scans',   href: '/app/scans'   },
    ],
  },
  {
    id: 'network-security',
    label: 'Network Security',
    icon: Wifi,
    href: '/app/network-security',
    items: [
      { icon: Zap,    label: 'Scans', href: '/app/network-security'       },
      { icon: Server, label: 'Hosts', href: '/app/network-security/hosts' },
    ],
  },
  {
    id: 'cloud-security',
    label: 'Cloud Security',
    icon: Cloud,
    href: '/app/cloud-security',
    comingSoon: true,
    items: [
      { icon: Shield,        label: 'Accounts',          href: '/app/cloud-security' },
      { icon: Network,       label: 'Cloud Assets',      href: '/app/cloud-security' },
      { icon: Lock,          label: 'IAM Analysis',      href: '/app/cloud-security' },
      { icon: FileText,      label: 'Storage Security',  href: '/app/cloud-security' },
      { icon: Wifi,          label: 'Network Security',  href: '/app/cloud-security' },
      { icon: AlertTriangle, label: 'Misconfigurations', href: '/app/cloud-security' },
      { icon: AlertTriangle, label: 'Cloud Findings',    href: '/app/cloud-security' },
    ],
  },
]

const TOP_ITEMS: StandaloneItem[] = [
  { icon: BarChart3, label: 'Dashboard', href: '/app/dashboard' },
]

const BOTTOM_ITEMS: StandaloneItem[] = [
  { icon: ShieldAlert, label: 'Vulnerability Management', href: '/app/findings'    },
  { icon: FileText,    label: 'Reports',                  href: '/app/reports'     },
  { icon: Sparkles,    label: 'AI Analysis',              href: '/app/ai-analysis' },
  { icon: Users,       label: 'Team',                     href: '/app/team'        },
]

// ── Route → module detection ──────────────────────────────────────────

function getModuleForPath(pathname: string): string | null {
  if (
    pathname.startsWith('/app/assets') ||
    pathname.startsWith('/app/targets') ||
    pathname.startsWith('/app/scans')
  ) return 'web-security'
  if (pathname.startsWith('/app/network-security')) return 'network-security'
  if (pathname.startsWith('/app/cloud-security'))   return 'cloud-security'
  // /app/findings is now standalone — no module expansion
  return null
}

// ── Sub-components ────────────────────────────────────────────────────

function StandaloneNavItem({ item, pathname }: { item: StandaloneItem; pathname: string }) {
  const Icon     = item.icon
  const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        isActive={isActive}
        className={`rounded-lg mb-0.5 h-9 ${
          isActive
            ? 'bg-primary/10 text-primary'
            : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5'
        }`}
      >
        <Link href={item.href}>
          <Icon className="w-4 h-4 shrink-0" />
          <span className="text-sm">{item.label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function ModuleSection({
  module, pathname, isOpen, onToggle,
}: {
  module: NavModule
  pathname: string
  isOpen: boolean
  onToggle: () => void
}) {
  const ModuleIcon = module.icon
  const Chevron    = isOpen ? ChevronDown : ChevronRight

  // Is any item in this module active?
  const isModuleActive = module.items.some(
    (item) => pathname === item.href || (item.href !== module.href && pathname.startsWith(item.href + '/')),
  ) || pathname.startsWith(module.href + '/')

  return (
    <div className="mb-1">
      {/* Module header */}
      <button
        onClick={onToggle}
        className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
          isModuleActive && !module.comingSoon
            ? 'text-foreground hover:bg-foreground/5'
            : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5'
        }`}
      >
        <ModuleIcon className={`w-4 h-4 shrink-0 ${isModuleActive && !module.comingSoon ? 'text-primary' : ''}`} />
        <span className="flex-1 text-left">{module.label}</span>
        {module.comingSoon && (
          <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-foreground/8 text-muted-foreground/70 border border-foreground/10 leading-none">
            SOON
          </span>
        )}
        <Chevron className="w-3.5 h-3.5 shrink-0 text-muted-foreground/60" />
      </button>

      {/* Module items — shown when expanded */}
      {isOpen && (
        <div className="ml-3 pl-3 border-l border-foreground/10 mt-0.5 mb-1">
          {module.items.map((item) => {
            const Icon     = item.icon
            const isActive = !module.comingSoon && (pathname === item.href || pathname.startsWith(item.href + '/'))

            if (module.comingSoon) {
              return (
                <Link key={item.label} href={module.href}>
                  <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-md text-xs text-muted-foreground/50 hover:text-muted-foreground hover:bg-foreground/5 transition-colors cursor-pointer group">
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    <span>{item.label}</span>
                  </div>
                </Link>
              )
            }

            return (
              <SidebarMenuItem key={item.href}>
                <SidebarMenuButton
                  asChild
                  isActive={isActive}
                  className={`rounded-md h-8 mb-0.5 text-xs ${
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5'
                  }`}
                >
                  <Link href={item.href}>
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    <span>{item.label}</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Main sidebar ──────────────────────────────────────────────────────

export function AppSidebar() {
  const pathname = usePathname()
  const router   = useRouter()
  const { user, logout } = useAuth()

  // Open the module containing the current route by default
  const [openModule, setOpenModule] = useState<string | null>(
    () => getModuleForPath(pathname) ?? 'web-security',
  )

  // Auto-expand when navigating into a module from outside
  useEffect(() => {
    const mod = getModuleForPath(pathname)
    if (mod && mod !== openModule) setOpenModule(mod)
  }, [pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  function handleModuleToggle(id: string) {
    setOpenModule((prev) => (prev === id ? null : id))
  }

  const handleLogout = async () => {
    await logout()
    router.push('/auth/login')
  }

  return (
    <Sidebar className="border-r border-foreground/10 bg-card">

      {/* Logo */}
      <SidebarHeader className="border-b border-foreground/10 px-4 py-5">
        <Link href="/app/dashboard" className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center shrink-0">
            <Sparkles className="w-4.5 h-4.5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-base font-bold text-foreground leading-none">Vectra</h1>
            <p className="text-[11px] text-muted-foreground mt-0.5">Security Platform</p>
          </div>
        </Link>
      </SidebarHeader>

      {/* Navigation */}
      <SidebarContent className="px-2 py-3 overflow-y-auto">
        <SidebarMenu>

          {/* Standalone top items (Dashboard) */}
          {TOP_ITEMS.map((item) => (
            <StandaloneNavItem key={item.href} item={item} pathname={pathname} />
          ))}

          {/* Divider */}
          <div className="my-2 border-t border-foreground/8" />

          {/* Security modules */}
          <div className="mb-1 px-3">
            <p className="text-[10px] font-semibold text-muted-foreground/60 uppercase tracking-widest">
              Security Modules
            </p>
          </div>

          {MODULES.map((module) => (
            <ModuleSection
              key={module.id}
              module={module}
              pathname={pathname}
              isOpen={openModule === module.id}
              onToggle={() => handleModuleToggle(module.id)}
            />
          ))}

          {/* Divider */}
          <div className="my-2 border-t border-foreground/8" />

          {/* Standalone bottom items */}
          {BOTTOM_ITEMS.map((item) => (
            <StandaloneNavItem key={item.href} item={item} pathname={pathname} />
          ))}

        </SidebarMenu>
      </SidebarContent>

      {/* Footer */}
      <SidebarFooter className="border-t border-foreground/10 p-3 space-y-2">
        <Link href="/app/settings" className="w-full">
          <Button
            variant="ghost"
            className="w-full justify-start h-9 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-sm"
          >
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </Button>
        </Link>

        {user && (
          <div className="px-3 py-2.5 bg-foreground/5 rounded-lg">
            <p className="text-xs font-medium text-foreground truncate">{user.name}</p>
            <p className="text-[11px] text-muted-foreground truncate">{user.email}</p>
          </div>
        )}

        <Button
          onClick={handleLogout}
          variant="ghost"
          className="w-full justify-start h-9 rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10 text-sm"
        >
          <LogOut className="w-4 h-4 mr-2" />
          Logout
        </Button>
      </SidebarFooter>

    </Sidebar>
  )
}
