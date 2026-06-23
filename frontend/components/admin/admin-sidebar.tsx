'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  LayoutDashboard,
  Users,
  Building2,
  CreditCard,
  Network,
  Zap,
  AlertTriangle,
  FileText,
  Cloud,
  Plug,
  ScrollText,
  Activity,
  Settings,
  LogOut,
  Shield,
  ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar'
import { useAuth } from '@/context/auth-context'

const sections = [
  {
    title: 'Overview',
    items: [
      { icon: LayoutDashboard, label: 'Dashboard', href: '/admin/dashboard' },
    ],
  },
  {
    title: 'Platform',
    items: [
      { icon: Users, label: 'Users', href: '/admin/users' },
      { icon: Building2, label: 'Organizations', href: '/admin/organizations' },
      { icon: CreditCard, label: 'Subscriptions', href: '/admin/subscriptions' },
    ],
  },
  {
    title: 'Monitoring',
    items: [
      { icon: Network, label: 'Assets', href: '/admin/assets' },
      { icon: Zap, label: 'Scans', href: '/admin/scans' },
      { icon: AlertTriangle, label: 'Findings', href: '/admin/findings' },
      { icon: FileText, label: 'Reports', href: '/admin/reports' },
    ],
  },

  {
    title: 'Administration',
    items: [
      { icon: ScrollText, label: 'Audit Logs', href: '/admin/audit-logs' },
      { icon: Activity, label: 'System Health', href: '/admin/system-health' },
      { icon: Settings, label: 'Settings', href: '/admin/settings' },
    ],
  },
]

const roleLabels: Record<string, string> = {
  super_admin: 'Super Admin',
  platform_admin: 'Platform Admin',
}

const roleBadgeColors: Record<string, string> = {
  super_admin: 'bg-red-500/10 text-red-500 border-red-500/20',
  platform_admin: 'bg-primary/10 text-primary border-primary/20',
}

export function AdminSidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const { state } = useSidebar()
  const { user, logout } = useAuth()

  const handleLogout = async () => {
    await logout()
    router.push('/auth/login')
  }

  const role = user?.role ?? 'platform_admin'

  return (
    <Sidebar className="border-r border-foreground/10 bg-card">
      {/* Header */}
      <SidebarHeader className="border-b border-foreground/10 px-4 py-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center shrink-0">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold text-foreground leading-none">Vectra</p>
            <p className="text-xs text-muted-foreground mt-0.5">Admin Console</p>
          </div>
        </div>
        {/* Role badge */}
        <div className="mt-3 px-2">
          <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${roleBadgeColors[role] || roleBadgeColors.platform_admin}`}>
            {roleLabels[role] || 'Platform Admin'}
          </span>
        </div>
      </SidebarHeader>

      {/* Content */}
      <SidebarContent className="px-2 py-3">
        <SidebarMenu>
          {sections.map((section) => (
            <div key={section.title} className="mb-5">
              <p className="px-4 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-1.5">
                {section.title}
              </p>
              {section.items.map((item) => {
                const Icon = item.icon
                const isActive =
                  item.href === '/admin/dashboard'
                    ? pathname === '/admin/dashboard' || pathname === '/admin'
                    : pathname.startsWith(item.href)
                return (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive}
                      className={`rounded-lg mb-0.5 ${
                        isActive
                          ? 'bg-primary/10 text-primary'
                          : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5'
                      }`}
                    >
                      <Link href={item.href} className="flex items-center gap-3">
                        <Icon className="w-4 h-4 shrink-0" />
                        <span>{item.label}</span>
                        {isActive && (
                          <ChevronRight className="w-3 h-3 ml-auto opacity-50" />
                        )}
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                )
              })}
            </div>
          ))}
        </SidebarMenu>
      </SidebarContent>

      {/* Footer */}
      <SidebarFooter className="border-t border-foreground/10 p-4 space-y-3">
        {user && (
          <div className="px-3 py-3 bg-foreground/5 rounded-lg">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-primary/40 to-accent/40 flex items-center justify-center shrink-0">
                <span className="text-xs font-bold text-primary">{user.name?.[0] || 'A'}</span>
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-foreground truncate">{user.name}</p>
                <p className="text-[10px] text-muted-foreground truncate">{user.email}</p>
              </div>
            </div>
          </div>
        )}
        <Button
          onClick={handleLogout}
          variant="outline"
          className="w-full justify-start h-9 rounded-lg border-foreground/10 hover:bg-destructive/10 hover:text-destructive text-sm"
        >
          <LogOut className="w-4 h-4 mr-2" />
          Sign Out
        </Button>
        <Link href="/app/dashboard" className="w-full">
          <Button variant="ghost" className="w-full justify-start h-8 rounded-lg text-xs text-muted-foreground hover:text-foreground">
            ← Customer Portal
          </Button>
        </Link>
      </SidebarFooter>
    </Sidebar>
  )
}
