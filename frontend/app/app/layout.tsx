'use client'

import { useEffect } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { AppSidebar } from '@/components/app/sidebar'
import { AppBreadcrumb } from '@/components/app/breadcrumb'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { useAuth } from '@/context/auth-context'
import { ScanSyncProvider } from '@/context/scan-sync-context'
import { AssetSyncProvider } from '@/context/asset-sync-context'
import { CveSyncProvider } from '@/context/cve-sync-context'
import { TeamProvider } from '@/context/team-context'
import { hasPermission } from '@/lib/rbac'

const ADMIN_ROLES = ['super_admin', 'platform_admin']

// Routes that require specific permissions. If not listed, default is: authenticated = allowed.
const ROUTE_PERMISSIONS: Array<{ prefix: string; perm: keyof ReturnType<typeof hasPermission extends (...args: any) => infer R ? never : any> }> = []

// Routes restricted to admin orgRole only
const ADMIN_ONLY_ROUTES = ['/app/team', '/app/settings']
// Routes restricted to editor+ (not viewer)
const EDITOR_ROUTES     = ['/app/scans', '/app/targets', '/app/assets', '/app/network-security', '/app/sast', '/app/ai-analysis']

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter()
  const pathname = usePathname()
  const { user, loading } = useAuth()

  useEffect(() => {
    if (loading) return

    if (!user) {
      router.push('/auth/login')
      return
    }

    // Platform admins use a different UI
    if (ADMIN_ROLES.includes(user.role)) {
      router.push('/admin/dashboard')
      return
    }

    const orgRole = user.orgRole

    // Viewer cannot access admin-only routes
    if (orgRole !== 'admin' && ADMIN_ONLY_ROUTES.some((r) => pathname.startsWith(r))) {
      router.push('/app/403')
      return
    }

    // Viewer cannot access editor routes
    if (orgRole === 'viewer' && EDITOR_ROUTES.some((r) => pathname.startsWith(r))) {
      router.push('/app/dashboard')
    }
  }, [user, loading, pathname, router])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="animate-spin rounded-full h-8 w-8 border border-primary border-t-transparent" />
      </div>
    )
  }

  if (!user || ADMIN_ROLES.includes(user.role)) return null

  return (
    <SidebarProvider>
      <TeamProvider>
        <ScanSyncProvider>
          <AssetSyncProvider>
            <CveSyncProvider>
              <AppSidebar />
              <SidebarInset className="overflow-y-auto flex flex-col">
                <AppBreadcrumb />
                {children}
              </SidebarInset>
            </CveSyncProvider>
          </AssetSyncProvider>
        </ScanSyncProvider>
      </TeamProvider>
    </SidebarProvider>
  )
}
