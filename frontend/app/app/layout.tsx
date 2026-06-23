'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { AppSidebar } from '@/components/app/sidebar'
import { AppBreadcrumb } from '@/components/app/breadcrumb'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { useAuth } from '@/context/auth-context'
import { ScanSyncProvider } from '@/context/scan-sync-context'
import { AssetSyncProvider } from '@/context/asset-sync-context'
import { CveSyncProvider } from '@/context/cve-sync-context'

const ADMIN_ROLES = ['super_admin', 'platform_admin']

export default function AppLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const router = useRouter()
  const { user, loading } = useAuth()

  useEffect(() => {
    if (loading) return

    if (!user) {
      router.push('/auth/login')
      return
    }

    if (ADMIN_ROLES.includes(user.role)) {
      router.push('/admin/dashboard')
    }
  }, [user, loading, router])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="animate-spin rounded-full h-8 w-8 border border-primary border-t-transparent" />
      </div>
    )
  }

  if (!user || ADMIN_ROLES.includes(user.role)) {
    return null
  }

  return (
    <SidebarProvider>
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
    </SidebarProvider>
  )
}
