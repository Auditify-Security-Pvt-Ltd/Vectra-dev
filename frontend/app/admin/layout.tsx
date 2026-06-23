'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { AdminSidebar } from '@/components/admin/admin-sidebar'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { useAuth } from '@/context/auth-context'

const ADMIN_ROLES = ['super_admin', 'platform_admin']

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { user, loading } = useAuth()

  useEffect(() => {
    if (loading) return

    if (!user) {
      router.push('/auth/admin-login')
      return
    }

    if (!ADMIN_ROLES.includes(user.role)) {
      router.push('/app/dashboard')
    }
  }, [user, loading, router])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-8 w-8 border border-primary border-t-transparent" />
          <p className="text-xs text-muted-foreground">Verifying admin access...</p>
        </div>
      </div>
    )
  }

  if (!user || !ADMIN_ROLES.includes(user.role)) {
    return null
  }

  return (
    <SidebarProvider>
      <AdminSidebar />
      <SidebarInset className="overflow-y-auto">
        {children}
      </SidebarInset>
    </SidebarProvider>
  )
}
