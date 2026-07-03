'use client'

import { useRouter } from 'next/navigation'
import { ShieldX } from 'lucide-react'
import { Button } from '@/components/ui/button'

export default function ForbiddenPage() {
  const router = useRouter()
  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] gap-6 p-8">
      <div className="p-4 bg-destructive/10 rounded-full">
        <ShieldX className="w-14 h-14 text-destructive" />
      </div>
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold text-foreground">Access Denied</h1>
        <p className="text-muted-foreground max-w-md">
          You don't have permission to view this page. Contact your team admin if you believe this is a mistake.
        </p>
      </div>
      <div className="flex gap-3">
        <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
        <Button onClick={() => router.push('/app/dashboard')}>Go to Dashboard</Button>
      </div>
    </div>
  )
}
