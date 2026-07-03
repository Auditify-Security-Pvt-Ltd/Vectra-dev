'use client'

import { useEffect } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Suspense } from 'react'
import { Loader2 } from 'lucide-react'

// Legacy accept URL — redirect to the unified public invite page.
function RedirectContent() {
  const params = useSearchParams()
  const router = useRouter()
  const token  = params.get('token') ?? ''

  useEffect(() => {
    if (token) router.replace(`/invite/${token}`)
    else       router.replace('/app/dashboard')
  }, [token, router])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <Loader2 className="w-8 h-8 animate-spin text-primary" />
    </div>
  )
}

export default function LegacyAcceptPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>}>
      <RedirectContent />
    </Suspense>
  )
}
