'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

// CVE Intelligence is now part of the unified Findings page.
// This redirect preserves any bookmarked /app/cves links.
export default function CvesRedirectPage() {
  const router = useRouter()
  useEffect(() => {
    router.replace('/app/findings?type=cves')
  }, [router])
  return (
    <div className="p-8 flex items-center justify-center min-h-64">
      <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
    </div>
  )
}
