'use client'

import { Suspense, useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { CheckCircle, XCircle, Loader2 } from 'lucide-react'

function CallbackContent() {
  const params   = useSearchParams()
  const provider = params.get('provider') ?? ''
  const success  = params.get('success') === 'true'
  const error    = params.get('error') ?? ''

  const [sent, setSent] = useState(false)

  useEffect(() => {
    if (sent) return
    setSent(true)

    if (typeof window !== 'undefined' && window.opener) {
      window.opener.postMessage(
        { type: 'sast-oauth-callback', provider, success, error },
        window.location.origin,
      )
      setTimeout(() => window.close(), 800)
    }
  }, [sent, provider, success, error])

  const label = provider === 'github' ? 'GitHub' : 'GitLab'

  return (
    <div className="flex flex-col items-center gap-4 text-center max-w-xs px-6">
      {success ? (
        <>
          <CheckCircle className="w-12 h-12 text-emerald-500" />
          <h2 className="text-lg font-semibold text-foreground">{label} Connected</h2>
          <p className="text-sm text-muted-foreground">
            Your {label} account was connected successfully. This window will close automatically.
          </p>
        </>
      ) : (
        <>
          <XCircle className="w-12 h-12 text-destructive" />
          <h2 className="text-lg font-semibold text-foreground">Connection Failed</h2>
          <p className="text-sm text-muted-foreground">
            {error
              ? decodeURIComponent(error)
              : `Could not connect to ${label}. Please try again.`}
          </p>
        </>
      )}
      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-2">
        <Loader2 className="w-3 h-3 animate-spin" />
        Closing window…
      </div>
    </div>
  )
}

export default function OAuthCallbackPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Suspense
        fallback={
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading…</span>
          </div>
        }
      >
        <CallbackContent />
      </Suspense>
    </div>
  )
}
