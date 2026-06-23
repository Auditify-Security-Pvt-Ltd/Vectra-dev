'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Globe, Search } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { startDiscovery } from '@/lib/api-assets'
import { createFirestoreDiscovery } from '@/lib/firestore-assets'
import { useAuth } from '@/context/auth-context'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function StartDiscoveryModal({ open, onOpenChange }: Props) {
  const router = useRouter()
  const { user } = useAuth()
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleStart() {
    const raw = domain.trim()
    if (!raw || !user) return

    // Normalise: strip protocol/path
    const cleanDomain = raw.replace(/^https?:\/\//, '').split('/')[0].trim()

    setLoading(true)
    try {
      const result = await startDiscovery(cleanDomain)

      await createFirestoreDiscovery(user.uid, {
        discoveryId:     result.discoveryId,
        domain:          result.domain,
        status:          'queued',
        currentStep:     'Queued',
        subdomainsFound: 0,
        liveAssets:      0,
        logs: [
          {
            timestamp: new Date().toLocaleTimeString(),
            message:   `Discovery queued for ${result.domain}`,
          },
        ],
        createdAt: new Date().toISOString(),
      })

      onOpenChange(false)
      setDomain('')

      toast.success('Discovery started', {
        description: `Scanning subdomains of ${result.domain}`,
        action: {
          label:   'View',
          onClick: () => router.push(`/app/assets/discovery/${result.discoveryId}`),
        },
      })

      router.push(`/app/assets/discovery/${result.discoveryId}`)
    } catch (err) {
      toast.error('Failed to start discovery', {
        description: err instanceof Error ? err.message : 'Unknown error',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={loading ? undefined : onOpenChange}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold">Asset Discovery</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 pt-2">
          {/* Info banner */}
          <div className="p-4 bg-primary/5 border border-primary/20 rounded-lg space-y-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" />
              <p className="text-sm font-semibold text-foreground">Subdomain Enumeration</p>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Discovers subdomains via Subfinder, then validates each with Httpx. Assets appear in
              real-time as they are found.
            </p>
          </div>

          {/* Domain input */}
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">Target Domain</p>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !loading && handleStart()}
                className="pl-10 bg-foreground/5 border-foreground/20 font-mono"
                disabled={loading}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Enter root domain without protocol (e.g.{' '}
              <span className="font-mono">example.com</span>)
            </p>
          </div>

          {/* Pipeline preview */}
          <div className="flex items-center gap-1.5 flex-wrap text-xs text-muted-foreground">
            {['Subfinder', 'Httpx', 'Firestore', 'Assets Page'].map((s, i, arr) => (
              <span key={s} className="contents">
                <span className="px-2 py-1 rounded bg-foreground/5 border border-foreground/10">{s}</span>
                {i < arr.length - 1 && <span>→</span>}
              </span>
            ))}
          </div>

          <div className="flex gap-3">
            <Button
              variant="outline"
              className="flex-1 border-foreground/20"
              onClick={() => { onOpenChange(false); setDomain('') }}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              className="flex-1 bg-primary hover:bg-primary/90"
              onClick={handleStart}
              disabled={!domain.trim() || loading}
            >
              {loading ? 'Starting…' : 'Start Discovery'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
