'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Globe, Code, Zap, SearchCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { startScan, type ScanProfile } from '@/lib/api'
import { createFirestoreScan } from '@/lib/firestore-scans'
import { useAuth } from '@/context/auth-context'

type ScanType = 'DAST' | 'SAST'

const PROFILES: {
  value: ScanProfile
  label: string
  description: string
  hint: string
  placeholder: string
  icon: React.ElementType
}[] = [
  {
    value: 'QUICK_SCAN',
    label: 'Quick Scan',
    description: 'Fast Nuclei vulnerability check on a single URL',
    hint: 'Target URL',
    placeholder: 'https://example.com',
    icon: Zap,
  },
  {
    value: 'FULL_SCAN',
    label: 'Full Scan',
    description: 'Discovery → Assets → Nuclei → CVE analysis — fully automated',
    hint: 'Target Domain',
    placeholder: 'example.com',
    icon: SearchCheck,
  },
]

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  defaultTarget?: string
}

export function NewScanModal({ open, onOpenChange, defaultTarget }: Props) {
  const router = useRouter()
  const { user } = useAuth()
  const [scanType, setScanType]     = useState<ScanType>('DAST')
  const [scanProfile, setScanProfile] = useState<ScanProfile>('FULL_SCAN')
  const [target, setTarget]         = useState(defaultTarget ?? '')
  const [loading, setLoading]       = useState(false)

  const activeProfile = PROFILES.find((p) => p.value === scanProfile)!

  useEffect(() => {
    if (open) setTarget(defaultTarget ?? '')
    else {
      setLoading(false)
      setScanType('DAST')
      setScanProfile('FULL_SCAN')
    }
  }, [open, defaultTarget])

  async function handleStart() {
    const raw = target.trim()
    if (!raw || !user) return

    // Always send a valid URL to the backend (which expects HttpUrl)
    let url = raw
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url
    }

    setLoading(true)
    try {
      const result = await startScan(url, scanProfile)
      const { scanId } = result

      await createFirestoreScan(user.uid, {
        scanId,
        target: url,
        scanType,
        scanProfile,
        status: 'queued',
        progress: 0,
        currentStep: 'Queued',
        logs: [{ timestamp: new Date().toLocaleTimeString(), message: 'Scan Created' }],
        findings: [],
        totalFindings: 0,
        createdAt: new Date().toISOString(),
      })

      onOpenChange(false)

      toast.success('Scan started', {
        description: `${activeProfile.label} — ${url}`,
        action: {
          label: 'View',
          onClick: () => router.push(`/app/scans/${scanId}`),
        },
      })

      router.push(`/app/scans/${scanId}`)
    } catch (err) {
      setLoading(false)
      toast.error('Failed to start scan', {
        description: err instanceof Error ? err.message : 'Unknown error',
      })
    }
  }

  return (
    <Dialog open={open} onOpenChange={loading ? undefined : onOpenChange}>
      <DialogContent className="sm:max-w-md bg-card border-foreground/10">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold">New Security Scan</DialogTitle>
        </DialogHeader>

        <div className="space-y-5 pt-2">
          {/* Scan Type */}
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">Scan Type</p>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setScanType('DAST')}
                className={`p-4 rounded-lg border text-left transition-all ${
                  scanType === 'DAST'
                    ? 'border-primary bg-primary/10'
                    : 'border-foreground/10 hover:border-foreground/30'
                }`}
              >
                <Globe className={`w-5 h-5 mb-2 ${scanType === 'DAST' ? 'text-primary' : 'text-muted-foreground'}`} />
                <div className="text-sm font-semibold text-foreground">DAST</div>
                <div className="text-xs text-green-500 mt-0.5">Available</div>
              </button>
              <button
                onClick={() => setScanType('SAST')}
                className="p-4 rounded-lg border border-foreground/10 text-left opacity-60"
              >
                <Code className="w-5 h-5 mb-2 text-muted-foreground" />
                <div className="text-sm font-semibold text-foreground">SAST</div>
                <div className="text-xs text-muted-foreground mt-0.5">Coming Soon</div>
              </button>
            </div>
          </div>

          {scanType === 'SAST' ? (
            <div className="p-5 bg-foreground/5 rounded-lg border border-foreground/10 text-center">
              <Code className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm font-semibold text-foreground">Coming Soon</p>
              <p className="text-xs text-muted-foreground mt-1">
                Source Code Analysis will be available in a future release.
              </p>
            </div>
          ) : (
            <>
              {/* Scan Profile */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-muted-foreground">Scan Profile</p>
                <div className="grid grid-cols-2 gap-3">
                  {PROFILES.map(({ value, label, description, icon: Icon }) => (
                    <button
                      key={value}
                      onClick={() => setScanProfile(value)}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        scanProfile === value
                          ? 'border-primary bg-primary/10'
                          : 'border-foreground/10 hover:border-foreground/30'
                      }`}
                    >
                      <Icon className={`w-4 h-4 mb-1.5 ${scanProfile === value ? 'text-primary' : 'text-muted-foreground'}`} />
                      <div className="text-xs font-semibold text-foreground">{label}</div>
                      <div className="text-xs text-muted-foreground mt-0.5 leading-tight">{description}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Full Scan description */}
              {scanProfile === 'FULL_SCAN' && (
                <div className="px-3 py-2.5 rounded-lg bg-primary/5 border border-primary/15 text-xs text-muted-foreground space-y-1">
                  <p className="font-medium text-primary">Automated Full Scan pipeline:</p>
                  <p>① Discover subdomains → ② Probe live assets → ③ Run Nuclei → ④ Detect technologies → ⑤ Correlate CVEs</p>
                </div>
              )}

              {/* Target input */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-muted-foreground">{activeProfile.hint}</p>
                <Input
                  placeholder={activeProfile.placeholder}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !loading && handleStart()}
                  className="bg-foreground/5 border-foreground/20"
                  disabled={loading}
                />
              </div>
            </>
          )}

          <div className="flex gap-3">
            <Button
              variant="outline" className="flex-1 border-foreground/20"
              onClick={() => onOpenChange(false)} disabled={loading}
            >
              Cancel
            </Button>
            <Button
              className="flex-1 bg-primary hover:bg-primary/90"
              onClick={handleStart}
              disabled={scanType === 'SAST' || !target.trim() || loading}
            >
              {loading ? 'Starting…' : 'Start Scan'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
