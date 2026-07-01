'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import {
  Globe, Wifi, Zap, SearchCheck, Code, ArrowLeft, Radio, Loader2,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { startScan, type ScanProfile } from '@/lib/api'
import { startNetworkScan, type NetworkScanProfile } from '@/lib/api-network'
import { createFirestoreScan } from '@/lib/firestore-scans'
import { createNetworkScan } from '@/lib/firestore-network-scans'
import { useAuth } from '@/context/auth-context'

type Step = 'select' | 'web' | 'network'
type ScanType = 'DAST' | 'SAST'

const WEB_PROFILES: {
  value: ScanProfile
  label: string
  description: string
  hint: string
  placeholder: string
  icon: React.ElementType
}[] = [
  { value: 'QUICK_SCAN', label: 'Quick Scan', description: 'Fast Nuclei vulnerability check on a single URL', hint: 'Target URL', placeholder: 'https://example.com', icon: Zap },
  { value: 'FULL_SCAN',  label: 'Full Scan',  description: 'Discovery → Assets → Nuclei → CVE analysis', hint: 'Target Domain', placeholder: 'example.com', icon: SearchCheck },
]

const NET_PROFILES: { id: NetworkScanProfile; label: string; desc: string }[] = [
  { id: 'QUICK_SCAN', label: 'Quick Scan', desc: 'Top 1000 ports · fast host discovery' },
  { id: 'FULL_SCAN',  label: 'Full Scan',  desc: 'All 65535 ports · full service detection' },
]

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function NewAssessmentModal({ open, onOpenChange }: Props) {
  const router    = useRouter()
  const { user }  = useAuth()
  const [step, setStep] = useState<Step>('select')

  // Web form state
  const [scanType,    setScanType]    = useState<ScanType>('DAST')
  const [scanProfile, setScanProfile] = useState<ScanProfile>('FULL_SCAN')
  const [webTarget,   setWebTarget]   = useState('')
  const [webLoading,  setWebLoading]  = useState(false)

  // Network form state
  const [netTarget,  setNetTarget]  = useState('')
  const [netProfile, setNetProfile] = useState<NetworkScanProfile>('QUICK_SCAN')
  const [netLoading, setNetLoading] = useState(false)
  const [netError,   setNetError]   = useState<string | null>(null)

  const isWorking = webLoading || netLoading

  function reset() {
    setStep('select')
    setScanType('DAST')
    setScanProfile('FULL_SCAN')
    setWebTarget('')
    setWebLoading(false)
    setNetTarget('')
    setNetProfile('QUICK_SCAN')
    setNetLoading(false)
    setNetError(null)
  }

  useEffect(() => {
    if (!open) reset()
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Web scan ──────────────────────────────────────────────────────────

  async function handleWebStart() {
    const raw = webTarget.trim()
    if (!raw || !user) return
    let url = raw
    if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url

    setWebLoading(true)
    try {
      const result = await startScan(url, scanProfile, user.uid)
      const { scanId } = result
      const profile = WEB_PROFILES.find((p) => p.value === scanProfile)!

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
        description: `${profile.label} — ${url}`,
        action: { label: 'View', onClick: () => router.push(`/app/scans/${scanId}`) },
      })
      router.push(`/app/scans/${scanId}`)
    } catch (err) {
      setWebLoading(false)
      toast.error('Failed to start scan', { description: err instanceof Error ? err.message : 'Unknown error' })
    }
  }

  // ── Network scan ──────────────────────────────────────────────────────

  async function handleNetStart() {
    if (!user || !netTarget.trim()) return
    setNetLoading(true)
    setNetError(null)
    try {
      const resp  = await startNetworkScan(netTarget.trim(), netProfile, user.uid)
      const scanId = resp.scanId
      const now   = new Date().toISOString()

      await createNetworkScan(user.uid, {
        scanId,
        target: netTarget.trim(),
        scanProfile: netProfile,
        status: 'queued',
        progress: 0,
        currentStep: 'Queued',
        logs: [{ timestamp: now, message: `Network scan queued (${netProfile})` }],
        totalHosts: 0,
        liveHosts: 0,
        totalFindings: 0,
        totalCves: 0,
        createdAt: now,
        engines: {
          host_discovery: { status: 'pending', count: 0 },
          port_scan:      { status: 'pending', count: 0 },
          cve_analysis:   { status: 'pending', count: 0 },
          nuclei:         { status: 'pending', count: 0 },
        },
      })

      onOpenChange(false)
      toast.success('Network scan started')
      router.push(`/app/network-security/scans/${scanId}`)
    } catch (err: unknown) {
      setNetError(err instanceof Error ? err.message : 'Failed to start scan')
    } finally {
      setNetLoading(false)
    }
  }

  const activeWebProfile = WEB_PROFILES.find((p) => p.value === scanProfile)!

  // ── Render ────────────────────────────────────────────────────────────

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!isWorking) onOpenChange(o) }}>
      <DialogContent className="sm:max-w-lg bg-card border-foreground/10">

        {/* ── Step 1: Module Selection ─────────────────────────────────── */}
        {step === 'select' && (
          <>
            <DialogHeader className="pb-1">
              <DialogTitle className="text-xl font-bold">New Security Assessment</DialogTitle>
              <p className="text-sm text-muted-foreground">Select the security module you want to scan.</p>
            </DialogHeader>

            <div className="grid grid-cols-2 gap-4 py-4">
              <button
                onClick={() => setStep('web')}
                className="group p-5 rounded-xl border border-foreground/10 hover:border-primary/40 hover:bg-primary/5 text-left transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
              >
                <div className="w-11 h-11 rounded-xl bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/15 transition-colors">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <p className="text-sm font-semibold text-foreground mb-1">Web Security</p>
                <p className="text-xs text-muted-foreground leading-relaxed">Web Application Security Assessment</p>
              </button>

              <button
                onClick={() => setStep('network')}
                className="group p-5 rounded-xl border border-foreground/10 hover:border-blue-500/40 hover:bg-blue-500/5 text-left transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50"
              >
                <div className="w-11 h-11 rounded-xl bg-blue-500/10 flex items-center justify-center mb-4 group-hover:bg-blue-500/15 transition-colors">
                  <Wifi className="w-5 h-5 text-blue-400" />
                </div>
                <p className="text-sm font-semibold text-foreground mb-1">Network Security</p>
                <p className="text-xs text-muted-foreground leading-relaxed">Network Infrastructure Assessment</p>
              </button>
            </div>

            <div className="flex justify-end">
              <Button variant="outline" className="border-foreground/20" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
            </div>
          </>
        )}

        {/* ── Step 2a: Web Scan Form ───────────────────────────────────── */}
        {step === 'web' && (
          <>
            <DialogHeader className="pb-1">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setStep('select')}
                  className="p-1.5 rounded-lg hover:bg-foreground/5 transition-colors text-muted-foreground hover:text-foreground"
                  disabled={webLoading}
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
                <DialogTitle className="text-xl font-bold">Web Security Scan</DialogTitle>
              </div>
            </DialogHeader>

            <div className="space-y-5 pt-2">
              <div className="space-y-2">
                <p className="text-sm font-medium text-muted-foreground">Scan Type</p>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => setScanType('DAST')}
                    className={`p-4 rounded-lg border text-left transition-all ${
                      scanType === 'DAST' ? 'border-primary bg-primary/10' : 'border-foreground/10 hover:border-foreground/30'
                    }`}
                  >
                    <Globe className={`w-5 h-5 mb-2 ${scanType === 'DAST' ? 'text-primary' : 'text-muted-foreground'}`} />
                    <div className="text-sm font-semibold text-foreground">DAST</div>
                    <div className="text-xs text-green-500 mt-0.5">Available</div>
                  </button>
                  <button className="p-4 rounded-lg border border-foreground/10 text-left opacity-50 cursor-not-allowed">
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
                  <p className="text-xs text-muted-foreground mt-1">Source Code Analysis will be available in a future release.</p>
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    <p className="text-sm font-medium text-muted-foreground">Scan Profile</p>
                    <div className="grid grid-cols-2 gap-3">
                      {WEB_PROFILES.map(({ value, label, description, icon: Icon }) => (
                        <button
                          key={value}
                          onClick={() => setScanProfile(value)}
                          className={`p-3 rounded-lg border text-left transition-all ${
                            scanProfile === value ? 'border-primary bg-primary/10' : 'border-foreground/10 hover:border-foreground/30'
                          }`}
                        >
                          <Icon className={`w-4 h-4 mb-1.5 ${scanProfile === value ? 'text-primary' : 'text-muted-foreground'}`} />
                          <div className="text-xs font-semibold text-foreground">{label}</div>
                          <div className="text-xs text-muted-foreground mt-0.5 leading-tight">{description}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {scanProfile === 'FULL_SCAN' && (
                    <div className="px-3 py-2.5 rounded-lg bg-primary/5 border border-primary/15 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-primary">Automated Full Scan pipeline:</p>
                      <p>① Discover subdomains → ② Probe live assets → ③ Run Nuclei → ④ Detect technologies → ⑤ Correlate CVEs</p>
                    </div>
                  )}

                  <div className="space-y-2">
                    <p className="text-sm font-medium text-muted-foreground">{activeWebProfile.hint}</p>
                    <Input
                      placeholder={activeWebProfile.placeholder}
                      value={webTarget}
                      onChange={(e) => setWebTarget(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && !webLoading && handleWebStart()}
                      className="bg-foreground/5 border-foreground/20"
                      disabled={webLoading}
                      autoFocus
                    />
                  </div>
                </>
              )}

              <div className="flex gap-3">
                <Button variant="outline" className="flex-1 border-foreground/20" onClick={() => setStep('select')} disabled={webLoading}>
                  Back
                </Button>
                <Button
                  className="flex-1 bg-primary hover:bg-primary/90"
                  onClick={handleWebStart}
                  disabled={scanType === 'SAST' || !webTarget.trim() || webLoading}
                >
                  {webLoading ? 'Starting…' : 'Start Scan'}
                </Button>
              </div>
            </div>
          </>
        )}

        {/* ── Step 2b: Network Scan Form ───────────────────────────────── */}
        {step === 'network' && (
          <>
            <DialogHeader className="pb-1">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setStep('select')}
                  className="p-1.5 rounded-lg hover:bg-foreground/5 transition-colors text-muted-foreground hover:text-foreground"
                  disabled={netLoading}
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
                <DialogTitle className="text-xl font-bold">Network Security Scan</DialogTitle>
              </div>
            </DialogHeader>

            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Target</label>
                <Input
                  placeholder="192.168.1.0/24  ·  10.0.0.5  ·  192.168.1.1-20"
                  value={netTarget}
                  onChange={(e) => setNetTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !netLoading && handleNetStart()}
                  className="font-mono text-sm bg-foreground/5 border-foreground/20 h-10"
                  disabled={netLoading}
                  autoFocus
                />
                <p className="text-[11px] text-muted-foreground">
                  Single IP, CIDR (192.168.1.0/24), or dash range (192.168.1.1-20)
                </p>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Scan Profile</label>
                <div className="grid grid-cols-2 gap-2">
                  {NET_PROFILES.map((p) => (
                    <button
                      key={p.id}
                      onClick={() => setNetProfile(p.id)}
                      className={`p-3 rounded-lg border text-left transition-colors ${
                        netProfile === p.id ? 'border-primary bg-primary/5' : 'border-foreground/10 hover:border-foreground/25'
                      }`}
                    >
                      <p className="text-sm font-medium text-foreground">{p.label}</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">{p.desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              {netError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
                  {netError}
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <Button variant="outline" className="flex-1 border-foreground/20" onClick={() => setStep('select')} disabled={netLoading}>
                  Back
                </Button>
                <Button
                  onClick={handleNetStart}
                  disabled={netLoading || !netTarget.trim()}
                  className="flex-1 bg-primary hover:bg-primary/90 gap-2"
                >
                  {netLoading
                    ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Starting…</>
                    : <><Radio className="w-3.5 h-3.5" />Start Scan</>
                  }
                </Button>
              </div>
            </div>
          </>
        )}

      </DialogContent>
    </Dialog>
  )
}
