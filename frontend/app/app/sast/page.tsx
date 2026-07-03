'use client'

import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Code2, Upload, FolderOpen, Github, Gitlab, AlertTriangle,
  ShieldAlert, Key, Package, CheckCircle2, XCircle, Loader2,
  FileCode2, Zap, Clock, X, Search,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { toast } from 'sonner'
import { useAuth } from '@/context/auth-context'
import {
  listenToSastScans,
  createSastScan,
  SAST_ACTIVE_STATUSES,
  type FirestoreSastScan,
} from '@/lib/firestore-sast-scans'
import { uploadSastZip, uploadSastDirectory } from '@/lib/api-sast'
import {
  getOAuthUrl,
  getOAuthStatus,
  getRepos,
  getBranches,
  disconnectOAuth,
  startRepoScan,
  type OAuthStatus,
  type Repo,
} from '@/lib/api-sast-oauth'

// ── Helpers ───────────────────────────────────────────────────────────

function makeBlankScan(
  scanId:      string,
  projectName: string,
  uploadMethod: FirestoreSastScan['uploadMethod'],
  userId:      string,
  totalFiles   = 0,
): FirestoreSastScan {
  return {
    scanId, projectName, uploadMethod, language: 'Unknown', userId,
    status: 'queued', progress: 0, currentStep: 'Queued',
    totalFiles, scannedFiles: 0,
    totalFindings: 0, criticalFindings: 0, highFindings: 0,
    mediumFindings: 0, lowFindings: 0, secretFindings: 0, dependencyVulns: 0,
    stages: {
      language_detection: 'pending', secret_detection: 'pending',
      dependency_analysis: 'pending', owasp_analysis: 'pending',
      cwe_mapping: 'pending', cve_correlation: 'pending',
    },
    duration: null, error: null,
    createdAt: new Date().toISOString(), completedAt: null,
  }
}

// ── Stat card ─────────────────────────────────────────────────────────

function StatCard({
  label, value, sub, accent,
}: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="bg-card border border-foreground/10 rounded-xl p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${accent ?? 'text-foreground'}`}>{value}</p>
      {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
    </div>
  )
}

// ── Status badge ──────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: 'bg-green-500/15 text-green-400 border-green-500/30',
    running:   'bg-blue-500/15 text-blue-400 border-blue-500/30',
    queued:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    failed:    'bg-red-500/15 text-red-400 border-red-500/30',
    cancelled: 'bg-foreground/10 text-muted-foreground border-foreground/20',
  }
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border capitalize ${map[status] ?? ''}`}>
      {status}
    </span>
  )
}

// ── New scan modal ────────────────────────────────────────────────────

type ScanMethod = 'zip' | 'directory' | 'github' | 'gitlab'

const METHODS: { id: ScanMethod; label: string; desc: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'zip',       label: 'Upload ZIP',           desc: 'Upload a zipped project archive', icon: Upload    },
  { id: 'directory', label: 'Upload Source Folder', desc: 'Upload a local source directory', icon: FolderOpen },
  { id: 'github',    label: 'GitHub Repository',    desc: 'Scan from a GitHub repo',         icon: Github    },
  { id: 'gitlab',    label: 'GitLab Repository',    desc: 'Scan from a GitLab repo',         icon: Gitlab    },
]

function NewScanModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user } = useAuth()
  const router   = useRouter()

  // ── Base state ──────────────────────────────────────────────────────
  const [method, setMethod]           = useState<ScanMethod>('zip')
  const [projectName, setProjectName] = useState('')
  const [uploading, setUploading]     = useState(false)
  const zipRef = useRef<HTMLInputElement>(null)
  const dirRef = useRef<HTMLInputElement>(null)

  // ── OAuth state ─────────────────────────────────────────────────────
  const [oauthStatus, setOauthStatus]         = useState<OAuthStatus | null>(null)
  const [oauthLoading, setOauthLoading]       = useState(false)
  const [repos, setRepos]                     = useState<Repo[]>([])
  const [repoSearch, setRepoSearch]           = useState('')
  const [reposLoading, setReposLoading]       = useState(false)
  const [selectedRepo, setSelectedRepo]       = useState<Repo | null>(null)
  const [branches, setBranches]               = useState<string[]>([])
  const [defaultBranch, setDefaultBranch]     = useState('main')
  const [selectedBranch, setSelectedBranch]   = useState('')
  const [branchesLoading, setBranchesLoading] = useState(false)

  const provider     = method as 'github' | 'gitlab'
  const providerLabel = method === 'github' ? 'GitHub' : 'GitLab'
  const isRepoMethod  = method === 'github' || method === 'gitlab'

  // ── Check OAuth status when provider changes ────────────────────────
  async function checkStatus(p: 'github' | 'gitlab') {
    if (!user) return
    setOauthLoading(true)
    setOauthStatus(null)
    setRepos([])
    setSelectedRepo(null)
    setBranches([])
    setRepoSearch('')
    try {
      const st = await getOAuthStatus(p, user.uid)
      setOauthStatus(st)
      if (st.connected) loadRepos(p, '')
    } finally {
      setOauthLoading(false)
    }
  }

  useEffect(() => {
    if (!open || !user) return
    if (isRepoMethod) checkStatus(provider)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, open])

  // ── Repo loading ────────────────────────────────────────────────────
  async function loadRepos(p: 'github' | 'gitlab', search: string) {
    if (!user) return
    setReposLoading(true)
    try {
      const { repos: r } = await getRepos(p, user.uid, search)
      setRepos(r)
    } catch {
      toast.error('Failed to load repositories')
    } finally {
      setReposLoading(false)
    }
  }

  // Debounced search
  useEffect(() => {
    if (!isRepoMethod || !oauthStatus?.connected) return
    const t = setTimeout(() => loadRepos(provider, repoSearch), 400)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [repoSearch])

  // ── Repo selection ──────────────────────────────────────────────────
  async function handleSelectRepo(repo: Repo) {
    setSelectedRepo(repo)
    setBranches([])
    setSelectedBranch('')
    setBranchesLoading(true)
    // Auto-fill project name from repo name if not already set
    if (!projectName || projectName === selectedRepo?.name) setProjectName(repo.name)
    try {
      const res = await getBranches(provider, user!.uid, repo.owner, repo.name)
      setBranches(res.branches)
      setDefaultBranch(res.default)
      setSelectedBranch(res.default)
    } catch {
      toast.error('Failed to load branches')
    } finally {
      setBranchesLoading(false)
    }
  }

  // ── OAuth connect via popup ─────────────────────────────────────────
  function handleConnect() {
    if (!user) return
    getOAuthUrl(provider, user.uid).then((res) => {
      if (!res.configured || !res.url) {
        toast.error(res.message ?? 'OAuth not configured. Check backend/.env')
        return
      }
      const popup = window.open(
        res.url,
        'sast_oauth',
        'width=600,height=700,popup=yes',
      )
      function onMessage(e: MessageEvent) {
        if (e.data?.type !== 'sast-oauth-callback') return
        if (e.data.provider !== provider) return
        window.removeEventListener('message', onMessage)
        clearInterval(poll)
        if (e.data.success) {
          checkStatus(provider)
        } else {
          toast.error(`Could not connect to ${providerLabel}`)
        }
      }
      window.addEventListener('message', onMessage)
      // Cleanup if popup closes without sending message
      const poll = setInterval(() => {
        if (popup?.closed) {
          clearInterval(poll)
          window.removeEventListener('message', onMessage)
        }
      }, 500)
    })
  }

  async function handleDisconnect() {
    if (!user) return
    await disconnectOAuth(provider, user.uid)
    setOauthStatus({ configured: true, connected: false })
    setRepos([])
    setSelectedRepo(null)
    setBranches([])
  }

  // ── Reset / close ───────────────────────────────────────────────────
  function resetModal() {
    setMethod('zip')
    setProjectName('')
    setUploading(false)
    setOauthStatus(null)
    setRepos([])
    setSelectedRepo(null)
    setBranches([])
    setRepoSearch('')
  }

  function handleClose() {
    resetModal()
    onClose()
  }

  // ── Scan submission ─────────────────────────────────────────────────
  async function handleScan() {
    if (!user) return
    if (!projectName.trim()) { toast.error('Enter a project name'); return }

    setUploading(true)
    try {
      if (method === 'zip') {
        const f = zipRef.current?.files?.[0]
        if (!f) { toast.error('Select a ZIP file'); return }
        const res  = await uploadSastZip(f, projectName.trim(), user.uid)
        await createSastScan(user.organizationId, makeBlankScan(res.scanId, projectName.trim(), 'zip', user.uid))
        handleClose()
        router.push(`/app/sast/scans/${res.scanId}`)

      } else if (method === 'directory') {
        const files = dirRef.current?.files
        if (!files || files.length === 0) { toast.error('Select a source folder'); return }
        const res  = await uploadSastDirectory(files, projectName.trim(), user.uid)
        await createSastScan(user.organizationId, makeBlankScan(res.scanId, projectName.trim(), 'directory', user.uid, files.length))
        handleClose()
        router.push(`/app/sast/scans/${res.scanId}`)

      } else if (method === 'github' || method === 'gitlab') {
        if (!selectedRepo)   { toast.error('Select a repository'); return }
        if (!selectedBranch) { toast.error('Select a branch'); return }
        const res = await startRepoScan({
          userId:      user.uid,
          provider:    method,
          owner:       selectedRepo.owner,
          repo:        selectedRepo.name,
          branch:      selectedBranch,
          projectName: projectName.trim(),
        })
        const scan: FirestoreSastScan = {
          ...makeBlankScan(res.scanId, projectName.trim(), method, user.uid),
          repoProvider:  method,
          repoOwner:     selectedRepo.owner,
          repoName:      selectedRepo.name,
          repoBranch:    selectedBranch,
        }
        await createSastScan(user.organizationId, scan)
        handleClose()
        router.push(`/app/sast/scans/${res.scanId}`)
      }
    } catch (e: any) {
      toast.error(e.message ?? 'Failed to start scan')
    } finally {
      setUploading(false)
    }
  }

  if (!open) return null

  const canScan =
    !uploading && (
      method === 'zip' ||
      method === 'directory' ||
      (isRepoMethod && oauthStatus?.connected && !!selectedRepo && !!selectedBranch)
    )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div
        className={`bg-card border border-foreground/15 rounded-2xl w-full shadow-2xl flex flex-col max-h-[90vh] transition-all duration-200 ${
          isRepoMethod && oauthStatus?.connected ? 'max-w-2xl' : 'max-w-lg'
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-foreground/10 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-violet-500/15 border border-violet-500/25 flex items-center justify-center">
              <Code2 className="w-4.5 h-4.5 text-violet-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-foreground">New SAST Scan</h2>
              <p className="text-xs text-muted-foreground">Static application security testing</p>
            </div>
          </div>
          <button onClick={handleClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-5 overflow-y-auto">

          {/* Method cards */}
          <div>
            <Label className="text-xs text-muted-foreground mb-2 block">Scan Method</Label>
            <div className="grid grid-cols-2 gap-2">
              {METHODS.map((m) => {
                const Icon = m.icon
                const sel  = method === m.id
                return (
                  <button
                    key={m.id}
                    onClick={() => {
                      setMethod(m.id)
                      setSelectedRepo(null)
                      setBranches([])
                    }}
                    className={`relative text-left p-3 rounded-xl border transition-all ${
                      sel
                        ? 'border-violet-500/50 bg-violet-500/10'
                        : 'border-foreground/12 hover:border-foreground/25 hover:bg-foreground/5'
                    }`}
                  >
                    <Icon className={`w-4 h-4 mb-1.5 ${sel ? 'text-violet-400' : 'text-muted-foreground'}`} />
                    <p className={`text-xs font-medium ${sel ? 'text-violet-400' : 'text-foreground'}`}>{m.label}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{m.desc}</p>
                  </button>
                )
              })}
            </div>
          </div>

          {/* ── GitHub / GitLab flow ──────────────────────────────────── */}
          {isRepoMethod && (
            <div className="space-y-4">

              {/* Checking status */}
              {oauthLoading && (
                <div className="flex items-center justify-center py-8 gap-2 text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Checking {providerLabel} connection…</span>
                </div>
              )}

              {/* Not configured */}
              {!oauthLoading && oauthStatus && !oauthStatus.configured && (
                <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 space-y-2.5">
                  <p className="text-sm font-medium text-yellow-400">OAuth Not Configured</p>
                  <p className="text-xs text-muted-foreground">
                    Add the following keys to{' '}
                    <code className="text-[11px] bg-foreground/8 px-1 rounded">backend/.env</code>:
                  </p>
                  <pre className="text-[11px] bg-foreground/5 border border-foreground/10 rounded-lg p-3 text-muted-foreground/80 select-all">{
                    provider === 'github'
                      ? 'GITHUB_CLIENT_ID=your_client_id\nGITHUB_CLIENT_SECRET=your_secret\nBACKEND_URL=http://localhost:8000\nFRONTEND_URL=http://localhost:3000'
                      : 'GITLAB_CLIENT_ID=your_client_id\nGITLAB_CLIENT_SECRET=your_secret\nBACKEND_URL=http://localhost:8000\nFRONTEND_URL=http://localhost:3000'
                  }</pre>
                  <p className="text-[11px] text-muted-foreground/60">
                    Create a {providerLabel} OAuth App and set the redirect URI to{' '}
                    <code className="text-[11px] bg-foreground/8 px-1 rounded">
                      http://localhost:8000/sast/oauth/{provider}/callback
                    </code>
                  </p>
                </div>
              )}

              {/* Configured but not connected */}
              {!oauthLoading && oauthStatus?.configured && !oauthStatus.connected && (
                <div className="flex flex-col items-center gap-3 py-8 border border-foreground/10 rounded-xl">
                  {provider === 'github'
                    ? <Github className="w-9 h-9 text-muted-foreground/60" />
                    : <Gitlab  className="w-9 h-9 text-muted-foreground/60" />
                  }
                  <div className="text-center">
                    <p className="text-sm font-medium text-foreground">
                      {oauthStatus.expired ? 'Session Expired' : `Connect ${providerLabel}`}
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {oauthStatus.expired
                        ? `Your ${providerLabel} token has expired. Please reconnect.`
                        : `Authorize Vectra to browse and scan your ${providerLabel} repositories.`
                      }
                    </p>
                  </div>
                  <Button
                    size="sm"
                    onClick={handleConnect}
                    className="bg-foreground text-background hover:bg-foreground/90 gap-2"
                  >
                    {provider === 'github'
                      ? <Github className="w-3.5 h-3.5" />
                      : <Gitlab className="w-3.5 h-3.5" />
                    }
                    {oauthStatus.expired ? `Reconnect ${providerLabel}` : `Connect ${providerLabel}`}
                  </Button>
                </div>
              )}

              {/* Connected — repo browser */}
              {!oauthLoading && oauthStatus?.connected && (
                <div className="space-y-3">

                  {/* Connected user strip */}
                  <div className="flex items-center justify-between px-3 py-2 bg-green-500/5 border border-green-500/15 rounded-xl">
                    <div className="flex items-center gap-2">
                      {oauthStatus.user?.avatar_url && (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img
                          src={oauthStatus.user.avatar_url}
                          alt=""
                          className="w-6 h-6 rounded-full border border-foreground/15"
                        />
                      )}
                      <div>
                        <p className="text-xs font-medium text-foreground leading-tight">
                          {oauthStatus.user?.name}
                        </p>
                        <p className="text-[10px] text-muted-foreground leading-tight">
                          @{oauthStatus.user?.login}
                        </p>
                      </div>
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 ml-0.5" />
                    </div>
                    <button
                      onClick={handleDisconnect}
                      className="text-[11px] text-muted-foreground hover:text-destructive transition-colors"
                    >
                      Disconnect
                    </button>
                  </div>

                  {/* Repo search + list */}
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1.5 block">Repository</Label>
                    <div className="relative mb-2">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50 pointer-events-none" />
                      <Input
                        placeholder={`Search ${providerLabel} repositories…`}
                        value={repoSearch}
                        onChange={(e) => setRepoSearch(e.target.value)}
                        className="h-8 text-xs pl-8"
                      />
                    </div>

                    <div className="border border-foreground/10 rounded-xl overflow-hidden h-52 overflow-y-auto">
                      {reposLoading ? (
                        <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span className="text-xs">Loading repositories…</span>
                        </div>
                      ) : repos.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
                          {repoSearch ? 'No repositories match your search' : 'No repositories found'}
                        </div>
                      ) : (
                        repos.map((repo) => {
                          const sel = selectedRepo?.fullName === repo.fullName
                          return (
                            <button
                              key={repo.fullName}
                              onClick={() => handleSelectRepo(repo)}
                              className={`w-full flex items-start gap-2.5 px-3 py-2.5 border-b border-foreground/8 last:border-0 text-left transition-colors ${
                                sel
                                  ? 'bg-violet-500/10 border-l-2 border-l-violet-500/60'
                                  : 'hover:bg-foreground/5'
                              }`}
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="text-xs font-medium text-foreground truncate">
                                    {repo.fullName}
                                  </span>
                                  <span className={`text-[9px] px-1 py-0.5 rounded border shrink-0 ${
                                    repo.visibility === 'private'
                                      ? 'border-orange-500/25 text-orange-400 bg-orange-500/8'
                                      : 'border-foreground/15 text-muted-foreground'
                                  }`}>
                                    {repo.visibility}
                                  </span>
                                </div>
                                {repo.description && (
                                  <p className="text-[10px] text-muted-foreground truncate mt-0.5">
                                    {repo.description}
                                  </p>
                                )}
                                {repo.language && (
                                  <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                                    {repo.language}
                                  </p>
                                )}
                              </div>
                              {sel && (
                                <CheckCircle2 className="w-3.5 h-3.5 text-violet-400 shrink-0 mt-0.5" />
                              )}
                            </button>
                          )
                        })
                      )}
                    </div>
                  </div>

                  {/* Branch selector */}
                  {selectedRepo && (
                    <div>
                      <Label className="text-xs text-muted-foreground mb-1.5 block">Branch</Label>
                      {branchesLoading ? (
                        <div className="flex items-center gap-2 text-muted-foreground py-1">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span className="text-xs">Loading branches…</span>
                        </div>
                      ) : (
                        <select
                          value={selectedBranch}
                          onChange={(e) => setSelectedBranch(e.target.value)}
                          className="w-full h-8 rounded-lg border border-foreground/15 bg-background px-2.5 text-xs text-foreground focus:outline-none focus:border-violet-500/50 focus:ring-0"
                        >
                          {branches.map((b) => (
                            <option key={b} value={b}>
                              {b}{b === defaultBranch ? ' (default)' : ''}
                            </option>
                          ))}
                        </select>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Project name */}
          <div>
            <Label htmlFor="pname" className="text-xs text-muted-foreground mb-1.5 block">
              Project Name
            </Label>
            <Input
              id="pname"
              placeholder="my-web-app"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              className="h-9 text-sm"
            />
          </div>

          {/* ZIP picker */}
          {method === 'zip' && (
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">ZIP Archive</Label>
              <input
                ref={zipRef}
                type="file"
                accept=".zip"
                className="block w-full text-xs text-muted-foreground file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border file:border-foreground/15 file:bg-foreground/5 file:text-xs file:font-medium file:text-foreground hover:file:bg-foreground/10 cursor-pointer"
              />
            </div>
          )}

          {/* Folder picker */}
          {method === 'directory' && (
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">Source Folder</Label>
              <input
                ref={dirRef}
                type="file"
                /* @ts-ignore – webkitdirectory is non-standard */
                webkitdirectory=""
                multiple
                className="block w-full text-xs text-muted-foreground file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border file:border-foreground/15 file:bg-foreground/5 file:text-xs file:font-medium file:text-foreground hover:file:bg-foreground/10 cursor-pointer"
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 pb-5 shrink-0 border-t border-foreground/8 pt-4">
          <Button variant="ghost" size="sm" onClick={handleClose} disabled={uploading}>
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleScan}
            disabled={!canScan}
            className="bg-violet-600 hover:bg-violet-700 text-white min-w-[140px]"
          >
            {uploading ? (
              <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Starting…</>
            ) : isRepoMethod ? (
              <><Zap className="w-3.5 h-3.5 mr-2" />Scan Repository</>
            ) : (
              <><Zap className="w-3.5 h-3.5 mr-2" />Upload &amp; Scan</>
            )}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function SastPage() {
  const { user } = useAuth()
  const router   = useRouter()

  const [scans, setScans]     = useState<FirestoreSastScan[]>([])
  const [modalOpen, setModal] = useState(false)

  useEffect(() => {
    if (!user) return
    return listenToSastScans(user.organizationId, setScans)
  }, [user])

  const running   = scans.filter((s) => SAST_ACTIVE_STATUSES.has(s.status)).length
  const completed = scans.filter((s) => s.status === 'completed').length
  const failed    = scans.filter((s) => s.status === 'failed').length
  const totalF    = scans.reduce((a, s) => a + s.totalFindings, 0)
  const critF     = scans.reduce((a, s) => a + s.criticalFindings, 0)
  const secretF   = scans.reduce((a, s) => a + s.secretFindings, 0)
  const depV      = scans.reduce((a, s) => a + s.dependencyVulns, 0)

  const recent = scans.slice(0, 8)

  return (
    <div className="p-6 space-y-6">
      <NewScanModal open={modalOpen} onClose={() => setModal(false)} />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground">SAST</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Static Application Security Testing</p>
        </div>
        <Button
          onClick={() => setModal(true)}
          className="bg-violet-600 hover:bg-violet-700 text-white gap-2"
        >
          <Code2 className="w-4 h-4" />
          New Scan
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total Scans"      value={scans.length} />
        <StatCard label="Running"          value={running}   accent={running   ? 'text-blue-400'   : 'text-foreground'} />
        <StatCard label="Completed"        value={completed} accent="text-green-400" />
        <StatCard label="Failed"           value={failed}    accent={failed    ? 'text-red-400'    : 'text-foreground'} />
        <StatCard label="Total Findings"   value={totalF}    sub={`${critF} critical`} />
        <StatCard label="Critical"         value={critF}     accent={critF     ? 'text-red-400'    : 'text-foreground'} />
        <StatCard label="Secret Findings"  value={secretF}   accent={secretF   ? 'text-orange-400' : 'text-foreground'} />
        <StatCard label="Dependency Vulns" value={depV}      accent={depV      ? 'text-yellow-400' : 'text-foreground'} />
      </div>

      {/* Recent scans */}
      <div className="bg-card border border-foreground/10 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-foreground/8">
          <h2 className="text-sm font-semibold text-foreground">Recent Scans</h2>
          {scans.length > 8 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs"
              onClick={() => router.push('/app/sast/scans')}
            >
              View all
            </Button>
          )}
        </div>

        {recent.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <FileCode2 className="w-10 h-10 text-muted-foreground/30 mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No SAST scans yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Upload a ZIP, source folder, or connect a GitHub/GitLab repository
            </p>
            <Button
              size="sm"
              className="mt-4 bg-violet-600 hover:bg-violet-700 text-white"
              onClick={() => setModal(true)}
            >
              <Code2 className="w-3.5 h-3.5 mr-2" /> New Scan
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-foreground/8">
            {recent.map((scan) => (
              <button
                key={scan.scanId}
                onClick={() => router.push(`/app/sast/scans/${scan.scanId}`)}
                className="w-full flex items-center gap-4 px-4 py-3 hover:bg-foreground/5 transition-colors text-left"
              >
                <div className="w-8 h-8 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
                  {scan.uploadMethod === 'github' ? (
                    <Github className="w-4 h-4 text-violet-400" />
                  ) : scan.uploadMethod === 'gitlab' ? (
                    <Gitlab className="w-4 h-4 text-violet-400" />
                  ) : (
                    <Code2 className="w-4 h-4 text-violet-400" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{scan.projectName}</p>
                  <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                    <span className="text-[10px] text-muted-foreground">{scan.language}</span>
                    {scan.repoBranch && (
                      <span className="text-[10px] text-muted-foreground">
                        branch: {scan.repoBranch}
                      </span>
                    )}
                    {scan.duration && (
                      <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                        <Clock className="w-2.5 h-2.5" />{scan.duration}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {scan.status === 'completed' && (
                    <div className="text-right">
                      <p className="text-xs font-semibold text-foreground">{scan.totalFindings}</p>
                      <p className="text-[10px] text-muted-foreground">findings</p>
                    </div>
                  )}
                  {SAST_ACTIVE_STATUSES.has(scan.status) && (
                    <div className="flex items-center gap-1.5 text-blue-400">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span className="text-xs">{scan.progress}%</span>
                    </div>
                  )}
                  <StatusBadge status={scan.status} />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
