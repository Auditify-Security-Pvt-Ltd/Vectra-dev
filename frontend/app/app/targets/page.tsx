'use client'

import { useEffect, useState } from 'react'
import { Plus, Search, Play, Trash2, Pencil, X } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { NewScanModal } from '@/components/app/new-scan-modal'
import {
  listenToTargets,
  createTarget,
  updateTarget,
  deleteTarget,
  type FirestoreTarget,
} from '@/lib/firestore-targets'
import { useAuth } from '@/context/auth-context'

interface TargetFormData {
  name: string
  url: string
  description: string
  tags: string
}

const EMPTY_FORM: TargetFormData = { name: '', url: '', description: '', tags: '' }

export default function TargetsPage() {
  const { user } = useAuth()
  const [targets, setTargets] = useState<FirestoreTarget[]>([])
  const [search, setSearch] = useState('')

  // Dialog state
  const [formOpen, setFormOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<FirestoreTarget | null>(null)
  const [form, setForm] = useState<TargetFormData>(EMPTY_FORM)
  const [formLoading, setFormLoading] = useState(false)

  // Delete confirmation state
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [deleteLoading, setDeleteLoading] = useState(false)

  // Scan modal
  const [scanModalOpen, setScanModalOpen] = useState(false)
  const [scanTarget, setScanTarget] = useState('')

  // Firestore realtime listener
  useEffect(() => {
    if (!user) return
    const unsub = listenToTargets(user.uid, setTargets)
    return unsub
  }, [user])

  function openCreate() {
    setEditTarget(null)
    setForm(EMPTY_FORM)
    setFormOpen(true)
  }

  function openEdit(t: FirestoreTarget) {
    setEditTarget(t)
    setForm({
      name: t.name,
      url: t.url,
      description: t.description ?? '',
      tags: (t.tags ?? []).join(', '),
    })
    setFormOpen(true)
  }

  async function handleFormSubmit() {
    if (!user || !form.name.trim() || !form.url.trim()) return
    setFormLoading(true)

    let url = form.url.trim()
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url
    }

    const data = {
      name: form.name.trim(),
      url,
      description: form.description.trim(),
      tags: form.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
    }

    try {
      if (editTarget) {
        await updateTarget(user.uid, editTarget.id, data)
        toast.success('Target updated')
      } else {
        await createTarget(user.uid, data)
        toast.success('Target created')
      }
      setFormOpen(false)
    } catch (err) {
      toast.error('Failed to save target', {
        description: err instanceof Error ? err.message : undefined,
      })
    } finally {
      setFormLoading(false)
    }
  }

  async function handleDelete() {
    if (!user || !deleteId) return
    setDeleteLoading(true)
    try {
      await deleteTarget(user.uid, deleteId)
      toast.success('Target deleted')
      setDeleteId(null)
    } catch (err) {
      toast.error('Failed to delete target', {
        description: err instanceof Error ? err.message : undefined,
      })
    } finally {
      setDeleteLoading(false)
    }
  }

  function handleScan(url: string) {
    setScanTarget(url)
    setScanModalOpen(true)
  }

  const filtered = targets.filter((t) =>
    t.name.toLowerCase().includes(search.toLowerCase()) ||
    t.url.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Scan Targets</h1>
          <p className="text-muted-foreground mt-1">Configure and manage security assessment targets</p>
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6"
          onClick={openCreate}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Target
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Total Targets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{targets.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Domains</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">
              {targets.filter((t) => !t.url.match(/^\d+\.\d+\.\d+\.\d+/)).length}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Ready to Scan</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{targets.length}</div>
          </CardContent>
        </Card>
      </div>

      {/* Targets list */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Active Targets</CardTitle>
              <CardDescription>{filtered.length} target{filtered.length !== 1 ? 's' : ''}</CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search targets…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <p className="text-sm">No targets yet.</p>
              <p className="text-xs mt-1">Click &ldquo;Add Target&rdquo; to create your first target.</p>
            </div>
          ) : (
            filtered.map((target) => (
              <div
                key={target.id}
                className="border border-foreground/10 rounded-lg p-4 hover:bg-foreground/5 transition-colors"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-foreground">{target.name}</p>
                    <p className="text-sm text-muted-foreground font-mono mt-0.5 truncate">{target.url}</p>
                    {target.description && (
                      <p className="text-xs text-muted-foreground mt-1">{target.description}</p>
                    )}
                    {target.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {target.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-xs px-2 py-0.5 rounded bg-foreground/5 text-muted-foreground border border-foreground/10"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="text-xs font-medium px-3 py-1 rounded-full bg-green-500/10 text-green-500 shrink-0 ml-3">
                    Ready
                  </span>
                </div>

                <div className="flex items-center justify-between mt-3">
                  <span className="text-xs text-muted-foreground">
                    Added {new Date(target.createdAt).toLocaleDateString()}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8 rounded-lg border-foreground/20 gap-1"
                      onClick={() => handleScan(target.url)}
                    >
                      <Play className="w-3 h-3" />
                      Scan
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 rounded-lg text-muted-foreground hover:text-foreground hover:bg-foreground/10"
                      onClick={() => openEdit(target)}
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 rounded-lg text-destructive hover:text-destructive hover:bg-destructive/10"
                      onClick={() => setDeleteId(target.id)}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Create / Edit dialog */}
      <Dialog open={formOpen} onOpenChange={formLoading ? undefined : setFormOpen}>
        <DialogContent className="sm:max-w-md bg-card border-foreground/10">
          <DialogHeader>
            <DialogTitle>{editTarget ? 'Edit Target' : 'Add Target'}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">
                Name <span className="text-destructive">*</span>
              </label>
              <Input
                placeholder="Production API"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                className="bg-foreground/5 border-foreground/20"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">
                URL <span className="text-destructive">*</span>
              </label>
              <Input
                placeholder="https://api.example.com"
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                className="bg-foreground/5 border-foreground/20"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Description</label>
              <Input
                placeholder="Optional description"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                className="bg-foreground/5 border-foreground/20"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">
                Tags{' '}
                <span className="text-xs text-muted-foreground/60">(comma-separated)</span>
              </label>
              <Input
                placeholder="production, api, critical"
                value={form.tags}
                onChange={(e) => setForm((f) => ({ ...f, tags: e.target.value }))}
                className="bg-foreground/5 border-foreground/20"
              />
            </div>
          </div>
          <DialogFooter className="pt-2">
            <Button
              variant="outline"
              className="border-foreground/20"
              onClick={() => setFormOpen(false)}
              disabled={formLoading}
            >
              Cancel
            </Button>
            <Button
              className="bg-primary hover:bg-primary/90"
              onClick={handleFormSubmit}
              disabled={!form.name.trim() || !form.url.trim() || formLoading}
            >
              {formLoading ? 'Saving…' : editTarget ? 'Save Changes' : 'Add Target'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(o) => !o && setDeleteId(null)}>
        <AlertDialogContent className="bg-card border-foreground/10">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Target</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently remove the target. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              disabled={deleteLoading}
              className="border-foreground/20"
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
              onClick={handleDelete}
            >
              {deleteLoading ? 'Deleting…' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Scan modal triggered from Scan button */}
      <NewScanModal
        open={scanModalOpen}
        onOpenChange={setScanModalOpen}
        defaultTarget={scanTarget}
      />
    </div>
  )
}
