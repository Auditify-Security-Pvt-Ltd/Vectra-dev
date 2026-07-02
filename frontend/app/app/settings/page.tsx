'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Bell, Shield, Key, Palette, Database, CalendarClock, Check, Loader2 } from 'lucide-react'
import { useAuth } from '@/context/auth-context'
import { listenToSlaPolicy, saveSlaPolicy, DEFAULT_SLA, type SlaPolicy } from '@/lib/firestore-sla'

// ── SLA Policy card ────────────────────────────────────────────────────

const SLA_ROWS: { key: keyof Pick<SlaPolicy,'critical'|'high'|'medium'|'low'|'info'>; label: string; cls: string }[] = [
  { key: 'critical', label: 'Critical', cls: 'text-red-400'    },
  { key: 'high',     label: 'High',     cls: 'text-orange-400' },
  { key: 'medium',   label: 'Medium',   cls: 'text-yellow-400' },
  { key: 'low',      label: 'Low',      cls: 'text-blue-400'   },
  { key: 'info',     label: 'Info',     cls: 'text-slate-400'  },
]

function SlaPolicyCard() {
  const { user }                = useAuth()
  const [policy, setPolicy]     = useState<SlaPolicy>(DEFAULT_SLA)
  const [draft,  setDraft]      = useState<SlaPolicy>(DEFAULT_SLA)
  const [saving, setSaving]     = useState(false)
  const [saved,  setSaved]      = useState(false)

  useEffect(() => {
    if (!user) return
    return listenToSlaPolicy(user.uid, (p) => {
      setPolicy(p)
      setDraft(p)
    })
  }, [user])

  function setDays(key: keyof Pick<SlaPolicy,'critical'|'high'|'medium'|'low'|'info'>, raw: string) {
    const n = parseInt(raw, 10)
    setDraft(prev => ({ ...prev, [key]: isNaN(n) || raw === '' ? null : Math.max(1, n) }))
  }

  function setWarn(raw: string) {
    const n = parseInt(raw, 10)
    setDraft(prev => ({ ...prev, warnDays: isNaN(n) ? 3 : Math.max(1, n) }))
  }

  async function handleSave() {
    if (!user) return
    setSaving(true)
    try {
      await saveSlaPolicy(user.uid, draft)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } finally {
      setSaving(false)
    }
  }

  const isDirty = JSON.stringify(draft) !== JSON.stringify(policy)

  return (
    <Card className="bg-card border-foreground/10">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CalendarClock className="w-5 h-5 text-primary" />
          SLA Policy
        </CardTitle>
        <CardDescription>
          Configure remediation deadlines by severity. Findings that exceed these deadlines are flagged as Breached.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">

        {/* Severity rows */}
        <div className="space-y-1">
          {/* Header */}
          <div className="grid grid-cols-[1fr_auto_auto] gap-4 px-4 pb-2">
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider">Severity</p>
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider w-28 text-center">SLA Deadline</p>
            <p className="text-[10px] font-semibold text-muted-foreground/55 uppercase tracking-wider w-16 text-center">Unit</p>
          </div>

          {SLA_ROWS.map(({ key, label, cls }) => (
            <div key={key} className="grid grid-cols-[1fr_auto_auto] gap-4 items-center px-4 py-3 rounded-xl border border-foreground/8 bg-foreground/[0.02] hover:bg-foreground/[0.04] transition-colors">
              <div className="flex items-center gap-2.5">
                <span className={`w-2 h-2 rounded-full shrink-0 ${cls.replace('text-', 'bg-')}`} />
                <span className={`text-sm font-semibold ${cls}`}>{label}</span>
              </div>
              <div className="w-28">
                <Input
                  type="number"
                  min={1}
                  placeholder="No SLA"
                  value={draft[key] ?? ''}
                  onChange={(e) => setDays(key, e.target.value)}
                  className="h-8 text-center bg-foreground/5 border-foreground/15 rounded-lg text-sm font-semibold tabular-nums"
                />
              </div>
              <p className="w-16 text-xs text-muted-foreground text-center">
                {draft[key] != null ? 'days' : '—'}
              </p>
            </div>
          ))}
        </div>

        {/* Warning threshold */}
        <div className="flex items-center justify-between p-4 rounded-xl border border-orange-500/20 bg-orange-500/[0.04]">
          <div>
            <p className="text-sm font-semibold text-foreground">Due Soon Warning</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Show "Due Soon" badge when a finding is within this many days of its deadline.
            </p>
          </div>
          <div className="flex items-center gap-2.5 shrink-0 ml-6">
            <Input
              type="number"
              min={1}
              max={30}
              value={draft.warnDays}
              onChange={(e) => setWarn(e.target.value)}
              className="h-8 w-16 text-center bg-foreground/5 border-orange-500/20 rounded-lg text-sm font-semibold tabular-nums"
            />
            <span className="text-xs text-muted-foreground">days</span>
          </div>
        </div>

        {/* Preview */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 text-center">
          {SLA_ROWS.filter(r => draft[r.key] != null).map(({ key, label, cls }) => (
            <div key={key} className="rounded-xl bg-foreground/[0.03] border border-foreground/8 p-3">
              <p className={`text-[10px] font-semibold uppercase tracking-wider ${cls}`}>{label}</p>
              <p className="text-2xl font-bold text-foreground tabular-nums mt-1">{draft[key]}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">days</p>
            </div>
          ))}
          {SLA_ROWS.filter(r => draft[r.key] == null).map(({ key, label, cls }) => (
            <div key={key} className="rounded-xl bg-foreground/[0.02] border border-foreground/8 p-3 opacity-50">
              <p className={`text-[10px] font-semibold uppercase tracking-wider ${cls}`}>{label}</p>
              <p className="text-sm text-muted-foreground mt-2">No SLA</p>
            </div>
          ))}
        </div>

        {/* Save */}
        <div className="flex items-center justify-between pt-2">
          <p className="text-xs text-muted-foreground/60">
            Changes apply immediately to the Vulnerability Management dashboard.
          </p>
          <Button
            onClick={handleSave}
            disabled={saving || !isDirty}
            className="min-w-[100px] gap-2"
          >
            {saving ? (
              <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving…</>
            ) : saved ? (
              <><Check className="w-3.5 h-3.5" /> Saved</>
            ) : (
              'Save Policy'
            )}
          </Button>
        </div>

      </CardContent>
    </Card>
  )
}

// ── Settings page ──────────────────────────────────────────────────────

export default function SettingsPage() {
  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Settings</h1>
        <p className="text-muted-foreground mt-1">Manage your account and preferences</p>
      </div>

      {/* SLA Policy — primary enterprise section */}
      <SlaPolicyCard />

      {/* Account Settings */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Account Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Email Address</label>
            <Input
              type="email"
              value="user@example.com"
              className="bg-foreground/5 border-foreground/20 rounded-lg"
              disabled
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Full Name</label>
            <Input
              type="text"
              value="John Doe"
              className="bg-foreground/5 border-foreground/20 rounded-lg"
            />
          </div>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg">
            Save Changes
          </Button>
        </CardContent>
      </Card>

      {/* Security */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="w-5 h-5" />
            Security
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { label: 'Change Password', desc: 'Update your password regularly' },
            { label: 'Two-Factor Authentication', desc: 'Enhance your account security' },
            { label: 'API Keys', desc: 'Manage your API access tokens' },
          ].map((item) => (
            <div key={item.label} className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
              <div>
                <p className="font-medium text-foreground">{item.label}</p>
                <p className="text-sm text-muted-foreground">{item.desc}</p>
              </div>
              <Button variant="outline" className="rounded-lg border-foreground/20">
                {item.label === 'API Keys' ? 'Manage' : item.label === 'Two-Factor Authentication' ? 'Enable' : 'Update'}
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="w-5 h-5" />
            Notifications
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { name: 'Critical Findings', desc: 'Get notified of critical security findings' },
            { name: 'SLA Breaches', desc: 'Alert when findings exceed their SLA deadline' },
            { name: 'Scan Completion', desc: 'Alerts when scans complete' },
            { name: 'Weekly Summary', desc: 'Receive weekly security summary reports' },
          ].map((item, idx) => (
            <label key={idx} className="flex items-center gap-3 p-3 border border-foreground/10 rounded-lg cursor-pointer hover:bg-foreground/5">
              <input type="checkbox" defaultChecked className="w-4 h-4" />
              <div>
                <p className="font-medium text-foreground">{item.name}</p>
                <p className="text-sm text-muted-foreground">{item.desc}</p>
              </div>
            </label>
          ))}
        </CardContent>
      </Card>

      {/* Integrations */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="w-5 h-5" />
            Integrations
          </CardTitle>
          <CardDescription>Connect third-party services and platforms</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {[
            { name: 'Slack', status: 'Not Connected', icon: '💬' },
            { name: 'Jira',  status: 'Not Connected', icon: '🔧' },
            { name: 'GitHub',status: 'Connected',     icon: '🐙' },
            { name: 'PagerDuty', status: 'Not Connected', icon: '📱' },
          ].map((integration, idx) => (
            <div key={idx} className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{integration.icon}</span>
                <div>
                  <p className="font-medium text-foreground">{integration.name}</p>
                  <p className={`text-xs ${integration.status === 'Connected' ? 'text-green-500' : 'text-muted-foreground'}`}>
                    {integration.status}
                  </p>
                </div>
              </div>
              <Button variant="outline" className="rounded-lg border-foreground/20">
                {integration.status === 'Connected' ? 'Disconnect' : 'Connect'}
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Preferences */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Palette className="w-5 h-5" />
            Preferences
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Theme</label>
            <select className="w-full px-4 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground">
              <option>Dark (Default)</option>
              <option>Light</option>
              <option>System</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Default Report Format</label>
            <select className="w-full px-4 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground">
              <option>PDF</option>
              <option>Excel</option>
              <option>HTML</option>
            </select>
          </div>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg">
            Save Preferences
          </Button>
        </CardContent>
      </Card>

      {/* Danger Zone */}
      <Card className="bg-card border-foreground/10 border-l-4 border-l-destructive">
        <CardHeader>
          <CardTitle className="text-destructive">Danger Zone</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
            <div>
              <p className="font-medium text-foreground">Delete Account</p>
              <p className="text-sm text-muted-foreground">Permanently delete your account and all data</p>
            </div>
            <Button variant="outline" className="rounded-lg border-destructive/50 text-destructive hover:text-destructive hover:bg-destructive/10">
              Delete
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
