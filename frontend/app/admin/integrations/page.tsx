'use client'

import { useState } from 'react'
import { CheckCircle2, XCircle, Settings, Zap } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

const initIntegrations = [
  { id: 'firebase', name: 'Firebase', category: 'Auth & Database', description: 'Authentication, real-time database, and session management for the entire platform.', status: 'Connected', lastSync: '3 min ago', icon: '🔥', color: 'from-orange-500/10', fields: [{ label: 'Project ID', placeholder: 'my-project-id' }, { label: 'API Key', placeholder: 'AIza...' }] },
  { id: 'github', name: 'GitHub', category: 'Source Control', description: 'Scan GitHub repositories for secrets, vulnerabilities, and insecure configurations.', status: 'Connected', lastSync: '10 min ago', icon: '🐙', color: 'from-foreground/5', fields: [{ label: 'Personal Access Token', placeholder: 'ghp_...' }, { label: 'Organization', placeholder: 'vectra-io' }] },
  { id: 'gitlab', name: 'GitLab', category: 'Source Control', description: 'Integrate GitLab CI/CD pipelines for automated security scanning.', status: 'Disconnected', lastSync: 'Never', icon: '🦊', color: 'from-orange-500/5', fields: [{ label: 'Access Token', placeholder: 'glpat-...' }, { label: 'GitLab URL', placeholder: 'https://gitlab.com' }] },
  { id: 'slack', name: 'Slack', category: 'Notifications', description: 'Real-time security alerts, scan results, and critical findings to Slack channels.', status: 'Connected', lastSync: '1 min ago', icon: '💬', color: 'from-green-500/10', fields: [{ label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...' }, { label: 'Channel', placeholder: '#security-alerts' }] },
  { id: 'teams', name: 'Microsoft Teams', category: 'Notifications', description: 'Push vulnerability notifications and reports to Microsoft Teams channels.', status: 'Disconnected', lastSync: 'Never', icon: '🟦', color: 'from-blue-500/5', fields: [{ label: 'Webhook URL', placeholder: 'https://outlook.office.com/...' }] },
  { id: 'openai', name: 'OpenAI', category: 'AI / ML', description: 'Power AI-driven vulnerability analysis, threat summaries, and automated report generation.', status: 'Connected', lastSync: '30s ago', icon: '🤖', color: 'from-primary/10', fields: [{ label: 'API Key', placeholder: 'sk-...' }, { label: 'Model', placeholder: 'gpt-4o' }] },
  { id: 'aws', name: 'AWS', category: 'Cloud', description: 'Platform-level AWS integration for cloud posture management and IAM analysis across all tenants.', status: 'Connected', lastSync: '5 min ago', icon: '☁', color: 'from-orange-500/10', fields: [{ label: 'Access Key ID', placeholder: 'AKIA...' }, { label: 'Secret Key', placeholder: '••••••••' }, { label: 'Region', placeholder: 'us-east-1' }] },
]

const statusConfig: Record<string, { icon: any; text: string }> = {
  Connected: { icon: CheckCircle2, text: 'text-green-500' },
  Disconnected: { icon: XCircle, text: 'text-muted-foreground' },
}

const categories = ['All', 'Auth & Database', 'Source Control', 'Notifications', 'AI / ML', 'Cloud']

export default function AdminIntegrationsPage() {
  const [integrations, setIntegrations] = useState(initIntegrations)
  const [categoryFilter, setCategoryFilter] = useState('All')
  const [configTarget, setConfigTarget] = useState<typeof initIntegrations[0] | null>(null)

  const filtered = integrations.filter(i => categoryFilter === 'All' || i.category === categoryFilter)
  const connected = integrations.filter(i => i.status === 'Connected').length

  const toggle = (id: string) => setIntegrations(prev => prev.map(i =>
    i.id === id ? { ...i, status: i.status === 'Connected' ? 'Disconnected' : 'Connected', lastSync: i.status === 'Connected' ? 'Never' : 'Just now' } : i
  ))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Platform Integrations</h1>
          <p className="text-muted-foreground mt-1">Connect external services to extend Vectra's capabilities platform-wide</p>
        </div>
        <div className="flex items-center gap-3 px-4 py-2.5 bg-green-500/10 rounded-lg border border-green-500/20">
          <CheckCircle2 className="w-4 h-4 text-green-500" />
          <span className="text-sm font-medium text-green-500">{connected} / {integrations.length} Connected</span>
        </div>
      </div>

      <div className="flex gap-2 flex-wrap">
        {categories.map(c => (
          <Button key={c} size="sm" variant={categoryFilter === c ? 'default' : 'outline'} onClick={() => setCategoryFilter(c)}
            className={`rounded-lg h-9 ${categoryFilter === c ? 'bg-primary text-primary-foreground' : 'border-foreground/20'}`}>{c}</Button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filtered.map(integration => {
          const cfg = statusConfig[integration.status]
          const StatusIcon = cfg.icon
          return (
            <Card key={integration.id} className={`bg-card border-foreground/10 bg-gradient-to-br ${integration.color} to-transparent hover:border-foreground/20 transition-all`}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-11 h-11 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center text-2xl">{integration.icon}</div>
                    <div>
                      <CardTitle className="text-base">{integration.name}</CardTitle>
                      <CardDescription className="text-xs">{integration.category}</CardDescription>
                    </div>
                  </div>
                  <Switch checked={integration.status === 'Connected'} onCheckedChange={() => toggle(integration.id)} className="data-[state=checked]:bg-primary shrink-0" />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">{integration.description}</p>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <StatusIcon className={`w-3.5 h-3.5 ${cfg.text}`} />
                    <span className={`text-xs font-medium ${cfg.text}`}>{integration.status}</span>
                    {integration.status === 'Connected' && <span className="text-xs text-muted-foreground">· {integration.lastSync}</span>}
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 text-xs rounded hover:bg-foreground/10" onClick={() => setConfigTarget(integration)}>
                    <Settings className="w-3 h-3 mr-1" />Configure
                  </Button>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <Dialog open={!!configTarget} onOpenChange={(open) => !open && setConfigTarget(null)}>
        <DialogContent className="bg-card border-foreground/10">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <span className="text-xl">{configTarget?.icon}</span>Configure {configTarget?.name}
            </DialogTitle>
            <DialogDescription>Update platform connection settings for {configTarget?.name}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {configTarget?.fields.map(f => (
              <div key={f.label} className="space-y-2">
                <Label>{f.label}</Label>
                <Input placeholder={f.placeholder} className="bg-foreground/5 border-foreground/20 rounded-lg" />
              </div>
            ))}
            <div className="flex items-center gap-3 p-3 bg-foreground/5 rounded-lg">
              <Zap className="w-4 h-4 text-primary shrink-0" />
              <span className="text-xs text-muted-foreground">Connection will be tested automatically after saving</span>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfigTarget(null)} className="rounded-lg border-foreground/20">Cancel</Button>
            <Button className="bg-primary hover:bg-primary/90 rounded-lg" onClick={() => setConfigTarget(null)}>Save & Test</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
