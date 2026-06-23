'use client'

import { useState } from 'react'
import { Building2, Shield, Key, Brain, Bell, Plug, Save, Plus, Trash2, Eye, EyeOff, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

const initApiKeys = [
  { id: 1, name: 'Platform Master API Key', key: 'vk_live_a8f2b3c4d5e6f7g8h9i0', created: 'Jan 10, 2026', lastUsed: '2 min ago', permissions: 'Full Access' },
  { id: 2, name: 'CI/CD Pipeline Key', key: 'vk_live_b9c3d4e5f6g7h8i9j0k1', created: 'Dec 15, 2025', lastUsed: '1h ago', permissions: 'Scan + Report' },
  { id: 3, name: 'Analytics Service Key', key: 'vk_live_c0d4e5f6g7h8i9j0k1l2', created: 'Nov 28, 2025', lastUsed: '3d ago', permissions: 'Read Only' },
]

const aiModels = [
  { id: 'gpt-4o', name: 'GPT-4o', provider: 'OpenAI', recommended: true },
  { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', provider: 'OpenAI', recommended: false },
  { id: 'claude-3-opus', name: 'Claude 3 Opus', provider: 'Anthropic', recommended: false },
  { id: 'gemini-pro', name: 'Gemini 1.5 Pro', provider: 'Google', recommended: false },
]

const tabs = [
  { value: 'organization', label: 'Organization', icon: Building2 },
  { value: 'security', label: 'Security', icon: Shield },
  { value: 'api-keys', label: 'API Keys', icon: Key },
  { value: 'ai', label: 'AI Config', icon: Brain },
  { value: 'notifications', label: 'Notifications', icon: Bell },
  { value: 'integrations', label: 'Integrations', icon: Plug },
]

export default function AdminSettingsPage() {
  const [apiKeys, setApiKeys] = useState(initApiKeys)
  const [showKeys, setShowKeys] = useState<Record<number, boolean>>({})
  const [selectedModel, setSelectedModel] = useState('gpt-4o')
  const [notifications, setNotifications] = useState({
    criticalFindings: true, scanCompletion: true, newOrg: true,
    systemAlerts: true, weeklyReport: false, loginAlerts: true,
  })
  const [security, setSecurity] = useState({
    mfaRequired: true, sessionTimeout: true, ipWhitelist: false,
    auditLogging: true, bruteForce: true, adminMFA: true,
  })

  const toggleKey = (id: number) => setShowKeys(prev => ({ ...prev, [id]: !prev[id] }))
  const deleteKey = (id: number) => setApiKeys(prev => prev.filter(k => k.id !== id))
  const mask = (k: string) => k.slice(0, 10) + '••••••••••••••••••••'

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Platform Settings</h1>
        <p className="text-muted-foreground mt-1">Configure platform-wide settings, security, AI, and notification preferences</p>
      </div>

      <Tabs defaultValue="organization" className="space-y-6">
        <TabsList className="bg-foreground/5 border border-foreground/10 rounded-xl p-1 h-auto flex-wrap gap-1">
          {tabs.map(tab => {
            const Icon = tab.icon
            return (
              <TabsTrigger key={tab.value} value={tab.value} className="rounded-lg data-[state=active]:bg-card data-[state=active]:shadow-sm flex items-center gap-2 px-4 py-2 h-9">
                <Icon className="w-3.5 h-3.5" />{tab.label}
              </TabsTrigger>
            )
          })}
        </TabsList>

        {/* Organization */}
        <TabsContent value="organization">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-card border-foreground/10">
              <CardHeader>
                <CardTitle>Vectra Platform Details</CardTitle>
                <CardDescription>Core organization identity</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[
                  { label: 'Platform Name', defaultValue: 'Vectra Security Inc.' },
                  { label: 'Primary Domain', defaultValue: 'vectra.io' },
                  { label: 'Support Email', defaultValue: 'support@vectra.io' },
                  { label: 'Admin Contact', defaultValue: 'admin@vectra.io' },
                ].map(f => (
                  <div key={f.label} className="space-y-2">
                    <Label>{f.label}</Label>
                    <Input defaultValue={f.defaultValue} className="bg-foreground/5 border-foreground/20 rounded-lg" />
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card className="bg-card border-foreground/10">
              <CardHeader>
                <CardTitle>Platform Limits</CardTitle>
                <CardDescription>Default capacity limits for all tenants</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[
                  { label: 'Max Concurrent Scans (Platform)', defaultValue: '50' },
                  { label: 'Default Scan Timeout (min)', defaultValue: '120' },
                  { label: 'Data Retention (days)', defaultValue: '365' },
                  { label: 'Max Report Size (MB)', defaultValue: '50' },
                ].map(f => (
                  <div key={f.label} className="space-y-2">
                    <Label>{f.label}</Label>
                    <Input type="number" defaultValue={f.defaultValue} className="bg-foreground/5 border-foreground/20 rounded-lg" />
                  </div>
                ))}
                <Button className="w-full bg-primary hover:bg-primary/90 rounded-lg mt-2">
                  <Save className="w-4 h-4 mr-2" />Save Settings
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Security */}
        <TabsContent value="security">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <CardTitle>Platform Security Policies</CardTitle>
              <CardDescription>Configure authentication and access control across the entire platform</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { key: 'mfaRequired', label: 'Require MFA — All Users', desc: 'Force multi-factor authentication for every platform user' },
                { key: 'adminMFA', label: 'Require MFA — Admin Console', desc: 'Enforce MFA for super_admin and platform_admin login only' },
                { key: 'sessionTimeout', label: 'Session Timeout (30 min)', desc: 'Auto-logout inactive sessions after 30 minutes' },
                { key: 'ipWhitelist', label: 'Admin Console IP Whitelist', desc: 'Restrict admin console access to specific IP ranges' },
                { key: 'auditLogging', label: 'Audit Logging', desc: 'Log all user actions and system events across all tenants' },
                { key: 'bruteForce', label: 'Brute Force Protection', desc: 'Block IPs with repeated failed login attempts' },
              ].map(item => (
                <div key={item.key} className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg hover:bg-foreground/5 transition-colors">
                  <div>
                    <p className="text-sm font-medium text-foreground">{item.label}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{item.desc}</p>
                  </div>
                  <Switch checked={security[item.key as keyof typeof security]}
                    onCheckedChange={v => setSecurity(p => ({ ...p, [item.key]: v }))}
                    className="data-[state=checked]:bg-primary ml-4" />
                </div>
              ))}
              <Button className="bg-primary hover:bg-primary/90 rounded-lg"><Save className="w-4 h-4 mr-2" />Save Security Settings</Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Keys */}
        <TabsContent value="api-keys">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Platform API Keys</CardTitle>
                  <CardDescription>Manage master API keys for platform integrations</CardDescription>
                </div>
                <Button className="bg-primary hover:bg-primary/90 rounded-lg h-9 text-sm px-4">
                  <Plus className="w-4 h-4 mr-2" />Generate Key
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {apiKeys.map(k => (
                <div key={k.id} className="p-4 border border-foreground/10 rounded-lg hover:bg-foreground/5 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-foreground text-sm">{k.name}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <code className="text-xs font-mono text-muted-foreground bg-foreground/5 px-2 py-1 rounded">
                          {showKeys[k.id] ? k.key : mask(k.key)}
                        </code>
                        <Button variant="ghost" size="icon" className="h-6 w-6 rounded" onClick={() => toggleKey(k.id)}>
                          {showKeys[k.id] ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                        </Button>
                        <Button variant="ghost" size="icon" className="h-6 w-6 rounded"><Copy className="w-3 h-3" /></Button>
                      </div>
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>Created: {k.created}</span>
                        <span>Last used: {k.lastUsed}</span>
                        <span className="px-1.5 py-0.5 bg-primary/10 text-primary rounded">{k.permissions}</span>
                      </div>
                    </div>
                    <Button variant="ghost" size="icon" className="h-8 w-8 rounded hover:bg-destructive/10 hover:text-destructive" onClick={() => deleteKey(k.id)}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Config */}
        <TabsContent value="ai">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-card border-foreground/10">
              <CardHeader>
                <CardTitle>AI Model Selection</CardTitle>
                <CardDescription>Platform-wide AI model for analysis and report generation</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {aiModels.map(m => (
                  <button key={m.id} onClick={() => setSelectedModel(m.id)}
                    className={`w-full flex items-center gap-4 p-3.5 rounded-lg border text-left transition-all ${selectedModel === m.id ? 'bg-primary/5 border-primary/30' : 'bg-foreground/5 border-foreground/10 hover:border-foreground/20'}`}>
                    <div className={`w-4 h-4 rounded-full border-2 shrink-0 flex items-center justify-center ${selectedModel === m.id ? 'border-primary' : 'border-foreground/30'}`}>
                      {selectedModel === m.id && <div className="w-2 h-2 rounded-full bg-primary" />}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium text-foreground">{m.name}</p>
                        {m.recommended && <span className="text-xs px-1.5 py-0.5 bg-green-500/10 text-green-500 rounded">Recommended</span>}
                      </div>
                      <p className="text-xs text-muted-foreground">{m.provider}</p>
                    </div>
                  </button>
                ))}
              </CardContent>
            </Card>
            <Card className="bg-card border-foreground/10">
              <CardHeader>
                <CardTitle>AI Parameters</CardTitle>
                <CardDescription>Fine-tune AI behavior for platform-wide security analysis</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[{ label: 'Max Tokens per Request', defaultValue: '4096' }, { label: 'Temperature (0–1)', defaultValue: '0.3' }].map(f => (
                  <div key={f.label} className="space-y-2">
                    <Label>{f.label}</Label>
                    <Input defaultValue={f.defaultValue} className="bg-foreground/5 border-foreground/20 rounded-lg" />
                  </div>
                ))}
                <div className="space-y-2">
                  <Label>System Prompt Override</Label>
                  <textarea rows={4} placeholder="Optional: Override default AI behavior for all tenants..." className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-sm text-foreground resize-none focus:outline-none focus:ring-1 focus:ring-primary" />
                </div>
                <Button className="w-full bg-primary hover:bg-primary/90 rounded-lg"><Save className="w-4 h-4 mr-2" />Save AI Config</Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Notifications */}
        <TabsContent value="notifications">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <CardTitle>Platform Notification Settings</CardTitle>
              <CardDescription>Control which platform events trigger admin alerts</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { key: 'criticalFindings', label: 'Critical Finding Detected (Platform-wide)', desc: 'Alert when any tenant finds a critical vulnerability' },
                { key: 'scanCompletion', label: 'Scan Completion', desc: 'Notify on all scan completions across the platform' },
                { key: 'newOrg', label: 'New Organization Signup', desc: 'Alert when a new tenant organization registers' },
                { key: 'systemAlerts', label: 'System Alerts & Degradation', desc: 'Receive alerts for service degradation and outages' },
                { key: 'weeklyReport', label: 'Weekly Platform Summary', desc: 'Weekly digest of platform-wide activity every Monday' },
                { key: 'loginAlerts', label: 'Suspicious Login Activity', desc: 'Alert on admin console brute-force attempts' },
              ].map(item => (
                <div key={item.key} className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg hover:bg-foreground/5 transition-colors">
                  <div>
                    <p className="text-sm font-medium text-foreground">{item.label}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{item.desc}</p>
                  </div>
                  <Switch checked={notifications[item.key as keyof typeof notifications]}
                    onCheckedChange={v => setNotifications(p => ({ ...p, [item.key]: v }))}
                    className="data-[state=checked]:bg-primary ml-4" />
                </div>
              ))}
              <div className="space-y-2">
                <Label>Admin Alert Email</Label>
                <Input defaultValue="admin@vectra.io" className="bg-foreground/5 border-foreground/20 rounded-lg" />
              </div>
              <Button className="bg-primary hover:bg-primary/90 rounded-lg"><Save className="w-4 h-4 mr-2" />Save Preferences</Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Integrations overview */}
        <TabsContent value="integrations">
          <Card className="bg-card border-foreground/10">
            <CardHeader>
              <CardTitle>Integration Settings</CardTitle>
              <CardDescription>Quick overview of connected platform integrations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { name: 'Firebase Auth', status: 'Connected', icon: '🔥' },
                { name: 'GitHub', status: 'Connected', icon: '🐙' },
                { name: 'Slack Alerts', status: 'Connected', icon: '💬' },
                { name: 'OpenAI GPT-4o', status: 'Connected', icon: '🤖' },
                { name: 'AWS Platform', status: 'Connected', icon: '☁' },
                { name: 'GitLab', status: 'Disconnected', icon: '🦊' },
                { name: 'Microsoft Teams', status: 'Disconnected', icon: '🟦' },
              ].map(item => (
                <div key={item.name} className="flex items-center justify-between p-3.5 border border-foreground/10 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">{item.icon}</span>
                    <p className="text-sm font-medium text-foreground">{item.name}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded ${item.status === 'Connected' ? 'bg-green-500/10 text-green-500' : 'bg-muted text-muted-foreground'}`}>{item.status}</span>
                    <Button size="sm" variant="ghost" className="h-7 text-xs rounded hover:bg-foreground/10">Configure</Button>
                  </div>
                </div>
              ))}
              <p className="text-xs text-muted-foreground text-center mt-2">
                For full integration management, visit the <a href="/admin/integrations" className="text-primary hover:underline">Integrations page →</a>
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
