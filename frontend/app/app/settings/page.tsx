'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Bell, Shield, Key, Palette, Database } from 'lucide-react'

export default function SettingsPage() {
  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Settings</h1>
        <p className="text-muted-foreground mt-1">Manage your account and preferences</p>
      </div>

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
          <div className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
            <div>
              <p className="font-medium text-foreground">Change Password</p>
              <p className="text-sm text-muted-foreground">Update your password regularly</p>
            </div>
            <Button variant="outline" className="rounded-lg border-foreground/20">
              Update
            </Button>
          </div>
          <div className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
            <div>
              <p className="font-medium text-foreground">Two-Factor Authentication</p>
              <p className="text-sm text-muted-foreground">Enhance your account security</p>
            </div>
            <Button variant="outline" className="rounded-lg border-foreground/20">
              Enable
            </Button>
          </div>
          <div className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
            <div>
              <p className="font-medium text-foreground">API Keys</p>
              <p className="text-sm text-muted-foreground">Manage your API access tokens</p>
            </div>
            <Button variant="outline" className="rounded-lg border-foreground/20">
              Manage
            </Button>
          </div>
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
            { name: 'Scan Completion', desc: 'Alerts when scans complete' },
            { name: 'Weekly Summary', desc: 'Receive weekly security summary reports' },
            { name: 'Team Updates', desc: 'Updates about team activities' },
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
            { name: 'Jira', status: 'Not Connected', icon: '🔧' },
            { name: 'GitHub', status: 'Connected', icon: '🐙' },
            { name: 'PagerDuty', status: 'Not Connected', icon: '📱' },
          ].map((integration, idx) => (
            <div key={idx} className="flex items-center justify-between p-4 border border-foreground/10 rounded-lg">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{integration.icon}</span>
                <div>
                  <p className="font-medium text-foreground">{integration.name}</p>
                  <p className={`text-xs ${
                    integration.status === 'Connected'
                      ? 'text-green-500'
                      : 'text-muted-foreground'
                  }`}>
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
        <CardContent className="space-y-3">
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
