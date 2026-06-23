'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Plus, Trash2, Shield, Eye, Edit2 } from 'lucide-react'

const teamMembers = [
  { id: 1, name: 'John Doe', email: 'john@example.com', role: 'Admin', status: 'Active', joined: '2024-01-01' },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'Editor', status: 'Active', joined: '2024-01-15' },
  { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'Viewer', status: 'Active', joined: '2024-01-20' },
  { id: 4, name: 'Alice Williams', email: 'alice@example.com', role: 'Editor', status: 'Pending', joined: '2024-02-01' },
]

export default function TeamPage() {
  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Team Management</h1>
          <p className="text-muted-foreground mt-1">Manage team members and access permissions</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6">
          <Plus className="w-4 h-4 mr-2" />
          Invite Member
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Total Members</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">{teamMembers.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Active</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{teamMembers.filter(m => m.status === 'Active').length}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Pending Invites</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{teamMembers.filter(m => m.status === 'Pending').length}</div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Team Members</CardTitle>
          <CardDescription>Manage your team and their access levels</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Name</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Email</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Role</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Joined</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {teamMembers.map((member) => (
                  <tr key={member.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-4 font-medium text-foreground">{member.name}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{member.email}</td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-medium px-2 py-1 bg-primary/10 text-primary rounded">
                        {member.role}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`text-xs font-medium px-2 py-1 rounded ${
                        member.status === 'Active'
                          ? 'bg-green-500/10 text-green-500'
                          : 'bg-yellow-500/10 text-yellow-500'
                      }`}>
                        {member.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{member.joined}</td>
                    <td className="py-3 px-4">
                      <div className="flex gap-1">
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <Edit2 className="w-4 h-4" />
                        </Button>
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10">
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Roles & Permissions */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Roles & Permissions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { role: 'Admin', desc: 'Full access to all features and settings', icon: Shield, permissions: 'All' },
            { role: 'Editor', desc: 'Can create and manage scans and reports', icon: Edit2, permissions: 'Create, Edit, View' },
            { role: 'Viewer', desc: 'View-only access to dashboards and reports', icon: Eye, permissions: 'View' },
          ].map((item, idx) => (
            <div key={idx} className="border border-foreground/10 rounded-lg p-4">
              <div className="flex items-start gap-4">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <item.icon className="w-5 h-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="font-medium text-foreground">{item.role}</p>
                  <p className="text-sm text-muted-foreground">{item.desc}</p>
                  <p className="text-xs text-muted-foreground mt-2">Permissions: {item.permissions}</p>
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
