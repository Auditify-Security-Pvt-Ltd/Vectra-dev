'use client'

import { useState } from 'react'
import { Search, UserPlus, MoreHorizontal, Edit2, ShieldOff, KeyRound, Trash2, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'

const initUsers = [
  { id: 1, name: 'James Wilson', email: 'james@fintechcorp.io', role: 'team_admin', org: 'FinTech Corp', status: 'Active', lastLogin: '5 min ago', created: 'Jan 14, 2026', avatar: 'JW' },
  { id: 2, name: 'Sarah Chen', email: 'sarah@medsecure.io', role: 'analyst', org: 'MedSecure Ltd', status: 'Active', lastLogin: '1h ago', created: 'Jan 12, 2026', avatar: 'SC' },
  { id: 3, name: 'Marcus Davis', email: 'marcus@cloudnative.io', role: 'customer', org: 'CloudNative IO', status: 'Trial', lastLogin: '2h ago', created: 'Jan 10, 2026', avatar: 'MD' },
  { id: 4, name: 'Elena Popov', email: 'elena@cybershield.io', role: 'analyst', org: 'CyberShield Inc', status: 'Active', lastLogin: '3h ago', created: 'Jan 8, 2026', avatar: 'EP' },
  { id: 5, name: 'Ryan Torres', email: 'ryan@datasafe.com', role: 'team_admin', org: 'DataSafe Corp', status: 'Active', lastLogin: 'Today', created: 'Dec 28, 2025', avatar: 'RT' },
  { id: 6, name: 'Aisha Patel', email: 'aisha@secopsco.io', role: 'customer', org: 'SecOps Co', status: 'Active', lastLogin: 'Yesterday', created: 'Dec 22, 2025', avatar: 'AP' },
  { id: 7, name: 'Lucas Müller', email: 'lucas@infrashield.de', role: 'analyst', org: 'InfraShield GmbH', status: 'Suspended', lastLogin: '5d ago', created: 'Dec 15, 2025', avatar: 'LM' },
  { id: 8, name: 'Priya Sharma', email: 'priya@zerosec.in', role: 'customer', org: 'ZeroSec Labs', status: 'Active', lastLogin: '2d ago', created: 'Dec 10, 2025', avatar: 'PS' },
  { id: 9, name: 'Noah Johnson', email: 'noah@guardiancorp.net', role: 'team_admin', org: 'Guardian Corp', status: 'Active', lastLogin: '4h ago', created: 'Dec 5, 2025', avatar: 'NJ' },
  { id: 10, name: 'Sofia Reyes', email: 'sofia@securehub.mx', role: 'analyst', org: 'SecureHub MX', status: 'Active', lastLogin: '6h ago', created: 'Nov 28, 2025', avatar: 'SR' },
  { id: 11, name: 'Thomas Wu', email: 'thomas@apexsecurity.sg', role: 'customer', org: 'Apex Security SG', status: 'Active', lastLogin: '1d ago', created: 'Nov 20, 2025', avatar: 'TW' },
  { id: 12, name: 'Amara Osei', email: 'amara@netdefend.gh', role: 'analyst', org: 'NetDefend GH', status: 'Inactive', lastLogin: '3w ago', created: 'Nov 15, 2025', avatar: 'AO' },
]

const roleLabels: Record<string, string> = {
  super_admin: 'Super Admin', platform_admin: 'Platform Admin',
  team_admin: 'Team Admin', analyst: 'Analyst', customer: 'Customer',
}

const roleColors: Record<string, string> = {
  super_admin: 'bg-red-500/10 text-red-500 border-red-500/20',
  platform_admin: 'bg-primary/10 text-primary border-primary/20',
  team_admin: 'bg-accent/10 text-accent border-accent/20',
  analyst: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  customer: 'bg-muted text-muted-foreground border-border',
}

const statusColors: Record<string, string> = {
  Active: 'bg-green-500/10 text-green-500 border-green-500/20',
  Trial: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  Suspended: 'bg-red-500/10 text-red-500 border-red-500/20',
  Inactive: 'bg-muted text-muted-foreground border-border',
}

const roles = ['All Roles', 'team_admin', 'analyst', 'customer']
const statuses = ['All Statuses', 'Active', 'Trial', 'Suspended', 'Inactive']

export default function AdminUsersPage() {
  const [users, setUsers] = useState(initUsers)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('All Roles')
  const [statusFilter, setStatusFilter] = useState('All Statuses')
  const [createOpen, setCreateOpen] = useState(false)

  const filtered = users.filter(u =>
    (u.name.toLowerCase().includes(search.toLowerCase()) ||
     u.email.toLowerCase().includes(search.toLowerCase()) ||
     u.org.toLowerCase().includes(search.toLowerCase())) &&
    (roleFilter === 'All Roles' || u.role === roleFilter) &&
    (statusFilter === 'All Statuses' || u.status === statusFilter)
  )

  const toggleSuspend = (id: number) =>
    setUsers(prev => prev.map(u => u.id === id ? { ...u, status: u.status === 'Suspended' ? 'Active' : 'Suspended' } : u))

  const deleteUser = (id: number) => setUsers(prev => prev.filter(u => u.id !== id))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Platform Users</h1>
          <p className="text-muted-foreground mt-1">Manage all users across every organization on the platform</p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" className="rounded-lg border-foreground/20 h-10">
            <Download className="w-4 h-4 mr-2" />Export
          </Button>
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-10 px-5">
                <UserPlus className="w-4 h-4 mr-2" />Create User
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-card border-foreground/10">
              <DialogHeader>
                <DialogTitle>Create Platform User</DialogTitle>
                <DialogDescription>Add a new user to the platform</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-2">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2"><Label>First Name</Label><Input placeholder="John" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                  <div className="space-y-2"><Label>Last Name</Label><Input placeholder="Doe" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                </div>
                <div className="space-y-2"><Label>Email</Label><Input type="email" placeholder="john@org.com" className="bg-foreground/5 border-foreground/20 rounded-lg" /></div>
                <div className="space-y-2">
                  <Label>Organization</Label>
                  <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                    <option>FinTech Corp</option><option>MedSecure Ltd</option><option>CloudNative IO</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Role</Label>
                  <select className="w-full px-3 py-2 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
                    <option value="customer">Customer</option><option value="analyst">Analyst</option><option value="team_admin">Team Admin</option>
                  </select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateOpen(false)} className="rounded-lg border-foreground/20">Cancel</Button>
                <Button className="bg-primary hover:bg-primary/90 rounded-lg" onClick={() => setCreateOpen(false)}>Create User</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Users', value: users.length, color: 'text-foreground' },
          { label: 'Active', value: users.filter(u => u.status === 'Active').length, color: 'text-green-500' },
          { label: 'Team Admins', value: users.filter(u => u.role === 'team_admin').length, color: 'text-accent' },
          { label: 'Suspended', value: users.filter(u => u.status === 'Suspended').length, color: 'text-red-500' },
        ].map(s => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search users, emails, organizations..." value={search} onChange={e => setSearch(e.target.value)} className="pl-10 bg-foreground/5 border-foreground/20 rounded-lg h-10" />
        </div>
        <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {roles.map(r => <option key={r}>{r}</option>)}
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2 h-10 bg-foreground/5 border border-foreground/20 rounded-lg text-foreground text-sm">
          {statuses.map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      {/* Table */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>All Users</CardTitle>
          <CardDescription>{filtered.length} of {users.length} users</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-foreground/10">
                  {['User', 'Role', 'Organization', 'Status', 'Last Login', 'Created', 'Actions'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(user => (
                  <tr key={user.id} className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary/30 to-accent/30 flex items-center justify-center shrink-0">
                          <span className="text-xs font-bold text-primary">{user.avatar}</span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-foreground">{user.name}</p>
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded border ${roleColors[user.role]}`}>{roleLabels[user.role]}</span>
                    </td>
                    <td className="py-3 px-3 text-sm text-foreground">{user.org}</td>
                    <td className="py-3 px-3">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded border ${statusColors[user.status]}`}>{user.status}</span>
                    </td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{user.lastLogin}</td>
                    <td className="py-3 px-3 text-sm text-muted-foreground">{user.created}</td>
                    <td className="py-3 px-3">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg hover:bg-foreground/10">
                            <MoreHorizontal className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="bg-card border-foreground/10 rounded-lg w-44">
                          <DropdownMenuItem className="cursor-pointer rounded-md"><Edit2 className="w-3.5 h-3.5 mr-2" />Edit User</DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md"><KeyRound className="w-3.5 h-3.5 mr-2" />Reset Password</DropdownMenuItem>
                          <DropdownMenuSeparator className="bg-foreground/10" />
                          <DropdownMenuItem className="cursor-pointer rounded-md" onClick={() => toggleSuspend(user.id)}>
                            <ShieldOff className="w-3.5 h-3.5 mr-2" />{user.status === 'Suspended' ? 'Activate' : 'Suspend'}
                          </DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer rounded-md text-destructive focus:text-destructive focus:bg-destructive/10" onClick={() => deleteUser(user.id)}>
                            <Trash2 className="w-3.5 h-3.5 mr-2" />Delete User
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
