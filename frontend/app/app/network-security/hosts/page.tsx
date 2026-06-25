'use client'

import { useEffect, useState } from 'react'
import { Server, Search, Wifi, Globe, ChevronDown, ChevronRight } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { useAuth } from '@/context/auth-context'
import { listenToNetworkHosts, type FirestoreNetworkHost, type NetworkPort } from '@/lib/firestore-network-assets'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const PORT_COLOR: Record<number, string> = {
  80: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  443: 'bg-green-500/10 text-green-500 border-green-500/20',
  22: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  3306: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
}

function HostRow({ host }: { host: FirestoreNetworkHost }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border-b border-foreground/5 last:border-0">
      <div
        className="flex items-center gap-4 px-5 py-4 hover:bg-foreground/2 transition-colors cursor-pointer group"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
          host.isWebService ? 'bg-blue-500/10' : 'bg-foreground/5'
        }`}>
          {host.isWebService ? <Globe className="w-4 h-4 text-blue-400" /> : <Server className="w-4 h-4 text-muted-foreground" />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-mono font-semibold text-foreground">{host.ip}</span>
            {host.hostname && <span className="text-xs text-muted-foreground">({host.hostname})</span>}
            {host.isWebService && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-blue-500/10 text-blue-400 border-blue-500/20">
                Web Service
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-xs text-muted-foreground">{host.ports.length} open ports</span>
            <span className="text-xs text-muted-foreground">{formatDate(host.createdAt)}</span>
            {host.technologies.length > 0 && (
              <span className="text-xs text-muted-foreground">{host.technologies.slice(0, 3).join(', ')}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="flex gap-1 flex-wrap max-w-48">
            {host.ports.slice(0, 5).map((p) => (
              <span key={p.port} className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${PORT_COLOR[p.port] ?? 'bg-foreground/8 text-muted-foreground border-foreground/10'}`}>
                {p.port}
              </span>
            ))}
            {host.ports.length > 5 && (
              <span className="text-[10px] text-muted-foreground">+{host.ports.length - 5}</span>
            )}
          </div>
          {expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground/40" /> : <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground" />}
        </div>
      </div>

      {expanded && host.ports.length > 0 && (
        <div className="px-5 pb-4 bg-foreground/1">
          <div className="rounded-lg border border-foreground/8 overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-foreground/8 bg-foreground/3">
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Port</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Protocol</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Service</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Version</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-foreground/5">
                {host.ports.map((p: NetworkPort) => (
                  <tr key={p.port} className="hover:bg-foreground/2">
                    <td className="px-3 py-2 font-mono font-bold text-foreground">{p.port}</td>
                    <td className="px-3 py-2 text-muted-foreground">{p.protocol}</td>
                    <td className="px-3 py-2 text-foreground">{p.service}</td>
                    <td className="px-3 py-2 text-muted-foreground">{p.version || '—'}</td>
                    <td className="px-3 py-2">
                      <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-green-500/10 text-green-500">
                        {p.state}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default function NetworkHostsPage() {
  const { user }  = useAuth()
  const [hosts,   setHosts]  = useState<FirestoreNetworkHost[]>([])
  const [search,  setSearch] = useState('')

  useEffect(() => {
    if (!user) return
    return listenToNetworkHosts(user.uid, setHosts)
  }, [user])

  const filtered = hosts.filter((h) =>
    h.ip.includes(search) ||
    (h.hostname ?? '').toLowerCase().includes(search.toLowerCase()) ||
    h.technologies.some((t) => t.toLowerCase().includes(search.toLowerCase())),
  )

  const webHosts = hosts.filter((h) => h.isWebService).length
  const totalPorts = hosts.reduce((n, h) => n + h.ports.length, 0)

  return (
    <div className="p-8 space-y-6 max-w-5xl">

      <div className="flex items-start gap-4">
        <div className="w-11 h-11 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
          <Server className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Network Hosts</h1>
          <p className="text-sm text-muted-foreground mt-0.5">All discovered hosts across network scans</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Hosts',  value: hosts.length, cls: 'text-foreground' },
          { label: 'Web Services', value: webHosts,     cls: 'text-blue-400'  },
          { label: 'Open Ports',   value: totalPorts,   cls: 'text-violet-400' },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-foreground/10">
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by IP, hostname, or technology…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-background border-foreground/15 h-10"
        />
      </div>

      <Card className="bg-card border-foreground/10">
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="text-center py-16 space-y-3">
              <div className="w-12 h-12 rounded-xl bg-foreground/5 border border-foreground/10 flex items-center justify-center mx-auto">
                <Wifi className="w-6 h-6 text-muted-foreground" />
              </div>
              <p className="text-sm text-muted-foreground">
                {search ? 'No hosts match your search' : 'No hosts discovered yet — start a network scan'}
              </p>
            </div>
          ) : (
            <div>
              {filtered.map((host) => <HostRow key={host.hostId} host={host} />)}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
