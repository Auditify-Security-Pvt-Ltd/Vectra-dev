'use client'

import { Wifi, Server, Network, Zap, AlertTriangle, Bug, Settings } from 'lucide-react'

const PLANNED_FEATURES = [
  { icon: Server,        label: 'Host Discovery',           desc: 'Enumerate live hosts and reachable endpoints across IP ranges' },
  { icon: Network,       label: 'IP Range Management',      desc: 'Define and track CIDR ranges for continuous network monitoring' },
  { icon: Zap,           label: 'Port Scanning',            desc: 'TCP/UDP port scanning with service banner grabbing and fingerprinting' },
  { icon: Settings,      label: 'Service Enumeration',      desc: 'Identify running services, versions, and protocol details per host' },
  { icon: AlertTriangle, label: 'Vulnerability Detection',  desc: 'Match discovered services against known vulnerability signatures' },
  { icon: Bug,           label: 'Network CVE Correlation',  desc: 'Correlate discovered service versions with NVD CVE database' },
]

export default function NetworkSecurityPage() {
  return (
    <div className="p-8 max-w-3xl">
      {/* Header */}
      <div className="flex items-start gap-5 mb-10">
        <div className="w-14 h-14 rounded-2xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
          <Wifi className="w-7 h-7 text-violet-400" />
        </div>
        <div>
          <div className="flex items-center gap-3 mb-1.5">
            <h1 className="text-2xl font-bold text-foreground">Network Security</h1>
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-violet-500/10 text-violet-400 border border-violet-500/20">
              Coming Soon
            </span>
          </div>
          <p className="text-muted-foreground text-sm leading-relaxed">
            Active network scanning, host discovery, service enumeration, and vulnerability detection across your internal and external infrastructure.
          </p>
        </div>
      </div>

      {/* Roadmap */}
      <div className="mb-6">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">Planned Features</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {PLANNED_FEATURES.map((feature) => {
            const Icon = feature.icon
            return (
              <div
                key={feature.label}
                className="flex items-start gap-3 p-4 rounded-lg border border-foreground/8 bg-foreground/2 hover:bg-foreground/4 transition-colors"
              >
                <div className="w-8 h-8 rounded-lg bg-violet-500/10 flex items-center justify-center shrink-0 mt-0.5">
                  <Icon className="w-4 h-4 text-violet-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">{feature.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{feature.desc}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Scan capability preview */}
      <div className="border border-foreground/8 rounded-lg p-5 bg-foreground/2">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">Scan Capabilities</p>
        <div className="flex gap-3 flex-wrap">
          {['TCP SYN Scan', 'UDP Scan', 'Service Version Detection', 'OS Fingerprinting', 'Script Engine', 'CVE Matching'].map((cap) => (
            <div key={cap} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-foreground/10 bg-card">
              <div className="w-2 h-2 rounded-full bg-muted-foreground/40" />
              <span className="text-xs text-muted-foreground">{cap}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
