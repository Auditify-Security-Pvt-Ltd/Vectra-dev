'use client'

import { Cloud, CheckCircle, Lock, Network, AlertTriangle, Bug, Shield } from 'lucide-react'

const PLANNED_FEATURES = [
  { icon: Shield,        label: 'AWS Security Assessment',        desc: 'Automated security posture evaluation across all AWS services' },
  { icon: Shield,        label: 'Azure Security Assessment',      desc: 'Comprehensive security review for Azure subscriptions and resources' },
  { icon: Shield,        label: 'GCP Security Assessment',        desc: 'Google Cloud Platform configuration and compliance scanning' },
  { icon: Lock,          label: 'IAM Analysis',                   desc: 'Detect overprivileged roles, unused permissions, and policy violations' },
  { icon: AlertTriangle, label: 'Cloud Misconfiguration Detection', desc: 'Identify exposed storage, open security groups, and insecure defaults' },
  { icon: Network,       label: 'Storage Security',               desc: 'Audit S3, Blob, and GCS buckets for public exposure and encryption' },
  { icon: Bug,           label: 'Cloud Findings',                 desc: 'Centralised findings dashboard across all connected cloud accounts' },
  { icon: CheckCircle,   label: 'Compliance Reporting',           desc: 'CIS Benchmarks, SOC 2, PCI DSS, and ISO 27001 compliance reports' },
]

export default function CloudSecurityPage() {
  return (
    <div className="p-8 max-w-3xl">
      {/* Header */}
      <div className="flex items-start gap-5 mb-10">
        <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
          <Cloud className="w-7 h-7 text-blue-400" />
        </div>
        <div>
          <div className="flex items-center gap-3 mb-1.5">
            <h1 className="text-2xl font-bold text-foreground">Cloud Security</h1>
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
              Coming Soon
            </span>
          </div>
          <p className="text-muted-foreground text-sm leading-relaxed">
            Multi-cloud security assessment, IAM analysis, and misconfiguration detection across AWS, Azure, and GCP.
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
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center shrink-0 mt-0.5">
                  <Icon className="w-4 h-4 text-blue-400" />
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

      {/* Providers */}
      <div className="border border-foreground/8 rounded-lg p-5 bg-foreground/2">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">Supported Providers</p>
        <div className="flex gap-4 flex-wrap">
          {['Amazon Web Services', 'Microsoft Azure', 'Google Cloud Platform'].map((provider) => (
            <div key={provider} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-foreground/10 bg-card">
              <div className="w-2 h-2 rounded-full bg-muted-foreground/40" />
              <span className="text-xs text-muted-foreground">{provider}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
