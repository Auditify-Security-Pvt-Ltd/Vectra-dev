'use client'

import { use, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { CardSkeleton } from '@/components/app/loading-states'
import { getCloudFinding, providerLabel } from '@/lib/api-cloud'
import {
  CloudErrorState, ProviderBadge, SeverityBadge, StatusBadge, formatDate, useCloudData,
} from '@/components/cloud/cloud-shared'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4 space-y-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
        {children}
      </CardContent>
    </Card>
  )
}

const SOURCE_LABEL: Record<string, string> = {
  'gcp-configuration-analysis':  'Vectra configuration analysis',
  'gcp-security-command-center': 'Security Command Center',
}

function evidenceValue(v: unknown): string {
  if (v == null || v === '') return '—'
  if (Array.isArray(v)) return v.length ? v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ') : '—'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[9rem_1fr] gap-3 text-sm py-0.5">
      <span className="text-muted-foreground text-xs pt-0.5">{k}</span>
      <span className={`text-foreground break-all ${mono ? 'font-mono text-xs pt-0.5' : ''}`}>{v ?? '—'}</span>
    </div>
  )
}

function SafeLink({ href, children }: { href: string | null | undefined; children: React.ReactNode }) {
  if (!href || !/^https?:\/\//i.test(href)) return null
  return (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-primary hover:underline text-sm">
      {children} <ExternalLink className="w-3 h-3" />
    </a>
  )
}

export default function CloudFindingDetailPage({ params }: { params: Promise<{ findingId: string }> }) {
  const { findingId } = use(params)
  const { data, error, loading } = useCloudData(() => getCloudFinding(findingId), [findingId])
  const [showRaw, setShowRaw] = useState(false)

  const back = (
    <Link href="/app/cloud-security/findings" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
      <ArrowLeft className="w-3.5 h-3.5" /> Cloud Findings
    </Link>
  )

  if (error) return <div className="p-6 space-y-4">{back}<CloudErrorState error={error} title="Finding unavailable" /></div>
  if (loading && !data) return <div className="p-6 space-y-4">{back}<CardSkeleton lines={3} /><CardSkeleton lines={5} /></div>
  if (!data) return null

  const f = data.finding
  const history = f.statusHistory ?? []

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      {back}

      <div className="space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={f.severity} />
          <StatusBadge status={f.status} />
          <ProviderBadge provider={f.provider} />
          {f.findingClass && <span className="text-[10px] font-semibold px-2 py-0.5 rounded border border-foreground/15 text-muted-foreground">{f.findingClass}</span>}
        </div>
        <h1 className="text-xl font-bold text-foreground">{f.title}</h1>
        <p className="text-xs text-muted-foreground">
          {f.providerProduct ?? providerLabel(f.provider)}{f.findingType ? ` · ${f.findingType}` : ''}
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <Section title="Overview">
          <Row k="Severity" v={<>{f.severity.toUpperCase()}{f.providerSeverity && <span className="text-xs text-muted-foreground"> (provider: {f.providerSeverity})</span>}</>} />
          <Row k="Status" v={<>{f.status}{f.providerStatus && <span className="text-xs text-muted-foreground"> (provider: {f.providerStatus})</span>}</>} />
          <Row k="Provider" v={providerLabel(f.provider)} />
          <Row k="Integration" v={data.integration?.displayName} />
          <Row k="Finding type" v={f.findingType} />
          {f.source && <Row k="Source" v={SOURCE_LABEL[f.source] ?? f.source} />}
          {f.category && <Row k="Category" v={f.category} />}
          {f.compliance?.securityControlId && <Row k="Control" v={f.compliance.securityControlId} mono />}
          {f.compliance?.status && <Row k="Compliance" v={f.compliance.status} />}
        </Section>

        <Section title="Affected resource">
          <Row k="Resource" v={f.resourceName} />
          <Row k="Resource ID" v={f.resourceId} mono />
          <Row k="Resource type" v={f.resourceType} />
          <Row k={f.provider === 'aws' ? 'Account' : 'Project'} v={f.accountId} mono />
          <Row k="Region" v={f.region} />
          {data.asset && <Row k="Asset" v={`${data.asset.openFindingCount} open of ${data.asset.findingCount} findings on this resource`} />}
          {data.asset && Object.keys(data.asset.tags ?? {}).length > 0 && (
            <Row k="Tags" v={<span className="flex flex-wrap gap-1">{Object.entries(data.asset.tags).map(([k, v]) => (
              <span key={k} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 border border-foreground/10">{k}={v}</span>
            ))}</span>} />
          )}
        </Section>
      </div>

      <Section title="Security information">
        {f.description ? <p className="text-sm text-foreground whitespace-pre-wrap">{f.description}</p> : <p className="text-sm text-muted-foreground">No description provided.</p>}
        {(f.cveIds?.length ?? 0) > 0 && (
          <div className="pt-2">
            <Row k="CVE" v={f.cveIds.join(', ')} mono />
            <Row k="CVSS" v={f.cvssScore != null ? `${f.cvssScore.toFixed(1)}${f.cvssVector ? ` · ${f.cvssVector}` : ''}` : null} mono />
          </div>
        )}
        {(f.affectedPackages?.length ?? 0) > 0 && (
          <div className="overflow-x-auto pt-2">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-muted-foreground border-b border-foreground/10">
                  {['Package', 'Installed', 'Fixed in', 'CVE'].map((h) => <th key={h} className="text-left py-1.5 pr-3 font-semibold">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {f.affectedPackages.map((p, i) => (
                  <tr key={i} className="border-b border-foreground/5 last:border-0 font-mono">
                    <td className="py-1.5 pr-3">{p.name}</td>
                    <td className="py-1.5 pr-3">{p.version ?? '—'}</td>
                    <td className="py-1.5 pr-3 text-green-500">{p.fixedInVersion ?? '—'}</td>
                    <td className="py-1.5 pr-3">{p.cve ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(f.compliance?.relatedRequirements?.length ?? 0) > 0 && (
          <Row k="Requirements" v={f.compliance.relatedRequirements!.join(', ')} />
        )}
      </Section>

      {f.evidence && Object.keys(f.evidence).length > 0 && (
        <Section title="Evidence">
          <p className="text-xs text-muted-foreground">Configuration read from {providerLabel(f.provider)} that this finding is based on.</p>
          {Object.entries(f.evidence).map(([k, v]) => (
            <Row key={k} k={k.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase())} v={evidenceValue(v)} mono />
          ))}
        </Section>
      )}

      <Section title="Remediation">
        {f.recommendation ? <p className="text-sm text-foreground whitespace-pre-wrap">{f.recommendation}</p>
          : <p className="text-sm text-muted-foreground">The provider did not include a recommendation for this finding.</p>}
        <SafeLink href={f.remediationUrl}>Provider remediation guidance</SafeLink>
      </Section>

      <div className="grid lg:grid-cols-2 gap-4">
        <Section title="Timeline">
          <Row k="First observed" v={formatDate(f.firstObservedAt)} />
          <Row k="Last observed" v={formatDate(f.lastObservedAt)} />
          <Row k="First seen in Vectra" v={formatDate(f.firstSeenAt)} />
          <Row k="Last synced" v={formatDate(f.lastSeenAt)} />
          {f.resolvedAt && <Row k="Resolved" v={`${formatDate(f.resolvedAt)}${f.resolvedReason === 'no_longer_reported' ? ' (no longer reported by provider)' : ''}`} />}
          {history.length > 0 && (
            <ol className="pt-2 space-y-1 border-l border-foreground/10 pl-3">
              {history.map((h, i) => (
                <li key={i} className="text-xs text-muted-foreground">
                  <span className="text-foreground capitalize">{h.status}</span> · {formatDate(h.at)}
                  {h.source === 'no_longer_reported' ? ' · no longer reported' : ' · reported by provider'}
                </li>
              ))}
            </ol>
          )}
        </Section>

        <Section title="External reference">
          <Row k="Provider finding ID" v={f.providerFindingId} mono />
          <SafeLink href={f.sourceUrl}>View in {providerLabel(f.provider)}</SafeLink>
          {!f.sourceUrl && (
            <p className="text-xs text-muted-foreground">
              {f.source === 'gcp-configuration-analysis'
                ? 'Detected by Vectra from the resource configuration; there is no provider console link.'
                : 'The provider did not include a link for this finding.'}
            </p>
          )}
        </Section>
      </div>

      {f.providerMetadata != null && (
        <Card className="bg-card border-foreground/10">
          <CardContent className="p-4">
            <button className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground" onClick={() => setShowRaw(!showRaw)}>
              {showRaw ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />} Provider data
            </button>
            {showRaw && (
              <pre className="mt-3 text-[11px] font-mono bg-foreground/5 border border-foreground/10 rounded-md p-3 max-h-[28rem] overflow-auto whitespace-pre-wrap break-all">
                {JSON.stringify(f.providerMetadata, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
