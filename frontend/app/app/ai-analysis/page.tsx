'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Sparkles, TrendingUp, AlertTriangle } from 'lucide-react'

export default function AIAnalysisPage() {
  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">AI Security Analysis</h1>
          <p className="text-muted-foreground mt-1">Powered security insights and recommendations</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-11 px-6">
          <Sparkles className="w-4 h-4 mr-2" />
          Run Analysis
        </Button>
      </div>

      {/* AI Insights */}
      <Card className="bg-card border-foreground/10 border-l-4 border-l-primary">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-primary" />
            AI-Powered Insights
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="p-4 bg-primary/10 rounded-lg border border-primary/20">
              <p className="font-medium text-foreground mb-1">🎯 Risk Priority Analysis</p>
              <p className="text-sm text-muted-foreground">
                Based on your infrastructure, critical SQL injection vulnerabilities in API endpoints pose the highest risk. 
                We recommend immediate patching. Estimated impact: High.
              </p>
            </div>
            <div className="p-4 bg-accent/10 rounded-lg border border-accent/20">
              <p className="font-medium text-foreground mb-1">🔗 Attack Path Detection</p>
              <p className="text-sm text-muted-foreground">
                Our AI identified 3 potential attack chains that could lead to data exfiltration. 
                These require coordinated remediation efforts across your infrastructure.
              </p>
            </div>
            <div className="p-4 bg-orange-500/10 rounded-lg border border-orange-500/20">
              <p className="font-medium text-foreground mb-1">📈 Threat Trend Analysis</p>
              <p className="text-sm text-muted-foreground">
                Cloud misconfigurations are trending 23% higher in your industry. 
                We recommend prioritizing IAM policy reviews and S3 bucket access controls.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Risk Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Risk Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-500">7.2/10</div>
            <p className="text-xs text-muted-foreground mt-2">Moderate - Requires attention</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              CVSS Average
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">8.1</div>
            <p className="text-xs text-muted-foreground mt-2">High severity baseline</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-foreground/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground">12</div>
            <p className="text-xs text-muted-foreground mt-2">AI-generated actions</p>
          </CardContent>
        </Card>
      </div>

      {/* Recommendations */}
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>AI-Generated Recommendations</CardTitle>
          <CardDescription>Priority actions based on your security posture</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {[
            { priority: 'Critical', action: 'Patch SQL injection vulnerability in /api/users endpoint', effort: 'Low', impact: 'High' },
            { priority: 'High', action: 'Review and restrict IAM policies for overprivileged accounts', effort: 'Medium', impact: 'High' },
            { priority: 'High', action: 'Enable encryption at rest for all S3 buckets', effort: 'Low', impact: 'High' },
            { priority: 'Medium', action: 'Update jQuery library to latest secure version', effort: 'Low', impact: 'Medium' },
            { priority: 'Medium', action: 'Implement WAF rules for common attack patterns', effort: 'High', impact: 'High' },
            { priority: 'Low', action: 'Update SSL/TLS certificate for improved configuration', effort: 'Low', impact: 'Low' },
          ].map((rec, idx) => (
            <div
              key={idx}
              className="border border-foreground/10 rounded-lg p-4 hover:bg-foreground/5 transition-colors"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`text-xs font-medium px-2 py-1 rounded ${
                      rec.priority === 'Critical'
                        ? 'bg-red-500/10 text-red-500'
                        : rec.priority === 'High'
                        ? 'bg-orange-500/10 text-orange-500'
                        : 'bg-yellow-500/10 text-yellow-500'
                    }`}>
                      {rec.priority}
                    </span>
                  </div>
                  <p className="font-medium text-foreground">{rec.action}</p>
                </div>
                <Button size="sm" className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg h-8">
                  Review
                </Button>
              </div>
              <div className="flex gap-6 text-xs text-muted-foreground">
                <span>Effort: {rec.effort}</span>
                <span>Impact: {rec.impact}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
