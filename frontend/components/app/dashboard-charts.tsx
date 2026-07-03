'use client'

import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer, LineChart, Line,
} from 'recharts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

const RISK_TREND = [
  { date: '1 Jan', critical: 180, high: 240, medium: 180 },
  { date: '8 Jan', critical: 165, high: 220, medium: 160 },
  { date: '15 Jan', critical: 150, high: 200, medium: 140 },
  { date: '22 Jan', critical: 143, high: 190, medium: 130 },
  { date: '29 Jan', critical: 135, high: 175, medium: 120 },
]

const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: 'rgba(0,0,0,0.8)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: '8px',
  },
}

interface ScanActivityEntry {
  date:      string
  completed: number
  failed:    number
  pending:   number
}

export function DashboardCharts({ scanActivity }: { scanActivity: ScanActivityEntry[] }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Scan Activity</CardTitle>
          <CardDescription>Last 7 days of scan operations</CardDescription>
        </CardHeader>
        <CardContent className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={scanActivity}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" stroke="rgba(255,255,255,0.5)" />
              <YAxis stroke="rgba(255,255,255,0.5)" allowDecimals={false} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Legend />
              <Bar dataKey="completed" fill="#8b5cf6" name="Completed" />
              <Bar dataKey="failed"    fill="#ef4444" name="Failed"    />
              <Bar dataKey="pending"   fill="#f97316" name="Pending"   />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card className="bg-card border-foreground/10">
        <CardHeader>
          <CardTitle>Risk Trend</CardTitle>
          <CardDescription>Security findings over time</CardDescription>
        </CardHeader>
        <CardContent className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={RISK_TREND}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" stroke="rgba(255,255,255,0.5)" />
              <YAxis stroke="rgba(255,255,255,0.5)" />
              <Tooltip {...TOOLTIP_STYLE} />
              <Legend />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} name="Critical" />
              <Line type="monotone" dataKey="high"     stroke="#f97316" strokeWidth={2} name="High"     />
              <Line type="monotone" dataKey="medium"   stroke="#eab308" strokeWidth={2} name="Medium"   />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}
