import { Link } from 'react-router-dom'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Separator } from '@/components/ui/separator'
import { useAppStore } from '@/store/useAppStore'
import type { Severity } from '@/types'
import { SEVERITY_ORDER } from '@/types'

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#6b7280',
  UNKNOWN: '#9ca3af',
}

export function ReportPage() {
  const { findings, metrics, cveGroups, uploads } = useAppStore()

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
        <p className="text-muted-foreground">No findings loaded yet.</p>
        <Button variant="outline" asChild>
          <Link to="/">Upload a report</Link>
        </Button>
      </div>
    )
  }

  const severityData = (Object.entries(metrics.severityCounts) as [Severity, number][])
    .filter(([, count]) => count > 0)
    .sort((a, b) => SEVERITY_ORDER[a[0]] - SEVERITY_ORDER[b[0]])
    .map(([severity, count]) => ({ severity, count }))

  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })

  return (
    <div className="max-w-4xl mx-auto space-y-10 py-6">
      {/* Header */}
      <div className="border-b pb-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Vulnerability Report</h1>
            <p className="text-muted-foreground mt-1">{reportDate}</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => window.print()}>
            Print / Export PDF
          </Button>
        </div>
        <div className="mt-4 text-sm text-muted-foreground">
          Source files: {uploads.map((u) => u.fileName).join(', ')}
        </div>
      </div>

      {/* Executive Summary */}
      <section>
        <h2 className="text-xl font-semibold mb-4">Executive Summary</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total Findings', value: metrics.totalFindings },
            { label: 'Unique CVEs', value: metrics.uniqueCVEs },
            { label: 'Critical', value: metrics.criticalFindings, highlight: metrics.criticalFindings > 0 },
            { label: 'Affected Assets', value: metrics.affectedAssets },
          ].map(({ label, value, highlight }) => (
            <div key={label} className="rounded-lg border p-4 text-center">
              <div className={`text-3xl font-bold ${highlight ? 'text-red-600' : ''}`}>
                {value.toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground mt-1">{label}</div>
            </div>
          ))}
        </div>
        <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
          This report was generated from {uploads.length} uploaded file(s) containing{' '}
          {metrics.totalFindings.toLocaleString()} total vulnerability findings across{' '}
          {metrics.affectedAssets.toLocaleString()} unique assets.
          {metrics.criticalFindings > 0 && (
            <span className="text-red-600 font-medium">
              {' '}
              {metrics.criticalFindings} critical-severity findings require immediate attention.
            </span>
          )}
        </p>
      </section>

      <Separator />

      {/* Severity Distribution */}
      <section>
        <h2 className="text-xl font-semibold mb-4">Severity Distribution</h2>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={severityData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis dataKey="severity" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{
                background: 'white',
                border: '1px solid #e5e7eb',
                borderRadius: '6px',
                fontSize: '12px',
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {severityData.map((entry) => (
                <Cell
                  key={entry.severity}
                  fill={SEVERITY_COLORS[entry.severity as Severity] ?? '#9ca3af'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </section>

      <Separator />

      {/* Top Vulnerabilities */}
      <section>
        <h2 className="text-xl font-semibold mb-4">Top Vulnerabilities</h2>
        <div className="rounded-md border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">CVE ID</th>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">Severity</th>
                <th className="text-right px-4 py-2.5 font-medium text-xs text-muted-foreground">Findings</th>
                <th className="text-right px-4 py-2.5 font-medium text-xs text-muted-foreground">Affected Assets</th>
              </tr>
            </thead>
            <tbody>
              {metrics.topCVEs.slice(0, 20).map(({ cveId, count, severity }, i) => {
                const group = cveGroups.find((g) => g.cveId === cveId)
                return (
                  <tr key={cveId} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
                    <td className="px-4 py-2 font-mono text-xs font-medium">{cveId}</td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={severity} />
                    </td>
                    <td className="px-4 py-2 text-right text-xs">{count}</td>
                    <td className="px-4 py-2 text-right text-xs">{group?.affectedAssets ?? 0}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <Separator />

      {/* Most Affected Assets */}
      <section>
        <h2 className="text-xl font-semibold mb-4">Most Affected Assets</h2>
        <div className="rounded-md border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">Asset</th>
                <th className="text-right px-4 py-2.5 font-medium text-xs text-muted-foreground">Findings</th>
              </tr>
            </thead>
            <tbody>
              {metrics.topAssets.map(({ asset, count }, i) => (
                <tr key={asset} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
                  <td className="px-4 py-2 font-mono text-xs">{asset}</td>
                  <td className="px-4 py-2 text-right text-xs">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <Separator />

      {/* Appendix */}
      <section>
        <h2 className="text-xl font-semibold mb-4">Appendix — All CVEs</h2>
        <div className="rounded-md border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">CVE ID</th>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">Severity</th>
                <th className="text-right px-4 py-2.5 font-medium text-xs text-muted-foreground">Findings</th>
                <th className="text-right px-4 py-2.5 font-medium text-xs text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 font-medium text-xs text-muted-foreground">Packages</th>
              </tr>
            </thead>
            <tbody>
              {cveGroups.map(({ cveId, severity, findings: cveFindings, affectedAssets, packages }, i) => (
                <tr key={cveId} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
                  <td className="px-4 py-2 font-mono text-xs font-medium">{cveId}</td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={severity} />
                  </td>
                  <td className="px-4 py-2 text-right text-xs">{cveFindings.length}</td>
                  <td className="px-4 py-2 text-right text-xs">{affectedAssets}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[200px]">
                    {packages.join(', ') || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
