import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppStore } from '@/store/useAppStore'
import type { Severity } from '@/types'
import { SEVERITY_ORDER, ORDERED_SEVERITIES } from '@/types'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Server, AlertTriangle } from 'lucide-react'

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#6b7280',
  UNKNOWN: '#9ca3af',
}

interface AssetRisk {
  asset: string
  totalFindings: number
  bySeverity: Record<Severity, number>
  uniqueCVEs: number
  environments: string[]
  maxSeverity: Severity
  riskScore: number
  hasFix: number
  noFix: number
}

export function AssetRiskPage() {
  const { findings } = useAppStore()

  const assetRisks = useMemo<AssetRisk[]>(() => {
    const map = new Map<string, AssetRisk>()

    for (const f of findings) {
      const key = f.assetName ?? '(unknown)'
      if (!map.has(key)) {
        map.set(key, {
          asset: key,
          totalFindings: 0,
          bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 },
          uniqueCVEs: 0,
          environments: [],
          maxSeverity: 'UNKNOWN',
          riskScore: 0,
          hasFix: 0,
          noFix: 0,
        })
      }
      const ar = map.get(key)!
      ar.totalFindings++
      ar.bySeverity[f.severity] = (ar.bySeverity[f.severity] ?? 0) + 1
      if (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[ar.maxSeverity]) ar.maxSeverity = f.severity
      if (f.environment && !ar.environments.includes(f.environment)) ar.environments.push(f.environment)
      ar.riskScore = Math.max(ar.riskScore, f.riskScore ?? 0)
      if (f.fixedVersion) ar.hasFix++
      else ar.noFix++
    }

    // Compute unique CVEs per asset
    for (const ar of map.values()) {
      const cves = new Set(findings.filter((f) => (f.assetName ?? '(unknown)') === ar.asset).map((f) => f.cveId))
      ar.uniqueCVEs = cves.size
    }

    return Array.from(map.values()).sort((a, b) => {
      if (SEVERITY_ORDER[a.maxSeverity] !== SEVERITY_ORDER[b.maxSeverity]) {
        return SEVERITY_ORDER[a.maxSeverity] - SEVERITY_ORDER[b.maxSeverity]
      }
      return b.riskScore - a.riskScore
    })
  }, [findings])

  // Chart data: top 10 assets by total findings
  const chartData = useMemo(() => {
    return assetRisks.slice(0, 10).map((ar) => ({
      asset: ar.asset.length > 20 ? ar.asset.slice(0, 18) + '…' : ar.asset,
      fullAsset: ar.asset,
      ...Object.fromEntries(ORDERED_SEVERITIES.filter((s) => s !== 'NONE').map((s) => [s, ar.bySeverity[s] ?? 0])),
    }))
  }, [assetRisks])

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
        <p className="text-muted-foreground">No findings loaded yet.</p>
        <Button variant="outline" asChild><Link to="/">Upload a report</Link></Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <Server className="h-6 w-6" />
          Asset Risk
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Vulnerability concentration by asset — find your most exposed systems
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold">{assetRisks.length}</div>
            <p className="text-xs text-muted-foreground">Total Assets</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold text-red-600">
              {assetRisks.filter((a) => a.maxSeverity === 'CRITICAL').length}
            </div>
            <p className="text-xs text-muted-foreground">Critical Assets</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold text-orange-600">
              {assetRisks.filter((a) => a.noFix > 0).length}
            </div>
            <p className="text-xs text-muted-foreground">Assets w/ No-Fix CVEs</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold">
              {assetRisks.length > 0 ? Math.round(findings.length / assetRisks.length) : 0}
            </div>
            <p className="text-xs text-muted-foreground">Avg Findings/Asset</p>
          </CardContent>
        </Card>
      </div>

      {/* Stacked bar chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top 10 Assets by Finding Count</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 60 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis
                dataKey="asset"
                tick={{ fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                angle={-35}
                textAnchor="end"
                interval={0}
              />
              <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{ fontSize: 12, borderRadius: 6 }}
                formatter={(val, name) => [val, name]}
              />
              {ORDERED_SEVERITIES.filter((s) => s !== 'NONE' && s !== 'UNKNOWN').map((s) => (
                <Bar key={s} dataKey={s} stackId="a" fill={SEVERITY_COLORS[s]} radius={s === 'LOW' ? [4, 4, 0, 0] : [0, 0, 0, 0]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Detailed asset table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assets at Risk — Ranked</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">#</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Asset</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Max Severity</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Risk</th>
                  <th className="text-center px-3 py-2 text-xs font-medium text-muted-foreground">Crit</th>
                  <th className="text-center px-3 py-2 text-xs font-medium text-muted-foreground">High</th>
                  <th className="text-center px-3 py-2 text-xs font-medium text-muted-foreground">Med</th>
                  <th className="text-center px-3 py-2 text-xs font-medium text-muted-foreground">Low</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">CVEs</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Env</th>
                  <th className="text-center px-3 py-2 text-xs font-medium text-muted-foreground">No Fix</th>
                </tr>
              </thead>
              <tbody>
                {assetRisks.map((ar, i) => (
                  <tr key={ar.asset} className={`border-t ${i % 2 ? 'bg-muted/10' : ''} hover:bg-muted/20`}>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{i + 1}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        {(ar.bySeverity.CRITICAL > 0) && <AlertTriangle className="h-3.5 w-3.5 text-red-500 shrink-0" />}
                        <Link
                          to={`/findings`}
                          className="font-mono text-xs font-medium text-primary hover:underline truncate max-w-[200px]"
                          title={ar.asset}
                        >
                          {ar.asset}
                        </Link>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={ar.maxSeverity} />
                    </td>
                    <td className="px-3 py-2 text-right">
                      <span className={`font-mono text-xs font-bold ${
                        ar.riskScore >= 70 ? 'text-red-600' : ar.riskScore >= 40 ? 'text-orange-600' : 'text-green-600'
                      }`}>{ar.riskScore}</span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      {ar.bySeverity.CRITICAL > 0 ? (
                        <span className="text-xs font-bold text-red-600">{ar.bySeverity.CRITICAL}</span>
                      ) : <span className="text-xs text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {ar.bySeverity.HIGH > 0 ? (
                        <span className="text-xs font-semibold text-orange-600">{ar.bySeverity.HIGH}</span>
                      ) : <span className="text-xs text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {ar.bySeverity.MEDIUM > 0 ? (
                        <span className="text-xs text-yellow-600">{ar.bySeverity.MEDIUM}</span>
                      ) : <span className="text-xs text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {ar.bySeverity.LOW > 0 ? (
                        <span className="text-xs text-blue-600">{ar.bySeverity.LOW}</span>
                      ) : <span className="text-xs text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-right text-xs font-medium">{ar.uniqueCVEs}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {ar.environments.slice(0, 2).map((e) => (
                          <Badge key={e} variant="outline" className="text-[10px] px-1 py-0">{e}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-center">
                      {ar.noFix > 0 ? (
                        <span className="text-xs font-semibold text-red-600">{ar.noFix}</span>
                      ) : <span className="text-xs text-green-600">0</span>}
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
