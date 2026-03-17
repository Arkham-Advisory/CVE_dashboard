import { useMemo, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ReChartsTooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  Legend,
  ScatterChart,
  Scatter,
  ZAxis,
} from 'recharts'
import {
  BarChart2,
  PieChart as PieIcon,
  Expand,
  Save,
  Share2,
  Trash2,
  RotateCcw,
  Check,
  Plus,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useAppStore } from '@/store/useAppStore'
import { useAnalyticsStore } from '@/store/useAnalyticsStore'
import type {
  Finding,
  DimensionKey,
  MetricKey,
  ChartType,
  Severity,
} from '@/types'
import { SEVERITY_ORDER } from '@/types'

// ── Constants ────────────────────────────────────────────────────────────────

const DIMENSION_LABELS: Record<DimensionKey, string> = {
  severity: 'Severity',
  account: 'Account',
  region: 'AWS Region',
  packageName: 'Package',
  assetType: 'Asset Type',
  assetName: 'Asset Name',
  sourceFile: 'Source File',
  cveYear: 'CVE Year',
  cveId: 'CVE ID',
  sla: 'SLA / Due Date',
  environment: 'Environment',
  findingType: 'Finding Type',
  treatment: 'Treatment',
  exploitAvailable: 'Exploit Available',
  riskPriority: 'Risk Priority',
}

const METRIC_LABELS: Record<MetricKey, string> = {
  findings: 'Total Findings',
  uniqueCVEs: 'Unique CVEs',
  affectedAssets: 'Affected Assets',
  fixableFindings: 'Fixable Findings',
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#6b7280',
  UNKNOWN: '#9ca3af',
}

const PALETTE = [
  '#6366f1', '#f43f5e', '#10b981', '#f59e0b', '#3b82f6',
  '#8b5cf6', '#14b8a6', '#ef4444', '#84cc16', '#fb923c',
]

// ── Data extraction ───────────────────────────────────────────────────────────

function getDimensionValue(f: Finding, dim: DimensionKey): string {
  switch (dim) {
    case 'severity': return f.severity
    case 'account': return f.accountName ?? f.account ?? '(none)'
    case 'region': return f.region ?? '(none)'
    case 'packageName': return f.packageName ?? '(none)'
    case 'assetType': return f.assetType ?? '(none)'
    case 'assetName': return f.assetName ?? '(none)'
    case 'sourceFile': return f.sourceFile
    case 'cveYear': return f.cveId.split('-')[1] ?? '(unknown)'
    case 'cveId': return f.cveId
    case 'environment': return f.environment ?? '(none)'
    case 'findingType': return f.findingType ?? '(none)'
    case 'treatment': return f.treatment ?? '(none)'
    case 'exploitAvailable': return f.exploitKnown ? 'Known Exploited' : f.exploitAvailable ? 'Exploit Available' : f.exploitPoC ? 'PoC Only' : 'No Exploit'
    case 'riskPriority': return f.priorityLabel ?? 'MONITOR'
    case 'sla': {
      if (!f.sla) return '(no SLA)'
      const d = new Date(f.sla)
      if (isNaN(d.getTime())) return f.sla
      // Bucket into month periods for grouping
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`
    }
    default: return '(none)'
  }
}

interface AggregatedRow {
  group: string
  findings: number
  uniqueCVEs: number
  affectedAssets: number
  fixableFindings: number
  stacks?: Record<string, number>
}

function aggregateFindings(
  findings: Finding[],
  groupBy: DimensionKey,
  metric: MetricKey,
  stackBy?: DimensionKey,
  topN = 20,
): AggregatedRow[] {
  const map = new Map<string, { findings: Finding[]; stacks: Map<string, Finding[]> }>()

  for (const f of findings) {
    const key = getDimensionValue(f, groupBy)
    if (!map.has(key)) map.set(key, { findings: [], stacks: new Map() })
    const bucket = map.get(key)!
    bucket.findings.push(f)
    if (stackBy) {
      const sv = getDimensionValue(f, stackBy)
      if (!bucket.stacks.has(sv)) bucket.stacks.set(sv, [])
      bucket.stacks.get(sv)!.push(f)
    }
  }

  const rows: AggregatedRow[] = Array.from(map.entries()).map(([group, { findings: fs, stacks }]) => {
    const affectedAssets = new Set(fs.map((f) => f.assetName).filter(Boolean)).size
    const uniqueCVEs = new Set(fs.map((f) => f.cveId)).size
    const fixableFindings = fs.filter((f) => !!f.fixedVersion).length

    const stackData: Record<string, number> = stackBy
      ? Object.fromEntries(
          Array.from(stacks.entries()).map(([sv, sfs]) => {
            switch (metric) {
              case 'uniqueCVEs': return [sv, new Set(sfs.map((f) => f.cveId)).size]
              case 'affectedAssets': return [sv, new Set(sfs.map((f) => f.assetName).filter(Boolean)).size]
              case 'fixableFindings': return [sv, sfs.filter((f) => !!f.fixedVersion).length]
              default: return [sv, sfs.length]
            }
          }),
        )
      : {}

    return {
      group,
      findings: fs.length,
      uniqueCVEs,
      affectedAssets,
      fixableFindings,
      ...(stackBy ? { stacks: stackData } : {}),
    }
  })

  // Sort by current metric desc — but always use severity canonical order when groupBy=severity
  if (groupBy === 'severity') {
    rows.sort((a, b) => (SEVERITY_ORDER[a.group as Severity] ?? 99) - (SEVERITY_ORDER[b.group as Severity] ?? 99))
  } else {
    rows.sort((a, b) => b[metric] - a[metric])
  }

  return rows.slice(0, topN)
}

// ── Pivot Table ───────────────────────────────────────────────────────────────

interface PivotTableProps {
  rows: AggregatedRow[]
  metric: MetricKey
  stackKeys: string[]
}

function PivotTable({ rows, stackKeys }: PivotTableProps) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">No data</p>

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border rounded-md overflow-hidden">
        <thead className="bg-muted/50">
          <tr>
            <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Group</th>
            {stackKeys.length > 0
              ? stackKeys.map((k) => (
                  <th key={k} className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">
                    {k}
                  </th>
                ))
              : (
                <>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Findings</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Unique CVEs</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Assets</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Fixable</th>
                  <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground">Fix %</th>
                </>
              )}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.group} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
              <td className="px-3 py-2 font-medium text-xs">
                {row.group === 'CRITICAL' || row.group === 'HIGH' || row.group === 'MEDIUM' || row.group === 'LOW' ? (
                  <Badge variant={row.group.toLowerCase() as 'critical' | 'high' | 'medium' | 'low'}>
                    {row.group}
                  </Badge>
                ) : (
                  row.group
                )}
              </td>
              {stackKeys.length > 0
                ? stackKeys.map((k) => (
                    <td key={k} className="px-3 py-2 text-right text-xs">
                      {(row.stacks?.[k] ?? 0).toLocaleString()}
                    </td>
                  ))
                : (
                  <>
                    <td className="px-3 py-2 text-right text-xs font-medium">{row.findings.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right text-xs">{row.uniqueCVEs.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right text-xs">{row.affectedAssets.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right text-xs text-green-600">{row.fixableFindings.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right text-xs text-muted-foreground">
                      {row.findings > 0 ? Math.round((row.fixableFindings / row.findings) * 100) : 0}%
                    </td>
                  </>
                )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Bar Chart ─────────────────────────────────────────────────────────────────

function AnalyticsBarChart({
  data,
  metric,
  groupBy,
  stackKeys,
}: {
  data: AggregatedRow[]
  metric: MetricKey
  groupBy: DimensionKey
  stackKeys: string[]
}) {
  const isSeverityGroup = groupBy === 'severity'

  if (stackKeys.length > 0) {
    return (
      <ResponsiveContainer width="100%" height={340}>
        <BarChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 40 }}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis dataKey="group" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} angle={-30} textAnchor="end" interval={0} />
          <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
          <ReChartsTooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
          <Legend />
          {stackKeys.map((k, i) => (
            <Bar
              key={k}
              dataKey={`stacks.${k}`}
              name={k}
              stackId="a"
              fill={PALETTE[i % PALETTE.length]}
              radius={i === stackKeys.length - 1 ? [4, 4, 0, 0] : [0, 0, 0, 0]}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={340}>
      <BarChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 40 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          dataKey="group"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          angle={-30}
          textAnchor="end"
          interval={0}
        />
        <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
        <ReChartsTooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
        <Bar dataKey={metric} radius={[4, 4, 0, 0]} name={METRIC_LABELS[metric]}>
          {data.map((entry, i) => (
            <Cell
              key={entry.group}
              fill={
                isSeverityGroup
                  ? SEVERITY_COLORS[entry.group as Severity] ?? PALETTE[i % PALETTE.length]
                  : PALETTE[i % PALETTE.length]
              }
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// ── Pie Chart ────────────────────────────────────────────────────────────────

function AnalyticsPieChart({
  data,
  metric,
  groupBy,
}: {
  data: AggregatedRow[]
  metric: MetricKey
  groupBy: DimensionKey
}) {
  const isSeverityGroup = groupBy === 'severity'
  const pieData = data.map((d, i) => ({
    name: d.group,
    value: d[metric],
    fill: isSeverityGroup
      ? SEVERITY_COLORS[d.group as Severity] ?? PALETTE[i % PALETTE.length]
      : PALETTE[i % PALETTE.length],
  }))

  return (
    <ResponsiveContainer width="100%" height={340}>
      <PieChart>
        <Pie
          data={pieData}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="45%"
          outerRadius={120}
          label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
          labelLine={false}
        >
          {pieData.map((entry, i) => (
            <Cell key={i} fill={entry.fill} />
          ))}
        </Pie>
        <ReChartsTooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}

// ── Analytics Scatter (Bubble) Chart ─────────────────────────────────────────
// Both X and Y axes are categorical dimensions; bubble size = a metric.
// We map each distinct dim-value to a numeric index for Recharts positioning.

function AnalyticsScatterChart({
  findings,
  xDim,
  yDim,
  sizeMetric,
}: {
  findings: Finding[]
  xDim: DimensionKey
  yDim: DimensionKey
  sizeMetric: MetricKey
}) {
  // Build cross-product aggregation: (xVal × yVal) → metric
  const { points, xLabels, yLabels } = useMemo(() => {
    const map = new Map<string, Finding[]>()
    for (const f of findings) {
      const xv = getDimensionValue(f, xDim)
      const yv = getDimensionValue(f, yDim)
      const key = `${xv}\x00${yv}`
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(f)
    }
    const xSet = Array.from(new Set(findings.map((f) => getDimensionValue(f, xDim))))
    const ySet = Array.from(new Set(findings.map((f) => getDimensionValue(f, yDim))))
    const pts = Array.from(map.entries()).map(([key, fs]) => {
      const [xLabel, yLabel] = key.split('\x00')
      let z: number
      switch (sizeMetric) {
        case 'uniqueCVEs': z = new Set(fs.map((f) => f.cveId)).size; break
        case 'affectedAssets': z = new Set(fs.map((f) => f.assetName).filter(Boolean)).size; break
        case 'fixableFindings': z = fs.filter((f) => !!f.fixedVersion).length; break
        default: z = fs.length
      }
      return { xLabel, yLabel, xIdx: xSet.indexOf(xLabel), yIdx: ySet.indexOf(yLabel), z: Math.max(z, 1), metricVal: z }
    })
    return { points: pts, xLabels: xSet, yLabels: ySet }
  }, [findings, xDim, yDim, sizeMetric])

  if (points.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-12">No data</p>
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(360, yLabels.length * 40 + 100)}>
      <ScatterChart margin={{ top: 20, right: 30, left: 60, bottom: 60 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          type="number"
          dataKey="xIdx"
          name={DIMENSION_LABELS[xDim]}
          domain={[-0.5, xLabels.length - 0.5]}
          ticks={xLabels.map((_, i) => i)}
          tickFormatter={(v: number) => xLabels[v] ?? ''}
          tick={{ fontSize: 10 }}
          tickLine={false}
          axisLine={false}
          interval={0}
          angle={-35}
          textAnchor="end"
          height={55}
          label={{ value: DIMENSION_LABELS[xDim], position: 'insideBottom', offset: -45, fontSize: 11 }}
        />
        <YAxis
          type="number"
          dataKey="yIdx"
          name={DIMENSION_LABELS[yDim]}
          domain={[-0.5, yLabels.length - 0.5]}
          ticks={yLabels.map((_, i) => i)}
          tickFormatter={(v: number) => yLabels[v] ?? ''}
          tick={{ fontSize: 10 }}
          tickLine={false}
          axisLine={false}
          interval={0}
          width={55}
          label={{ value: DIMENSION_LABELS[yDim], angle: -90, position: 'insideLeft', offset: 55, fontSize: 11 }}
        />
        <ZAxis type="number" dataKey="z" range={[40, 900]} name={METRIC_LABELS[sizeMetric]} />
        <ReChartsTooltip
          cursor={{ strokeDasharray: '3 3' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as typeof points[number]
            return (
              <div className="rounded border bg-background p-2 shadow-lg text-xs space-y-1">
                <div className="font-semibold">{d.xLabel} × {d.yLabel}</div>
                <div className="text-muted-foreground">
                  {DIMENSION_LABELS[xDim]}: <span className="text-foreground font-medium">{d.xLabel}</span>
                </div>
                <div className="text-muted-foreground">
                  {DIMENSION_LABELS[yDim]}: <span className="text-foreground font-medium">{d.yLabel}</span>
                </div>
                <div className="text-muted-foreground">
                  {METRIC_LABELS[sizeMetric]}: <span className="text-foreground font-medium">{d.metricVal}</span>
                </div>
              </div>
            )
          }}
        />
        <Scatter data={points} fill="#6366f1" fillOpacity={0.7} />
      </ScatterChart>
    </ResponsiveContainer>
  )
}

// ── Preset Panel ─────────────────────────────────────────────────────────────

function PresetPanel() {
  const { presets, savePreset, loadPreset, deletePreset, resetConfig, getShareUrl } =
    useAnalyticsStore()
  const [newName, setNewName] = useState('')
  const [copied, setCopied] = useState(false)

  const handleSave = () => {
    if (!newName.trim()) return
    savePreset(newName.trim())
    setNewName('')
  }

  const handleShare = () => {
    const url = getShareUrl()
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="space-y-3">
      {/* Save */}
      <div className="flex gap-2">
        <Input
          placeholder="Preset name..."
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSave()}
          className="h-8 text-xs"
        />
        <Button size="sm" className="h-8 gap-1" onClick={handleSave} disabled={!newName.trim()}>
          <Plus className="h-3.5 w-3.5" /> Save
        </Button>
      </div>

      {/* Saved Presets */}
      {presets.length > 0 && (
        <div className="space-y-1">
          {presets.map((p) => (
            <div key={p.id} className="flex items-center gap-2 rounded-md border px-2 py-1.5">
              <button
                className="flex-1 text-left text-xs font-medium hover:text-primary"
                onClick={() => loadPreset(p.id)}
              >
                {p.name}
              </button>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={() => deletePreset(p.id)}
              >
                <Trash2 className="h-3 w-3 text-muted-foreground" />
              </Button>
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2 pt-1">
        <Button variant="outline" size="sm" className="h-8 gap-1 text-xs" onClick={handleShare}>
          {copied ? <Check className="h-3.5 w-3.5 text-green-600" /> : <Share2 className="h-3.5 w-3.5" />}
          {copied ? 'Copied!' : 'Share URL'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1 text-xs"
          onClick={resetConfig}
        >
          <RotateCcw className="h-3.5 w-3.5" /> Reset
        </Button>
      </div>
    </div>
  )
}

// ── Main Analytics Page ───────────────────────────────────────────────────────

export function AnalyticsPage() {
  const { findings } = useAppStore()
  const { config, updateConfig, loadFromUrl } = useAnalyticsStore()

  useEffect(() => {
    loadFromUrl()
  }, [loadFromUrl])

  const aggregated = useMemo(
    () =>
      aggregateFindings(
        findings,
        config.groupBy,
        config.metric,
        config.stackBy,
        config.topN,
      ),
    [findings, config.groupBy, config.metric, config.stackBy, config.topN],
  )

  const stackKeys = useMemo(() => {
    if (!config.stackBy) return []
    const all = new Set<string>()
    aggregated.forEach((r) => r.stacks && Object.keys(r.stacks).forEach((k) => all.add(k)))
    return Array.from(all).slice(0, 8)
  }, [aggregated, config.stackBy])

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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Analytics</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Explore and pivot your vulnerability data. Save and share views as presets.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        {/* ── Config Sidebar ────────────────────────────────────────────── */}
        <div className="space-y-6">
          {/* Chart Config */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Visualization</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Chart Type */}
              <div className="space-y-1.5">
                <Label className="text-xs">Chart Type</Label>
                <div className="grid grid-cols-3 gap-1.5">
                  {[
                    { type: 'bar' as ChartType, label: 'Bar', icon: BarChart2 },
                    { type: 'pie' as ChartType, label: 'Pie', icon: PieIcon },
                    { type: 'scatter' as ChartType, label: 'Bubble', icon: Expand },
                  ].map(({ type, label, icon: Icon }) => (
                    <button
                      key={type}
                      onClick={() => updateConfig({ chartType: type })}
                      className={`flex flex-col items-center gap-1 rounded-md border p-2 text-xs transition-colors ${
                        config.chartType === type
                          ? 'border-primary bg-primary/5 text-primary'
                          : 'hover:bg-muted'
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Group By */}
              <div className="space-y-1.5">
                <Label className="text-xs">Group By</Label>
                <Select
                  value={config.groupBy}
                  onValueChange={(v) => updateConfig({ groupBy: v as DimensionKey })}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.entries(DIMENSION_LABELS) as [DimensionKey, string][]).map(
                      ([key, label]) => (
                        <SelectItem key={key} value={key} className="text-xs">
                          {label}
                        </SelectItem>
                      ),
                    )}
                  </SelectContent>
                </Select>
              </div>

              {/* Stack By (only for bar) */}
              {config.chartType === 'bar' && (
                <div className="space-y-1.5">
                  <Label className="text-xs">Stack / Color By</Label>
                  <Select
                    value={config.stackBy ?? 'none'}
                    onValueChange={(v) =>
                      updateConfig({ stackBy: v === 'none' ? undefined : (v as DimensionKey) })
                    }
                  >
                    <SelectTrigger className="h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none" className="text-xs">None</SelectItem>
                      {(Object.entries(DIMENSION_LABELS) as [DimensionKey, string][])
                        .filter(([k]) => k !== config.groupBy)
                        .map(([key, label]) => (
                          <SelectItem key={key} value={key} className="text-xs">
                            {label}
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              {/* Scatter X / Y Axis (scatter only) */}
              {config.chartType === 'scatter' && (
                <>
                  <div className="space-y-1.5">
                    <Label className="text-xs">X Axis</Label>
                    <Select
                      value={config.scatterX ?? 'severity'}
                      onValueChange={(v) => updateConfig({ scatterX: v as DimensionKey })}
                    >
                      <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {(Object.entries(DIMENSION_LABELS) as [DimensionKey, string][]).map(([key, label]) => (
                          <SelectItem key={key} value={key} className="text-xs">{label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Y Axis</Label>
                    <Select
                      value={config.scatterY ?? 'environment'}
                      onValueChange={(v) => updateConfig({ scatterY: v as DimensionKey })}
                    >
                      <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {(Object.entries(DIMENSION_LABELS) as [DimensionKey, string][]).map(([key, label]) => (
                          <SelectItem key={key} value={key} className="text-xs">{label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </>
              )}

              {/* Metric / Bubble Size */}
              <div className="space-y-1.5">
                <Label className="text-xs">{config.chartType === 'scatter' ? 'Bubble Size' : 'Metric'}</Label>
                <Select
                  value={config.metric}
                  onValueChange={(v) => updateConfig({ metric: v as MetricKey })}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.entries(METRIC_LABELS) as [MetricKey, string][]).map(
                      ([key, label]) => (
                        <SelectItem key={key} value={key} className="text-xs">
                          {label}
                        </SelectItem>
                      ),
                    )}
                  </SelectContent>
                </Select>
              </div>

              {/* Top N */}
              <div className="space-y-1.5">
                <Label className="text-xs">Show Top</Label>
                <Select
                  value={String(config.topN)}
                  onValueChange={(v) => updateConfig({ topN: Number(v) })}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {[5, 10, 20, 50, 100].map((n) => (
                      <SelectItem key={n} value={String(n)} className="text-xs">
                        Top {n}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Presets */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Save className="h-4 w-4" /> Presets
              </CardTitle>
            </CardHeader>
            <CardContent>
              <PresetPanel />
            </CardContent>
          </Card>
        </div>

        {/* ── Main Chart Area ───────────────────────────────────────────── */}
        <div className="space-y-4">
          {/* Chart */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {config.chartType === 'scatter'
                  ? `${DIMENSION_LABELS[config.scatterX ?? 'severity']} vs ${DIMENSION_LABELS[config.scatterY ?? 'environment']} · size = ${METRIC_LABELS[config.metric]}`
                  : `${METRIC_LABELS[config.metric]} by ${DIMENSION_LABELS[config.groupBy]}${config.stackBy ? ` · Stacked by ${DIMENSION_LABELS[config.stackBy]}` : ''}`
                }
                <Badge variant="outline" className="ml-2 text-xs font-normal">
                  {aggregated.length} groups
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {config.chartType === 'bar' && (
                <AnalyticsBarChart
                  data={aggregated}
                  metric={config.metric}
                  groupBy={config.groupBy}
                  stackKeys={stackKeys}
                />
              )}
              {config.chartType === 'pie' && (
                <AnalyticsPieChart
                  data={aggregated}
                  metric={config.metric}
                  groupBy={config.groupBy}
                />
              )}
              {config.chartType === 'scatter' && (
                <AnalyticsScatterChart
                  findings={findings}
                  xDim={config.scatterX ?? 'severity'}
                  yDim={config.scatterY ?? 'environment'}
                  sizeMetric={config.metric}
                />
              )}
            </CardContent>
          </Card>

          {/* Data Table with Pivot */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Data Table</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="pivot">
                <TabsList className="h-8">
                  <TabsTrigger value="pivot" className="text-xs h-6">
                    Pivot View
                  </TabsTrigger>
                  <TabsTrigger value="cross" className="text-xs h-6">
                    Cross-tab
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="pivot" className="mt-4">
                  <PivotTable rows={aggregated} metric={config.metric} stackKeys={[]} />
                </TabsContent>

                <TabsContent value="cross" className="mt-4">
                  {config.stackBy ? (
                    <PivotTable rows={aggregated} metric={config.metric} stackKeys={stackKeys} />
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Select a "Stack / Color By" dimension to see the cross-tab view.
                    </p>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {aggregated.slice(0, 4).map((row) => (
              <Card key={row.group} className="text-center">
                <CardContent className="p-4">
                  <div className="text-xl font-bold">{row[config.metric].toLocaleString()}</div>
                  <div className="text-xs text-muted-foreground mt-1 truncate" title={row.group}>
                    {row.group}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>

    </div>
  )
}
