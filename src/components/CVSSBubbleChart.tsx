import { useMemo, useState } from 'react'
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  ReferenceLine,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Slider } from '@/components/ui/slider'
import { Label } from '@/components/ui/label'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppStore } from '@/store/useAppStore'
import { useCVEDataStore } from '@/store/useCVEDataStore'
import { estimateCVSS } from '@/lib/cveApi'
import type { Severity } from '@/types'

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#6b7280',
  UNKNOWN: '#9ca3af',
}

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

interface BubblePoint {
  cveId: string
  severity: Severity
  cvssScore: number
  cvssSource: 'nvd' | 'estimated'
  affectedAssets: number
  findings: number
  fixableCount: number
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ payload: BubblePoint }>
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="rounded-lg border bg-background p-3 shadow-lg text-xs space-y-1.5 max-w-[240px]">
      <div className="font-mono font-semibold text-sm">{d.cveId}</div>
      <div className="flex items-center gap-2">
        <SeverityBadge severity={d.severity} />
        <span className="text-muted-foreground">
          {d.cvssSource === 'nvd' ? 'CVSS' : 'Est. CVSS'}: {d.cvssScore.toFixed(1)}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-muted-foreground">
        <span>Findings</span><span className="font-medium text-foreground">{d.findings}</span>
        <span>Assets</span><span className="font-medium text-foreground">{d.affectedAssets}</span>
        <span>Fixable</span><span className="font-medium text-foreground">{d.fixableCount}</span>
      </div>
      {d.cvssSource === 'estimated' && (
        <p className="text-[10px] text-muted-foreground italic">* Score estimated from severity</p>
      )}
    </div>
  )
}

export function CVSSBubbleChart() {
  const { cveGroups } = useAppStore()
  const { data: nvdData, fetchOne } = useCVEDataStore()
  const [selectedSeverities, setSelectedSeverities] = useState<Set<Severity>>(new Set(ALL_SEVERITIES))
  const [cvssRange, setCvssRange] = useState([0, 10])
  const [minAssets, setMinAssets] = useState(0)

  // Build bubble data
  const bubbleData = useMemo<BubblePoint[]>(() => {
    return cveGroups.map((g) => {
      const nvd = nvdData[g.cveId]
      const cvssScore = nvd?.cvssV3Score ?? nvd?.cvssV2Score ?? estimateCVSS(g.severity)
      const fixableCount = g.findings.filter((f) => !!f.fixedVersion).length
      return {
        cveId: g.cveId,
        severity: g.severity,
        cvssScore,
        cvssSource: nvd ? 'nvd' : 'estimated',
        affectedAssets: g.affectedAssets,
        findings: g.findings.length,
        fixableCount,
      }
    })
  }, [cveGroups, nvdData])

  // Apply filters
  const filteredData = useMemo(
    () =>
      bubbleData.filter(
        (d) =>
          selectedSeverities.has(d.severity) &&
          d.cvssScore >= cvssRange[0] &&
          d.cvssScore <= cvssRange[1] &&
          d.affectedAssets >= minAssets,
      ),
    [bubbleData, selectedSeverities, cvssRange, minAssets],
  )

  const toggleSeverity = (s: Severity) => {
    setSelectedSeverities((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  }

  // Trigger NVD fetch for visible CVEs (lazy)
  const visibleIds = filteredData.slice(0, 50).map((d) => d.cveId)
  visibleIds.forEach((id) => { if (!nvdData[id]) fetchOne(id) })

  const nvdCount = filteredData.filter((d) => d.cvssSource === 'nvd').length

  if (cveGroups.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">CVSS Bubble Chart</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              X = CVSS score · Y = Affected assets · Size = Findings
              {nvdCount > 0 && (
                <span className="ml-2 text-green-600">
                  {nvdCount}/{filteredData.length} scores from NVD
                </span>
              )}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {ALL_SEVERITIES.map((s) => (
              <button key={s} onClick={() => toggleSeverity(s)}>
                <Badge
                  variant={selectedSeverities.has(s) ? (s.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'unknown') : 'outline'}
                  className="cursor-pointer"
                >
                  {s}
                </Badge>
              </button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-2">
            <Label className="text-xs">
              CVSS Range: {cvssRange[0].toFixed(1)} – {cvssRange[1].toFixed(1)}
            </Label>
            <Slider
              min={0}
              max={10}
              step={0.5}
              value={cvssRange}
              onValueChange={setCvssRange}
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">
              Min. Affected Assets: {minAssets}
            </Label>
            <Slider
              min={0}
              max={Math.max(10, ...bubbleData.map((d) => d.affectedAssets))}
              step={1}
              value={[minAssets]}
              onValueChange={([v]) => setMinAssets(v)}
            />
          </div>
        </div>

        {/* Chart */}
        <ResponsiveContainer width="100%" height={360}>
          <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis
              type="number"
              dataKey="cvssScore"
              domain={[0, 10]}
              name="CVSS Score"
              label={{ value: 'CVSS Score', position: 'insideBottom', offset: -10, fontSize: 11 }}
              tick={{ fontSize: 11 }}
              tickLine={false}
            />
            <YAxis
              type="number"
              dataKey="affectedAssets"
              name="Affected Assets"
              label={{ value: 'Affected Assets', angle: -90, position: 'insideLeft', fontSize: 11 }}
              tick={{ fontSize: 11 }}
              tickLine={false}
            />
            <ZAxis type="number" dataKey="findings" range={[30, 500]} name="Findings" />
            <Tooltip content={<CustomTooltip />} />
            {/* CVSS threshold lines */}
            <ReferenceLine x={9} stroke="#ef4444" strokeDasharray="3 3" label={{ value: 'Critical', fontSize: 9, fill: '#ef4444' }} />
            <ReferenceLine x={7} stroke="#f97316" strokeDasharray="3 3" label={{ value: 'High', fontSize: 9, fill: '#f97316' }} />
            <ReferenceLine x={4} stroke="#eab308" strokeDasharray="3 3" label={{ value: 'Medium', fontSize: 9, fill: '#eab308' }} />
            <Scatter data={filteredData}>
              {filteredData.map((entry, i) => (
                <Cell
                  key={i}
                  fill={SEVERITY_COLORS[entry.severity]}
                  fillOpacity={entry.cvssSource === 'estimated' ? 0.5 : 0.85}
                  stroke={SEVERITY_COLORS[entry.severity]}
                  strokeWidth={1}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>

        <p className="text-xs text-muted-foreground text-center">
          {filteredData.length} CVEs shown · Semi-transparent = estimated score, solid = NVD verified
        </p>
      </CardContent>
    </Card>
  )
}
