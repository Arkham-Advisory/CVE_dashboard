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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppStore } from '@/store/useAppStore'
import { useCVEDataStore } from '@/store/useCVEDataStore'
import { estimateCVSS } from '@/lib/cveApi'
import type { Severity } from '@/types'

// ── CVSS axis options ─────────────────────────────────────────────────────────

type CVSSAxis = 'exploitability' | 'impact' | 'base'

const AXIS_CONFIG: Record<CVSSAxis, { label: string; desc: string; max: number }> = {
  exploitability: {
    label: 'Exploitability (Likelihood)',
    desc: 'How easily can an attacker exploit this? (0–10)',
    max: 10,
  },
  impact: {
    label: 'Impact',
    desc: 'How severe is the effect on CIA triad? (0–10)',
    max: 10,
  },
  base: {
    label: 'CVSS Base Score',
    desc: 'Overall CVSS v3 base score (0–10)',
    max: 10,
  },
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#6b7280',
  UNKNOWN: '#9ca3af',
}

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

// ── Estimate sub-scores from base when NVD isn't available ───────────────────

/** Rough estimate for exploitability sub-score from base CVSS */
function estimateExploitability(base: number): number {
  return Math.min(10, base * 0.67)
}

/** Rough estimate for impact sub-score from base CVSS */
function estimateImpact(base: number): number {
  return Math.min(10, base * 0.82)
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface BubblePoint {
  cveId: string
  severity: Severity
  baseScore: number
  exploitabilityScore: number
  impactScore: number
  cvssSource: 'nvd' | 'estimated'
  findings: number        // Size dimension (occurrences)
  affectedAssets: number
  fixableCount: number
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ payload: BubblePoint }>
  xAxis: CVSSAxis
  yAxis: CVSSAxis
}

function CustomTooltip({ active, payload, xAxis, yAxis }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="rounded-lg border bg-background p-3 shadow-lg text-xs space-y-1.5 max-w-[260px]">
      <div className="font-mono font-semibold text-sm">{d.cveId}</div>
      <div className="flex items-center gap-2">
        <SeverityBadge severity={d.severity} />
        <span className="text-muted-foreground">
          {d.cvssSource === 'nvd' ? 'NVD' : 'Estimated'}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-muted-foreground">
        <span>CVSS Base</span>
        <span className="font-medium text-foreground">{d.baseScore.toFixed(1)}</span>
        <span>Exploitability</span>
        <span className="font-medium text-foreground">{d.exploitabilityScore.toFixed(1)}</span>
        <span>Impact</span>
        <span className="font-medium text-foreground">{d.impactScore.toFixed(1)}</span>
        <span>Findings</span>
        <span className="font-medium text-foreground">{d.findings}</span>
        <span>Assets</span>
        <span className="font-medium text-foreground">{d.affectedAssets}</span>
        <span>Fixable</span>
        <span className="font-medium text-foreground">{d.fixableCount}</span>
      </div>
      {d.cvssSource === 'estimated' && (
        <p className="text-[10px] text-muted-foreground italic">
          Exploitability &amp; Impact estimated from severity
        </p>
      )}
      <p className="text-[10px] text-muted-foreground">
        X = {AXIS_CONFIG[xAxis].label} · Y = {AXIS_CONFIG[yAxis].label}
      </p>
    </div>
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export function CVSSBubbleChart() {
  const { cveGroups } = useAppStore()
  const { data: nvdData, fetchOne } = useCVEDataStore()

  const [selectedSeverities, setSelectedSeverities] = useState<Set<Severity>>(
    new Set(ALL_SEVERITIES),
  )
  const [cvssRange, setCvssRange] = useState([0, 10])
  const [minFindings, setMinFindings] = useState(0)
  const [xAxis, setXAxis] = useState<CVSSAxis>('exploitability')
  const [yAxis, setYAxis] = useState<CVSSAxis>('impact')

  // Build bubble data
  const bubbleData = useMemo<BubblePoint[]>(() => {
    return cveGroups.map((g) => {
      const nvd = nvdData[g.cveId]
      const baseScore = nvd?.cvssV3Score ?? nvd?.cvssV2Score ?? estimateCVSS(g.severity)
      const exploitabilityScore = nvd?.exploitabilityScore ?? estimateExploitability(baseScore)
      const impactScore = nvd?.impactScore ?? estimateImpact(baseScore)
      const fixableCount = g.findings.filter((f) => !!f.fixedVersion).length
      return {
        cveId: g.cveId,
        severity: g.severity,
        baseScore,
        exploitabilityScore,
        impactScore,
        cvssSource: nvd ? 'nvd' : 'estimated',
        findings: g.findings.length,
        affectedAssets: g.affectedAssets,
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
          d.baseScore >= cvssRange[0] &&
          d.baseScore <= cvssRange[1] &&
          d.findings >= minFindings,
      ),
    [bubbleData, selectedSeverities, cvssRange, minFindings],
  )

  // Map axis selection to data key
  const getAxisValue = (d: BubblePoint, axis: CVSSAxis): number => {
    if (axis === 'exploitability') return d.exploitabilityScore
    if (axis === 'impact') return d.impactScore
    return d.baseScore
  }

  // Inject x/y values into the scatter data
  const scatterData = useMemo(
    () =>
      filteredData.map((d) => ({
        ...d,
        x: getAxisValue(d, xAxis),
        y: getAxisValue(d, yAxis),
      })),
    [filteredData, xAxis, yAxis], // eslint-disable-line react-hooks/exhaustive-deps
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
  const maxFindings = Math.max(1, ...bubbleData.map((d) => d.findings))

  if (cveGroups.length === 0) return null

  const xCfg = AXIS_CONFIG[xAxis]
  const yCfg = AXIS_CONFIG[yAxis]

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">CVSS Risk Landscape</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Bubble size = number of findings · Color = severity
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
                  variant={
                    selectedSeverities.has(s)
                      ? (s.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'unknown')
                      : 'outline'
                  }
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
        {/* Axis selectors + filters */}
        <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          {/* X axis */}
          <div className="space-y-1.5">
            <Label className="text-xs">X Axis</Label>
            <Select value={xAxis} onValueChange={(v) => setXAxis(v as CVSSAxis)}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(AXIS_CONFIG) as CVSSAxis[]).map((k) => (
                  <SelectItem key={k} value={k} className="text-xs">
                    {AXIS_CONFIG[k].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[10px] text-muted-foreground leading-tight">{xCfg.desc}</p>
          </div>

          {/* Y axis */}
          <div className="space-y-1.5">
            <Label className="text-xs">Y Axis</Label>
            <Select value={yAxis} onValueChange={(v) => setYAxis(v as CVSSAxis)}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(AXIS_CONFIG) as CVSSAxis[]).map((k) => (
                  <SelectItem key={k} value={k} className="text-xs">
                    {AXIS_CONFIG[k].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[10px] text-muted-foreground leading-tight">{yCfg.desc}</p>
          </div>

          {/* CVSS range */}
          <div className="space-y-1.5">
            <Label className="text-xs">
              CVSS Base Range: {cvssRange[0].toFixed(1)} – {cvssRange[1].toFixed(1)}
            </Label>
            <Slider
              min={0}
              max={10}
              step={0.5}
              value={cvssRange}
              onValueChange={setCvssRange}
            />
          </div>

          {/* Min findings */}
          <div className="space-y-1.5">
            <Label className="text-xs">Min. Findings: {minFindings}</Label>
            <Slider
              min={0}
              max={maxFindings}
              step={1}
              value={[minFindings]}
              onValueChange={([v]) => setMinFindings(v)}
            />
          </div>
        </div>

        {/* Chart */}
        <ResponsiveContainer width="100%" height={380}>
          <ScatterChart margin={{ top: 20, right: 30, bottom: 40, left: 20 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis
              type="number"
              dataKey="x"
              domain={[0, xCfg.max]}
              name={xCfg.label}
              label={{
                value: xCfg.label,
                position: 'insideBottom',
                offset: -20,
                fontSize: 11,
              }}
              tick={{ fontSize: 11 }}
              tickLine={false}
            />
            <YAxis
              type="number"
              dataKey="y"
              domain={[0, yCfg.max]}
              name={yCfg.label}
              label={{
                value: yCfg.label,
                angle: -90,
                position: 'insideLeft',
                offset: 10,
                fontSize: 11,
              }}
              tick={{ fontSize: 11 }}
              tickLine={false}
            />
            <ZAxis
              type="number"
              dataKey="findings"
              range={[40, 600]}
              name="Findings"
            />
            <Tooltip
              content={(props) => (
                <CustomTooltip
                  active={props.active}
                  payload={props.payload as Array<{ payload: BubblePoint }> | undefined}
                  xAxis={xAxis}
                  yAxis={yAxis}
                />
              )}
            />
            {/* Quadrant reference lines at score = 7 */}
            {xAxis !== 'base' && (
              <ReferenceLine
                x={7}
                stroke="#ef4444"
                strokeDasharray="4 4"
                strokeOpacity={0.5}
                label={{ value: 'High', fontSize: 9, fill: '#ef4444', position: 'top' }}
              />
            )}
            {yAxis !== 'base' && (
              <ReferenceLine
                y={7}
                stroke="#ef4444"
                strokeDasharray="4 4"
                strokeOpacity={0.5}
                label={{ value: 'High', fontSize: 9, fill: '#ef4444', position: 'right' }}
              />
            )}
            {xAxis === 'base' && (
              <>
                <ReferenceLine x={9} stroke="#ef4444" strokeDasharray="3 3" strokeOpacity={0.5} label={{ value: 'Critical', fontSize: 9, fill: '#ef4444' }} />
                <ReferenceLine x={7} stroke="#f97316" strokeDasharray="3 3" strokeOpacity={0.5} label={{ value: 'High', fontSize: 9, fill: '#f97316' }} />
                <ReferenceLine x={4} stroke="#eab308" strokeDasharray="3 3" strokeOpacity={0.5} label={{ value: 'Medium', fontSize: 9, fill: '#eab308' }} />
              </>
            )}
            <Scatter data={scatterData} isAnimationActive={false}>
              {scatterData.map((entry, i) => (
                <Cell
                  key={i}
                  fill={SEVERITY_COLORS[entry.severity]}
                  fillOpacity={entry.cvssSource === 'estimated' ? 0.45 : 0.82}
                  stroke={SEVERITY_COLORS[entry.severity]}
                  strokeWidth={1}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>

        <p className="text-xs text-muted-foreground text-center">
          {filteredData.length} CVEs · Semi-transparent = estimated score · Solid = NVD verified ·
          {' '}Top-right quadrant = highest risk
        </p>
      </CardContent>
    </Card>
  )
}
