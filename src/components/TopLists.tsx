import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from '@/components/SeverityBadge'
import { FixStatusBadge } from '@/components/FixStatusBadge'
import { InfoTooltip } from '@/components/InfoTooltip'
import { useAppStore } from '@/store/useAppStore'
import { CONCEPT_TOOLTIPS } from '@/lib/riskScore'
import { Zap, Target, Bomb } from 'lucide-react'

export function TopCVEs() {
  const { metrics } = useAppStore()

  if (metrics.topCVEs.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Top CVEs</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {metrics.topCVEs.map(({ cveId, count, severity, affectedAssets }) => (
          <div key={cveId} className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={severity} />
              <span className="font-mono font-medium text-xs">{cveId}</span>
            </div>
            <div className="text-right">
              <div className="text-xs text-muted-foreground">{count} findings</div>
              {affectedAssets > 0 && (
                <div className="text-[10px] text-muted-foreground">{affectedAssets} assets</div>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

export function TopAssets() {
  const { metrics } = useAppStore()

  if (metrics.topAssets.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Most Affected Assets</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {metrics.topAssets.map(({ asset, count, bySeverity }) => (
          <div key={asset} className="flex items-center justify-between text-sm">
            <span className="truncate font-medium max-w-[180px] text-xs" title={asset}>
              {asset}
            </span>
            <div className="text-right">
              <div className="text-xs text-muted-foreground">{count} findings</div>
              {bySeverity.CRITICAL > 0 && (
                <div className="text-[10px] text-red-600 font-medium">{bySeverity.CRITICAL} critical</div>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

export function TopRemediationTargets() {
  const { metrics, cveGroups, setSelectedCVE } = useAppStore()

  if (metrics.topRemediationTargets.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Target className="h-4 w-4 text-primary" />
          What Should I Fix First?
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {metrics.topRemediationTargets.map(({ cveId, severity, affectedAssets, fixAvailable, riskScore, exploitable }, i) => (
          <div key={cveId} className="flex items-start gap-3">
            <span className="text-muted-foreground font-bold text-sm w-4 shrink-0">{i + 1}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  className="font-mono text-xs font-semibold text-primary hover:underline"
                  onClick={() => {
                    const g = cveGroups.find((g) => g.cveId === cveId)
                    if (g) setSelectedCVE(g)
                  }}
                >
                  {cveId}
                </button>
                <SeverityBadge severity={severity} />
                {exploitable && (
                  <span className="inline-flex items-center gap-0.5 text-[10px] text-orange-700 bg-orange-50 border border-orange-200 rounded px-1">
                    <Zap className="h-2.5 w-2.5" /> Exploitable
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 mt-1">
                <span className="text-xs text-muted-foreground">{affectedAssets} assets affected</span>
                <FixStatusBadge status={fixAvailable ? 'AVAILABLE' : 'NONE'} compact />
                <span className="text-xs font-mono text-muted-foreground">Risk: {riskScore}</span>
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

export function BlastRadiusCard() {
  const { metrics, cveGroups, setSelectedCVE } = useAppStore()
  const br = metrics.blastRadius
  if (!br) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Bomb className="h-4 w-4 text-destructive" />
          Highest Blast Radius
          <InfoTooltip content={CONCEPT_TOOLTIPS['Blast Radius']} />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div>
            <button
              className="font-mono text-sm font-semibold text-primary hover:underline block"
              onClick={() => {
                const g = cveGroups.find((g) => g.cveId === br.cveId)
                if (g) setSelectedCVE(g)
              }}
            >
              {br.cveId}
            </button>
            <div className="flex items-center gap-2 mt-1">
              <SeverityBadge severity={br.severity} />
            </div>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold text-destructive">{br.affectedAssets}</div>
            <div className="text-xs text-muted-foreground">assets affected</div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

