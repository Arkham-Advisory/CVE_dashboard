import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppStore } from '@/store/useAppStore'

export function TopCVEs() {
  const { metrics } = useAppStore()

  if (metrics.topCVEs.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Top CVEs</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {metrics.topCVEs.map(({ cveId, count, severity }) => (
          <div key={cveId} className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={severity} />
              <span className="font-mono font-medium">{cveId}</span>
            </div>
            <span className="text-muted-foreground">{count} findings</span>
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
        {metrics.topAssets.map(({ asset, count }) => (
          <div key={asset} className="flex items-center justify-between text-sm">
            <span className="truncate font-medium max-w-[200px]" title={asset}>
              {asset}
            </span>
            <span className="text-muted-foreground">{count} findings</span>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
