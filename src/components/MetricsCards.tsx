import { Shield, Bug, AlertTriangle, Server } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAppStore } from '@/store/useAppStore'

interface MetricCardProps {
  title: string
  value: string | number
  icon: React.ReactNode
  description?: string
  valueClassName?: string
}

function MetricCard({ title, value, icon, description, valueClassName }: MetricCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className="text-muted-foreground">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${valueClassName ?? ''}`}>{value}</div>
        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
      </CardContent>
    </Card>
  )
}

export function MetricsCards() {
  const { metrics } = useAppStore()

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        title="Total Findings"
        value={metrics.totalFindings.toLocaleString()}
        icon={<Bug className="h-4 w-4" />}
        description="Across all uploaded files"
      />
      <MetricCard
        title="Unique CVEs"
        value={metrics.uniqueCVEs.toLocaleString()}
        icon={<Shield className="h-4 w-4" />}
        description="Distinct vulnerabilities"
      />
      <MetricCard
        title="Critical"
        value={metrics.criticalFindings.toLocaleString()}
        icon={<AlertTriangle className="h-4 w-4" />}
        valueClassName={metrics.criticalFindings > 0 ? 'text-red-600' : ''}
        description="Critical severity findings"
      />
      <MetricCard
        title="Affected Assets"
        value={metrics.affectedAssets.toLocaleString()}
        icon={<Server className="h-4 w-4" />}
        description="Unique impacted assets"
      />
    </div>
  )
}
