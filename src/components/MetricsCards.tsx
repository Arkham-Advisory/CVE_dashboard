import { Shield, Bug, AlertTriangle, Server, Zap, TrendingUp } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { InfoTooltip } from '@/components/InfoTooltip'
import { useAppStore } from '@/store/useAppStore'
import { CONCEPT_TOOLTIPS } from '@/lib/riskScore'

interface MetricCardProps {
  title: string
  value: string | number
  icon: React.ReactNode
  description?: string
  valueClassName?: string
  tooltip?: string
  href?: string
}

function MetricCard({ title, value, icon, description, valueClassName, tooltip, href }: MetricCardProps) {
  const card = (
    <Card className={href ? 'cursor-pointer hover:shadow-md transition-shadow' : ''}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-1.5">
          {title}
          {tooltip && <InfoTooltip content={tooltip} />}
        </CardTitle>
        <div className="text-muted-foreground">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${valueClassName ?? ''}`}>{value}</div>
        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
      </CardContent>
    </Card>
  )
  if (href) return <Link to={href}>{card}</Link>
  return card
}

function SecurityScoreCard() {
  const { metrics } = useAppStore()
  const score = metrics.securityScore
  const color = score >= 80 ? 'text-green-600' : score >= 60 ? 'text-yellow-600' : score >= 40 ? 'text-orange-600' : 'text-red-600'
  const bg = score >= 80 ? '#16a34a' : score >= 60 ? '#ca8a04' : score >= 40 ? '#ea580c' : '#dc2626'
  const pct = score

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-1.5">
          Security Score
          <InfoTooltip content={CONCEPT_TOOLTIPS['Security Score']} />
        </CardTitle>
        <TrendingUp className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${color}`}>{score}/100</div>
        <div className="mt-2 h-2 rounded-full bg-secondary overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${pct}%`, backgroundColor: bg }}
          />
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          {score >= 80 ? 'Good posture' : score >= 60 ? 'Needs attention' : score >= 40 ? 'High risk' : 'Critical risk'}
        </p>
      </CardContent>
    </Card>
  )
}

export function MetricsCards() {
  const { metrics } = useAppStore()

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
      <SecurityScoreCard />
      <MetricCard
        title="Total Findings"
        value={metrics.totalFindings.toLocaleString()}
        icon={<Bug className="h-4 w-4" />}
        description="Across all uploaded files"
        href="/findings"
      />
      <MetricCard
        title="Unique CVEs"
        value={metrics.uniqueCVEs.toLocaleString()}
        icon={<Shield className="h-4 w-4" />}
        description="Distinct vulnerabilities"
        tooltip={CONCEPT_TOOLTIPS['CVE']}
      />
      <MetricCard
        title="Critical"
        value={metrics.criticalFindings.toLocaleString()}
        icon={<AlertTriangle className="h-4 w-4" />}
        valueClassName={metrics.criticalFindings > 0 ? 'text-red-600' : ''}
        description="Critical severity findings"
        tooltip={CONCEPT_TOOLTIPS['Severity']}
        href="/findings?sev=CRITICAL"
      />
      <MetricCard
        title="Exploitable"
        value={metrics.exploitableFindings.toLocaleString()}
        icon={<Zap className="h-4 w-4" />}
        valueClassName={metrics.exploitableFindings > 0 ? 'text-orange-600' : ''}
        description="Active or public exploits"
        tooltip={CONCEPT_TOOLTIPS['Exploitability']}
        href="/findings?exploit=kev,exploit,poc"
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
