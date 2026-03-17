import { UploadPanel } from '@/components/UploadPanel'
import { MetricsCards } from '@/components/MetricsCards'
import { SeverityChart } from '@/components/SeverityChart'
import { TopCVEs, TopAssets } from '@/components/TopLists'
import { useAppStore } from '@/store/useAppStore'

export function DashboardPage() {
  const { findings } = useAppStore()
  const hasData = findings.length > 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Upload vulnerability reports to analyze your security posture
        </p>
      </div>

      <UploadPanel />

      {hasData && (
        <>
          <MetricsCards />

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-1">
              <SeverityChart />
            </div>
            <div className="lg:col-span-2 grid gap-4 sm:grid-cols-2">
              <TopCVEs />
              <TopAssets />
            </div>
          </div>
        </>
      )}
    </div>
  )
}
