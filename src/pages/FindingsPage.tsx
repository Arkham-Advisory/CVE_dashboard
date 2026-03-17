import { FindingsTable } from '@/components/FindingsTable'
import { useAppStore } from '@/store/useAppStore'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export function FindingsPage() {
  const { findings } = useAppStore()

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
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Findings Explorer</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Browse, filter, and sort all vulnerability findings
        </p>
      </div>
      <FindingsTable />
    </div>
  )
}
