import { getFixStatus, FIX_STATUS_CONFIG } from '@/lib/riskScore'
import type { Finding, FixStatus } from '@/types'
import { cn } from '@/lib/utils'

interface FixStatusBadgeProps {
  finding?: Finding
  status?: FixStatus
  compact?: boolean
  className?: string
}

export function FixStatusBadge({ finding, status, compact, className }: FixStatusBadgeProps) {
  const resolved: FixStatus = status ?? (finding ? getFixStatus(finding) : 'UNKNOWN')
  const cfg = FIX_STATUS_CONFIG[resolved]

  const icons: Record<FixStatus, string> = {
    AVAILABLE: '✓',
    NONE: '✗',
    UNKNOWN: '?',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap border',
        cfg.bg,
        cfg.color,
        resolved === 'AVAILABLE' ? 'border-green-200' : resolved === 'NONE' ? 'border-red-200' : 'border-gray-200',
        className,
      )}
    >
      <span className="font-bold">{icons[resolved]}</span>
      {!compact && cfg.label}
    </span>
  )
}
