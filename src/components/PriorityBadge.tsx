import { PRIORITY_CONFIG } from '@/lib/riskScore'
import type { RiskPriority } from '@/types'
import { cn } from '@/lib/utils'

interface PriorityBadgeProps {
  priority: RiskPriority
  compact?: boolean
  className?: string
}

export function PriorityBadge({ priority, compact, className }: PriorityBadgeProps) {
  const cfg = PRIORITY_CONFIG[priority]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap',
        cfg.bg,
        cfg.border,
        cfg.color,
        className,
      )}
    >
      {cfg.emoji}
      {!compact && <span>{cfg.label}</span>}
    </span>
  )
}
