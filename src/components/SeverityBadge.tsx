import { Badge } from '@/components/ui/badge'
import type { Severity } from '@/types'

interface SeverityBadgeProps {
  severity: Severity
}

const variantMap: Record<Severity, 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  NONE: 'none',
  UNKNOWN: 'unknown',
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <Badge variant={variantMap[severity] ?? 'unknown'}>
      {severity}
    </Badge>
  )
}
