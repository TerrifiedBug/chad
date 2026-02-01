import { cn } from '@/lib/utils'
import { SEVERITY_COLORS, capitalize } from '@/lib/constants'

interface SeverityBadgeProps {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'px-2 py-1 rounded text-xs font-medium',
        SEVERITY_COLORS[severity] || 'bg-gray-500 text-white',
        className
      )}
    >
      {capitalize(severity)}
    </span>
  )
}
