import { cn } from '@/lib/utils'
import { STATUS_COLORS, ALERT_STATUS_COLORS, ALERT_STATUS_LABELS, capitalize } from '@/lib/constants'

interface RuleStatusBadgeProps {
  status: string
  className?: string
}

export function RuleStatusBadge({ status, className }: RuleStatusBadgeProps) {
  return (
    <span
      className={cn(
        'px-2 py-1 rounded text-xs font-medium',
        STATUS_COLORS[status] || 'bg-gray-500 text-white',
        className
      )}
    >
      {capitalize(status)}
    </span>
  )
}

interface AlertStatusBadgeProps {
  status: string
  className?: string
}

export function AlertStatusBadge({ status, className }: AlertStatusBadgeProps) {
  return (
    <span
      className={cn(
        'px-2 py-1 rounded text-xs font-medium',
        ALERT_STATUS_COLORS[status] || 'bg-gray-500 text-white',
        className
      )}
    >
      {ALERT_STATUS_LABELS[status] || capitalize(status)}
    </span>
  )
}
