import { cn } from '@/lib/utils'
import { STATUS_COLORS, ALERT_STATUS_COLORS, ALERT_STATUS_LABELS, capitalize } from '@/lib/constants'

// Alert status badge with enhanced styling options
interface AlertStatusBadgeProps {
  status: string
  className?: string
  /** Use subtle (outlined) style instead of solid */
  subtle?: boolean
  /** Show a dot indicator before the label */
  showDot?: boolean
}

const ALERT_STATUS_STYLES: Record<string, { solid: string; subtle: string; dot: string }> = {
  new: {
    solid: 'bg-blue-500 text-white border-transparent',
    subtle: 'border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400',
    dot: 'bg-blue-500',
  },
  acknowledged: {
    solid: 'bg-yellow-500 text-black border-transparent',
    subtle: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
    dot: 'bg-yellow-500',
  },
  resolved: {
    solid: 'bg-green-500 text-white border-transparent',
    subtle: 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400',
    dot: 'bg-green-500',
  },
  false_positive: {
    solid: 'bg-gray-500 text-white border-transparent',
    subtle: 'border-gray-500/30 bg-gray-500/10 text-gray-600 dark:text-gray-400',
    dot: 'bg-gray-500',
  },
}

export function AlertStatusBadge({
  status,
  className,
  subtle = false,
  showDot = false,
}: AlertStatusBadgeProps) {
  const styles = ALERT_STATUS_STYLES[status] || {
    solid: ALERT_STATUS_COLORS[status] || 'bg-gray-500 text-white',
    subtle: 'border-gray-500/30 bg-gray-500/10 text-gray-600 dark:text-gray-400',
    dot: 'bg-gray-500',
  }
  const label = ALERT_STATUS_LABELS[status] || capitalize(status)

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold border',
        subtle ? styles.subtle : styles.solid,
        className
      )}
    >
      {showDot && (
        <span className={cn('h-1.5 w-1.5 rounded-full', styles.dot)} />
      )}
      {label}
    </span>
  )
}

// Rule deployment status badge
interface RuleStatusBadgeProps {
  status: string
  className?: string
  subtle?: boolean
}

const RULE_STATUS_STYLES: Record<string, { solid: string; subtle: string }> = {
  deployed: {
    solid: 'bg-green-500 text-white border-transparent',
    subtle: 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400',
  },
  undeployed: {
    solid: 'bg-gray-500 text-white border-transparent',
    subtle: 'border-gray-500/30 bg-gray-500/10 text-gray-600 dark:text-gray-400',
  },
  snoozed: {
    solid: 'bg-yellow-500 text-black border-transparent',
    subtle: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
  },
}

export function RuleStatusBadge({ status, className, subtle = false }: RuleStatusBadgeProps) {
  const styles = RULE_STATUS_STYLES[status] || {
    solid: STATUS_COLORS[status] || 'bg-gray-500 text-white',
    subtle: 'border-gray-500/30 bg-gray-500/10 text-gray-600 dark:text-gray-400',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold',
        subtle ? styles.subtle : styles.solid,
        className
      )}
    >
      {capitalize(status)}
    </span>
  )
}

// Count badge for notification counts
interface CountBadgeProps {
  count: number
  max?: number
  className?: string
  variant?: 'default' | 'destructive' | 'muted'
}

export function CountBadge({
  count,
  max = 99,
  className,
  variant = 'default',
}: CountBadgeProps) {
  if (count <= 0) return null

  const displayCount = count > max ? `${max}+` : count.toString()

  const variantStyles = {
    default: 'bg-primary text-primary-foreground',
    destructive: 'bg-red-500 text-white',
    muted: 'bg-muted text-muted-foreground',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center rounded-full px-2 py-0.5 text-xs font-semibold min-w-[1.25rem]',
        variantStyles[variant],
        className
      )}
    >
      {displayCount}
    </span>
  )
}

// Live/Pulse indicator badge
interface LiveBadgeProps {
  className?: string
  label?: string
}

export function LiveBadge({ className, label = 'Live' }: LiveBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold',
        'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30',
        className
      )}
    >
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
      </span>
      {label}
    </span>
  )
}
