import { cn } from '@/lib/utils'
import { SEVERITY_CONFIG } from '@/lib/constants'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

interface SeverityIndicatorProps {
  severity: Severity
  variant?: 'badge' | 'dot' | 'prominent'
  showLabel?: boolean
  showIcon?: boolean
  pulse?: boolean
  className?: string
}

export function SeverityIndicator({
  severity,
  variant = 'badge',
  showLabel = true,
  showIcon = false,
  pulse = false,
  className,
}: SeverityIndicatorProps) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.informational
  const Icon = config.icon
  const label = severity.charAt(0).toUpperCase() + severity.slice(1)

  if (variant === 'dot') {
    return (
      <span className={cn('relative inline-flex', className)}>
        {pulse && severity === 'critical' && (
          <span
            className={cn(
              'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
              config.dotColor
            )}
          />
        )}
        <span
          className={cn(
            'relative inline-flex h-2.5 w-2.5 rounded-full',
            config.dotColor
          )}
        />
      </span>
    )
  }

  if (variant === 'prominent') {
    return (
      <div
        className={cn(
          'inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium',
          config.color,
          pulse && severity === 'critical' && 'animate-pulse',
          className
        )}
      >
        <Icon className="h-4 w-4" />
        {showLabel && <span>{label}</span>}
      </div>
    )
  }

  // Default badge variant
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium',
        config.color,
        className
      )}
    >
      {showIcon && <Icon className="h-3 w-3" />}
      {showLabel && <span>{label}</span>}
    </span>
  )
}
