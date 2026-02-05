import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: number | string
  subtext?: string
  icon?: LucideIcon
  trend?: {
    value: number
    isPositive?: boolean
  }
  onClick?: () => void
  variant?: 'default' | 'warning' | 'danger' | 'success'
  className?: string
  // New props for enhanced visualization
  sparklineData?: number[]  // Array of values for mini chart (e.g., 7 days)
  showUrgencyRing?: boolean  // Animated ring around icon when critical
  pulseOnCritical?: boolean  // Pulse animation when value exceeds threshold
  criticalThreshold?: number  // Threshold for pulse/urgency (default: 0)
}

function Sparkline({ data, className }: { data: number[]; className?: string }) {
  if (!data || data.length === 0) return null

  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1

  // Normalize values to 0-100 range for viewBox
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100
    const y = 100 - ((value - min) / range) * 100
    return `${x},${y}`
  }).join(' ')

  // Create area path
  const areaPath = `M0,100 L0,${100 - ((data[0] - min) / range) * 100} ${data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100
    const y = 100 - ((value - min) / range) * 100
    return `L${x},${y}`
  }).join(' ')} L100,100 Z`

  return (
    <svg
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      className={cn('h-8 w-full', className)}
    >
      {/* Area fill */}
      <path
        d={areaPath}
        className="fill-primary/10"
      />
      {/* Line */}
      <polyline
        points={points}
        fill="none"
        className="stroke-primary"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function StatCard({
  title,
  value,
  subtext,
  icon: Icon,
  trend,
  onClick,
  variant = 'default',
  className,
  sparklineData,
  showUrgencyRing,
  pulseOnCritical,
  criticalThreshold = 0,
}: StatCardProps) {
  const numericValue = typeof value === 'number' ? value : parseInt(String(value), 10)
  const isCritical = !isNaN(numericValue) && numericValue > criticalThreshold
  const shouldPulse = pulseOnCritical && isCritical
  const shouldShowRing = showUrgencyRing && isCritical

  const variantStyles = {
    default: '',
    warning: 'border-l-4 border-l-yellow-500 bg-yellow-500/5',
    danger: 'border-l-4 border-l-red-500 bg-red-500/5',
    success: 'border-l-4 border-l-green-500 bg-green-500/5',
  }

  const iconBgStyles = {
    default: 'bg-muted/50',
    warning: 'bg-yellow-500/10',
    danger: 'bg-red-500/10',
    success: 'bg-green-500/10',
  }

  const iconColorStyles = {
    default: 'text-muted-foreground',
    warning: 'text-yellow-600 dark:text-yellow-500',
    danger: 'text-red-600 dark:text-red-500',
    success: 'text-green-600 dark:text-green-500',
  }

  return (
    <Card
      className={cn(
        variantStyles[variant],
        onClick && 'card-interactive cursor-pointer',
        shouldPulse && 'animate-pulse-subtle',
        className
      )}
      onClick={onClick}
    >
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        {Icon && (
          <div className={cn(
            'p-2 rounded-lg',
            shouldShowRing ? 'urgency-ring bg-red-500/10' : iconBgStyles[variant]
          )}>
            <Icon className={cn(
              'h-4 w-4',
              shouldShowRing ? 'text-red-500' : iconColorStyles[variant]
            )} />
          </div>
        )}
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <div className="text-3xl font-bold tracking-tight">{value}</div>
          {trend && (
            <div
              className={cn(
                'flex items-center text-xs font-medium transition-transform',
                trend.isPositive ? 'text-green-600' : 'text-red-600',
                'animate-trend-arrow'
              )}
            >
              {trend.isPositive ? (
                <TrendingUp className="h-3 w-3 mr-0.5" />
              ) : (
                <TrendingDown className="h-3 w-3 mr-0.5" />
              )}
              {Math.abs(trend.value)}%
            </div>
          )}
        </div>
        {subtext && (
          <p className="text-xs text-muted-foreground mt-1">{subtext}</p>
        )}
        {sparklineData && sparklineData.length > 1 && (
          <div className="mt-3 -mx-1">
            <Sparkline data={sparklineData} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}
