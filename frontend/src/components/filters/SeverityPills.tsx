import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

const SEVERITIES = [
  { value: 'critical', label: 'Critical', dotColor: 'bg-red-500' },
  { value: 'high', label: 'High', dotColor: 'bg-orange-500' },
  { value: 'medium', label: 'Medium', dotColor: 'bg-yellow-500' },
  { value: 'low', label: 'Low', dotColor: 'bg-blue-500' },
  { value: 'informational', label: 'Info', dotColor: 'bg-gray-500' },
] as const

interface SeverityPillsProps {
  selected: string[]
  onChange: (severity: string) => void
  showCounts?: Record<string, number>
  size?: 'sm' | 'default'
  className?: string
}

export function SeverityPills({
  selected,
  onChange,
  showCounts,
  size = 'default',
  className,
}: SeverityPillsProps) {
  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {SEVERITIES.map(({ value, label, dotColor }) => {
        const isSelected = selected.includes(value)
        const count = showCounts?.[value]

        return (
          <Button
            key={value}
            variant={isSelected ? 'default' : 'outline'}
            size={size === 'sm' ? 'sm' : 'default'}
            onClick={() => onChange(value)}
            className={cn(
              'gap-1.5 transition-all',
              size === 'sm' && 'h-7 px-2 text-xs',
              isSelected && value === 'critical' && 'bg-red-500 hover:bg-red-600 border-red-500',
              isSelected && value === 'high' && 'bg-orange-500 hover:bg-orange-600 border-orange-500',
              isSelected && value === 'medium' && 'bg-yellow-500 hover:bg-yellow-600 border-yellow-500 text-black',
              isSelected && value === 'low' && 'bg-blue-500 hover:bg-blue-600 border-blue-500',
              isSelected && value === 'informational' && 'bg-gray-500 hover:bg-gray-600 border-gray-500'
            )}
          >
            <span
              className={cn(
                'h-2 w-2 rounded-full',
                isSelected ? 'bg-white/80' : dotColor
              )}
            />
            {label}
            {count !== undefined && (
              <span
                className={cn(
                  'ml-0.5 rounded-full px-1.5 py-0 text-xs font-medium',
                  isSelected
                    ? 'bg-white/20 text-white'
                    : 'bg-muted text-muted-foreground'
                )}
              >
                {count}
              </span>
            )}
          </Button>
        )
      })}
    </div>
  )
}
