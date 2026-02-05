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
            variant="outline"
            size={size === 'sm' ? 'sm' : 'default'}
            onClick={() => onChange(value)}
            className={cn(
              'gap-1.5 transition-all duration-200',
              size === 'sm' && 'h-7 px-2.5 text-xs',
              // Unselected state - subtle with colored border on hover
              !isSelected && 'hover:border-current',
              !isSelected && value === 'critical' && 'hover:text-red-600 hover:border-red-300',
              !isSelected && value === 'high' && 'hover:text-orange-600 hover:border-orange-300',
              !isSelected && value === 'medium' && 'hover:text-yellow-600 hover:border-yellow-300',
              !isSelected && value === 'low' && 'hover:text-blue-600 hover:border-blue-300',
              !isSelected && value === 'informational' && 'hover:text-gray-600 hover:border-gray-300',
              // Selected state - solid background
              isSelected && 'shadow-sm',
              isSelected && value === 'critical' && 'bg-red-500 hover:bg-red-600 border-red-500 text-white',
              isSelected && value === 'high' && 'bg-orange-500 hover:bg-orange-600 border-orange-500 text-white',
              isSelected && value === 'medium' && 'bg-yellow-500 hover:bg-yellow-600 border-yellow-500 text-black',
              isSelected && value === 'low' && 'bg-blue-500 hover:bg-blue-600 border-blue-500 text-white',
              isSelected && value === 'informational' && 'bg-gray-500 hover:bg-gray-600 border-gray-500 text-white'
            )}
          >
            <span
              className={cn(
                'h-2 w-2 rounded-full transition-colors',
                isSelected ? 'bg-white/90' : dotColor
              )}
            />
            {label}
            {count !== undefined && (
              <span
                className={cn(
                  'ml-0.5 rounded px-1.5 py-0 text-xs font-medium tabular-nums',
                  isSelected
                    ? 'bg-white/25 text-inherit'
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
