import { cn } from '@/lib/utils'

interface FilterPillProps {
  label: string
  active: boolean
  onClick: () => void
  color?: string
  count?: number
  className?: string
}

export function FilterPill({
  label,
  active,
  onClick,
  color,
  count,
  className,
}: FilterPillProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium transition-colors',
        'border focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
        active
          ? 'bg-primary text-primary-foreground border-primary'
          : 'bg-background text-muted-foreground border-input hover:bg-muted hover:text-foreground',
        className
      )}
    >
      {color && (
        <span
          className={cn('w-2 h-2 rounded-full', color)}
        />
      )}
      <span>{label}</span>
      {count !== undefined && (
        <span
          className={cn(
            'text-xs',
            active ? 'text-primary-foreground/80' : 'text-muted-foreground'
          )}
        >
          ({count})
        </span>
      )}
    </button>
  )
}
