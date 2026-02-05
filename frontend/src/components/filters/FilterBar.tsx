import { useState } from 'react'
import { Search, X, ChevronDown, ChevronUp } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface FilterBarSearchProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}

interface ActiveFilter {
  key: string
  label: string
  onRemove: () => void
}

interface FilterBarProps {
  search?: FilterBarSearchProps
  primaryFilters?: React.ReactNode
  secondaryFilters?: React.ReactNode
  actions?: React.ReactNode
  onReset?: () => void
  activeFilterCount?: number
  activeFilters?: ActiveFilter[]
  className?: string
  collapsibleSecondary?: boolean  // Enable collapsible on mobile
}

export function FilterBar({
  search,
  primaryFilters,
  secondaryFilters,
  actions,
  onReset,
  activeFilterCount = 0,
  activeFilters,
  className,
  collapsibleSecondary = true,
}: FilterBarProps) {
  const [secondaryExpanded, setSecondaryExpanded] = useState(true)

  return (
    <div className={cn('space-y-3', className)}>
      {/* Primary row: Search + primary filters + actions */}
      <div className="flex flex-wrap items-center gap-3">
        {search && (
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder={search.placeholder || 'Search...'}
              value={search.value}
              onChange={(e) => search.onChange(e.target.value)}
              className="pl-10"
            />
            {search.value && (
              <button
                type="button"
                onClick={() => search.onChange('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Clear search"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        )}

        {primaryFilters && (
          <div className="flex items-center gap-2">
            {primaryFilters}
          </div>
        )}

        {actions && (
          <div className="flex items-center gap-2 ml-auto">
            {actions}
          </div>
        )}

        {/* Mobile toggle for secondary filters */}
        {secondaryFilters && collapsibleSecondary && (
          <Button
            variant="ghost"
            size="sm"
            className="md:hidden"
            onClick={() => setSecondaryExpanded(!secondaryExpanded)}
          >
            {secondaryExpanded ? (
              <ChevronUp className="h-4 w-4 mr-1" />
            ) : (
              <ChevronDown className="h-4 w-4 mr-1" />
            )}
            Filters
            {activeFilterCount > 0 && (
              <Badge variant="secondary" className="ml-1">
                {activeFilterCount}
              </Badge>
            )}
          </Button>
        )}
      </div>

      {/* Secondary row: Filter pills */}
      {secondaryFilters && (
        <div
          className={cn(
            'flex flex-wrap items-center gap-2 transition-all',
            collapsibleSecondary && !secondaryExpanded && 'hidden md:flex'
          )}
        >
          {secondaryFilters}

          {activeFilterCount > 0 && onReset && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onReset}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3 mr-1" />
              Clear all
            </Button>
          )}
        </div>
      )}

      {/* Active filters display */}
      {activeFilters && activeFilters.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t">
          <span className="text-xs text-muted-foreground">Active:</span>
          {activeFilters.map((filter) => (
            <Badge
              key={filter.key}
              variant="secondary"
              className="gap-1 pr-1"
            >
              {filter.label}
              <button
                type="button"
                onClick={filter.onRemove}
                className="ml-1 rounded-sm hover:bg-muted p-0.5"
                aria-label={`Remove filter: ${filter.label}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}

export { FilterPill } from './FilterPill'
