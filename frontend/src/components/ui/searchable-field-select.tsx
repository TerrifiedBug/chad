import { useState, useRef, useEffect } from 'react'
import { Input } from '@/components/ui/input'
import { Search } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SearchableFieldSelectProps {
  fields: string[]
  value?: string
  placeholder?: string
  onSelect: (field: string) => void
  /** Called when the input value changes (on typing) */
  onChange?: (value: string) => void
  /** Clear search after selection (useful for multi-select scenarios) */
  clearOnSelect?: boolean
  /** Exclude these fields from the dropdown */
  excludeFields?: string[]
  /** Maximum height of dropdown (default: 15rem / 240px) */
  maxDropdownHeight?: string
  className?: string
}

export function SearchableFieldSelect({
  fields,
  value = '',
  placeholder = 'Search and select a field...',
  onSelect,
  onChange,
  clearOnSelect = false,
  excludeFields = [],
  maxDropdownHeight = '15rem',
  className,
}: SearchableFieldSelectProps) {
  const [search, setSearch] = useState(value)
  const [showDropdown, setShowDropdown] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  // Sync external value changes
  useEffect(() => {
    setSearch(value)
  }, [value])

  // Handle click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setShowDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const filteredFields = fields
    .filter((f) => !excludeFields.includes(f))
    .filter((f) => f.toLowerCase().includes(search.toLowerCase()))

  const handleSelect = (field: string) => {
    if (clearOnSelect) {
      setSearch('')
    } else {
      setSearch(field)
    }
    setShowDropdown(false)
    onSelect(field)
  }

  return (
    <div ref={containerRef} className={cn('relative', className)}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setShowDropdown(true)
            onChange?.(e.target.value)
          }}
          onFocus={() => setShowDropdown(true)}
          placeholder={placeholder}
          className="pl-9"
        />
      </div>
      {showDropdown && fields.length > 0 && (
        <div
          className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md overflow-y-auto"
          style={{ maxHeight: maxDropdownHeight }}
        >
          {filteredFields.length === 0 ? (
            <div className="px-3 py-2 text-sm text-muted-foreground">
              No matching fields
            </div>
          ) : (
            filteredFields.slice(0, 100).map((field) => (
              <button
                key={field}
                type="button"
                className="w-full px-3 py-2 text-left text-sm font-mono hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground outline-none"
                onClick={() => handleSelect(field)}
              >
                {field}
              </button>
            ))
          )}
          {filteredFields.length > 100 && (
            <div className="px-3 py-2 text-xs text-muted-foreground border-t">
              Showing first 100 of {filteredFields.length} matches
            </div>
          )}
        </div>
      )}
    </div>
  )
}
