import { useState } from 'react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ChevronDown, Loader2 } from 'lucide-react'

interface SearchableFieldSelectorProps {
  fields: string[]
  value: string | null
  onChange?: (value: string) => void
  onSelect?: (value: string) => void
  label?: string
  placeholder?: string
  description?: string
  disabled?: boolean
  isLoading?: boolean
  emptyMessage?: string
}

export function SearchableFieldSelector({
  fields,
  value,
  onChange,
  onSelect,
  label,
  placeholder = "Select a field...",
  description,
  disabled = false,
  isLoading = false,
  emptyMessage = "No fields available",
}: SearchableFieldSelectorProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  const filteredFields = fields.filter((field) =>
    field.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-2">
      {label && <Label>{label}</Label>}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            className="w-full justify-between"
            disabled={disabled}
          >
            {value || placeholder}
            {isLoading ? (
              <Loader2 className="ml-2 h-4 w-4 animate-spin text-muted-foreground" />
            ) : (
              <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[300px] p-0">
          <div className="p-2">
            <Input
              placeholder="Search fields..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 text-sm"
            />
          </div>
          <div className="max-h-[300px] overflow-y-auto">
            {filteredFields.length === 0 ? (
              <div className="p-4 text-sm text-muted-foreground text-center">
                {isLoading ? 'Loading fields...' : emptyMessage}
              </div>
            ) : (
              <div className="p-1">
                {filteredFields.map((field) => (
                  <button
                    key={field}
                    onClick={() => {
                      if (onChange) {
                        onChange(field)
                      }
                      if (onSelect) {
                        onSelect(field)
                      }
                      setOpen(false)
                      setSearch('')
                    }}
                    disabled={!onChange}
                    className="flex items-center gap-2 w-full px-2 py-1.5 text-sm hover:bg-accent rounded-sm cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span className="font-medium">{field}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </PopoverContent>
      </Popover>
      {description && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
    </div>
  )
}
