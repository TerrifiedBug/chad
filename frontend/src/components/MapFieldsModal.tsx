import { useState, useEffect, useRef } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Loader2, Sparkles, Check, X, Search } from 'lucide-react'
import {
  fieldMappingsApi,
  indexPatternsApi,
  AISuggestion,
} from '@/lib/api'

type MappingEntry = {
  sigmaField: string
  targetField: string
  searchValue: string
  confidence?: number
  reason?: string
}

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  unmappedFields: string[]
  indexPatternId: string
  onMappingsSaved: () => void
}

export function MapFieldsModal({
  open,
  onOpenChange,
  unmappedFields,
  indexPatternId,
  onMappingsSaved,
}: Props) {
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [indexPatternName, setIndexPatternName] = useState('')
  const [mappings, setMappings] = useState<MappingEntry[]>([])
  const [scope, setScope] = useState<'index' | 'global'>('index')
  const [isLoading, setIsLoading] = useState(false)
  const [isSuggestingAI, setIsSuggestingAI] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState('')
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Load available fields from index when modal opens
  useEffect(() => {
    if (open && indexPatternId) {
      loadIndexFields()
      initializeMappings()
    }
  }, [open, indexPatternId, unmappedFields])

  const loadIndexFields = async () => {
    setIsLoading(true)
    try {
      // Get index pattern details
      const patterns = await indexPatternsApi.list()
      const pattern = patterns.find((p) => p.id === indexPatternId)
      if (pattern) {
        setIndexPatternName(pattern.name)
        // Get fields from index
        const fields = await indexPatternsApi.getFields(indexPatternId)
        setAvailableFields(fields.sort())
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load index fields')
    } finally {
      setIsLoading(false)
    }
  }

  const initializeMappings = () => {
    setMappings(
      unmappedFields.map((field) => ({
        sigmaField: field,
        targetField: '',
        searchValue: '',
      }))
    )
    setActiveDropdown(null)
  }

  // Handle click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setActiveDropdown(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleFieldChange = (sigmaField: string, targetField: string, searchValue?: string) => {
    setMappings((prev) =>
      prev.map((m) =>
        m.sigmaField === sigmaField
          ? { ...m, targetField, searchValue: searchValue ?? targetField, confidence: undefined, reason: undefined }
          : m
      )
    )
  }

  const handleSearchChange = (sigmaField: string, searchValue: string) => {
    setMappings((prev) =>
      prev.map((m) =>
        m.sigmaField === sigmaField
          ? { ...m, searchValue, targetField: searchValue }
          : m
      )
    )
  }

  const getFilteredFields = (searchValue: string) => {
    if (!searchValue) return availableFields
    return availableFields.filter((f) =>
      f.toLowerCase().includes(searchValue.toLowerCase())
    )
  }

  const handleSuggestAI = async () => {
    setIsSuggestingAI(true)
    setError('')
    try {
      const suggestions = await fieldMappingsApi.suggest({
        index_pattern_id: indexPatternId,
        sigma_fields: unmappedFields,
      })

      // Apply suggestions to mappings
      setMappings((prev) =>
        prev.map((m) => {
          const suggestion = suggestions.find(
            (s: AISuggestion) => s.sigma_field === m.sigmaField
          )
          if (suggestion && suggestion.target_field) {
            return {
              ...m,
              targetField: suggestion.target_field,
              searchValue: suggestion.target_field,
              confidence: suggestion.confidence,
              reason: suggestion.reason,
            }
          }
          return m
        })
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI suggestion failed')
    } finally {
      setIsSuggestingAI(false)
    }
  }

  const handleSave = async () => {
    // Filter out unmapped fields
    const validMappings = mappings.filter((m) => m.targetField)
    if (validMappings.length === 0) {
      setError('Please map at least one field')
      return
    }

    setIsSaving(true)
    setError('')
    try {
      // Create mappings
      for (const mapping of validMappings) {
        await fieldMappingsApi.create({
          sigma_field: mapping.sigmaField,
          target_field: mapping.targetField,
          index_pattern_id: scope === 'index' ? indexPatternId : null,
          origin: mapping.confidence !== undefined ? 'ai_suggested' : 'manual',
          confidence: mapping.confidence,
        })
      }
      onMappingsSaved()
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save mappings')
    } finally {
      setIsSaving(false)
    }
  }

  const mappedCount = mappings.filter((m) => m.targetField).length
  const totalCount = mappings.length

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Map Fields</DialogTitle>
          <DialogDescription>
            Map Sigma rule fields to your log field names for index pattern:{' '}
            <strong>{indexPatternName}</strong>
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
            {error}
          </div>
        )}

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="space-y-4">
            {/* Scope Selection */}
            <div className="space-y-2">
              <Label>Mapping Scope</Label>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant={scope === 'index' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setScope('index')}
                >
                  This index only
                </Button>
                <Button
                  type="button"
                  variant={scope === 'global' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setScope('global')}
                >
                  Global (all indices)
                </Button>
              </div>
            </div>

            {/* Field Mappings Table */}
            <div className="border rounded-md">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left text-sm font-medium p-3">Sigma Field</th>
                    <th className="text-left text-sm font-medium p-3">Target Field</th>
                    <th className="text-left text-sm font-medium p-3 w-24">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {mappings.map((mapping) => (
                    <tr key={mapping.sigmaField} className="border-b last:border-b-0">
                      <td className="p-3">
                        <code className="text-sm bg-muted px-1.5 py-0.5 rounded">
                          {mapping.sigmaField}
                        </code>
                      </td>
                      <td className="p-3">
                        <div
                          ref={activeDropdown === mapping.sigmaField ? dropdownRef : undefined}
                          className="relative"
                        >
                          <div className="relative">
                            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                              value={mapping.searchValue}
                              onChange={(e) => {
                                handleSearchChange(mapping.sigmaField, e.target.value)
                                setActiveDropdown(mapping.sigmaField)
                              }}
                              onFocus={() => setActiveDropdown(mapping.sigmaField)}
                              placeholder="Search fields..."
                              className="pl-8 h-9 text-sm font-mono"
                            />
                          </div>
                          {activeDropdown === mapping.sigmaField && availableFields.length > 0 && (
                            <div className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-48 overflow-y-auto">
                              {(() => {
                                const filtered = getFilteredFields(mapping.searchValue)
                                if (filtered.length === 0) {
                                  return (
                                    <div className="px-3 py-2 text-sm text-muted-foreground">
                                      No matching fields
                                    </div>
                                  )
                                }
                                return (
                                  <>
                                    {filtered.slice(0, 100).map((field) => (
                                      <button
                                        key={field}
                                        type="button"
                                        className="w-full px-3 py-1.5 text-left text-sm font-mono hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground outline-none"
                                        onClick={() => {
                                          handleFieldChange(mapping.sigmaField, field, field)
                                          setActiveDropdown(null)
                                        }}
                                      >
                                        {field}
                                      </button>
                                    ))}
                                    {filtered.length > 100 && (
                                      <div className="px-3 py-1.5 text-xs text-muted-foreground border-t">
                                        Showing first 100 of {filtered.length} matches
                                      </div>
                                    )}
                                  </>
                                )
                              })()}
                            </div>
                          )}
                        </div>
                        {mapping.confidence !== undefined && mapping.reason && (
                          <div className="text-xs text-muted-foreground mt-1">
                            AI: {mapping.reason} ({Math.round(mapping.confidence * 100)}%)
                          </div>
                        )}
                      </td>
                      <td className="p-3">
                        {mapping.targetField ? (
                          <span className="flex items-center gap-1 text-green-600 text-sm">
                            <Check className="h-4 w-4" />
                            Mapped
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-muted-foreground text-sm">
                            <X className="h-4 w-4" />
                            Unmapped
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* AI Suggest Button */}
            <Button
              variant="outline"
              onClick={handleSuggestAI}
              disabled={isSuggestingAI}
              className="w-full"
            >
              <Sparkles className="h-4 w-4 mr-2" />
              {isSuggestingAI ? 'Getting AI Suggestions...' : 'Suggest with AI'}
            </Button>
          </div>
        )}

        <DialogFooter className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            {mappedCount} of {totalCount} fields mapped
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={isSaving || mappedCount === 0}>
              {isSaving ? 'Saving...' : 'Save Mappings'}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
