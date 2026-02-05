import { useState, useEffect, useRef } from 'react'
import {
  IndexPattern,
  indexPatternsApi,
  tiApi,
  TISourceConfig,
  TIConfig,
  TIFieldConfig,
  TIIndicatorType,
  TI_SOURCE_INFO,
  TI_SOURCE_SUPPORTED_TYPES,
  TI_INDICATOR_TYPE_INFO,
  TISourceType,
} from '@/lib/api'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Loader2, X, Search, ChevronDown, Shield } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Link } from 'react-router-dom'

interface TIEnrichmentTabProps {
  pattern: IndexPattern
  onDirtyChange?: (isDirty: boolean) => void
  onPendingChange?: (changes: Partial<IndexPattern>) => void
}

export function TIEnrichmentTab({ pattern, onDirtyChange, onPendingChange }: TIEnrichmentTabProps) {
  const [tiSources, setTiSources] = useState<TISourceConfig[]>([])
  const [tiConfig, setTiConfig] = useState<TIConfig>(pattern.ti_config || {})
  const [originalConfig] = useState<TIConfig>(pattern.ti_config || {})
  const [isLoading, setIsLoading] = useState(true)
  const [availableFields, setAvailableFields] = useState<string[]>([])

  // Track pending field additions per source (field search text and selected field)
  const [fieldSearches, setFieldSearches] = useState<Record<string, string>>({})
  const [selectedFields, setSelectedFields] = useState<Record<string, string>>({})
  const [showDropdowns, setShowDropdowns] = useState<Record<string, boolean>>({})
  const [expandedSources, setExpandedSources] = useState<Record<string, boolean>>({})
  const dropdownRefs = useRef<Record<string, HTMLDivElement | null>>({})

  // Load TI sources and available fields
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true)
      try {
        const [sourcesResponse, fields] = await Promise.all([
          tiApi.listSources(),
          indexPatternsApi.getFields(pattern.id),
        ])
        // Filter to only enabled sources with API keys configured
        setTiSources(sourcesResponse.sources.filter(s => s.is_enabled && s.has_api_key))
        setAvailableFields(fields.sort())
      } catch (err) {
        console.error('Failed to load TI data:', err)
      } finally {
        setIsLoading(false)
      }
    }
    loadData()
  }, [pattern.id])

  // Initialize config from pattern
  useEffect(() => {
    setTiConfig(pattern.ti_config || {})
  }, [pattern.ti_config])

  // Handle click outside to close dropdowns
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      Object.entries(dropdownRefs.current).forEach(([sourceType, ref]) => {
        if (ref && !ref.contains(event.target as Node)) {
          setShowDropdowns(prev => ({ ...prev, [sourceType]: false }))
        }
      })
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Track dirty state and report pending changes
  useEffect(() => {
    const isDirty = JSON.stringify(tiConfig) !== JSON.stringify(originalConfig)
    onDirtyChange?.(isDirty)
    if (isDirty) {
      onPendingChange?.({
        ti_config: Object.keys(tiConfig).length > 0 ? tiConfig : null,
      })
    }
  }, [tiConfig, originalConfig, onDirtyChange, onPendingChange])

  const toggleSource = (sourceType: string, enabled: boolean) => {
    if (enabled) {
      setTiConfig({
        ...tiConfig,
        [sourceType]: { enabled: true, fields: [] },
      })
    } else {
      const newConfig = { ...tiConfig }
      delete newConfig[sourceType]
      setTiConfig(newConfig)
    }
  }

  const selectField = (sourceType: string, field: string) => {
    setSelectedFields(prev => ({ ...prev, [sourceType]: field }))
    setFieldSearches(prev => ({ ...prev, [sourceType]: field }))
    setShowDropdowns(prev => ({ ...prev, [sourceType]: false }))
  }

  const addFieldWithType = (sourceType: string, indicatorType: TIIndicatorType) => {
    const field = selectedFields[sourceType]
    if (!field) return

    const sourceConfig = tiConfig[sourceType] || { enabled: true, fields: [] }
    const fieldConfig: TIFieldConfig = { field, type: indicatorType }

    // Check if field already exists
    if (sourceConfig.fields.some(f => f.field === field)) {
      return
    }

    setTiConfig({
      ...tiConfig,
      [sourceType]: {
        ...sourceConfig,
        fields: [...sourceConfig.fields, fieldConfig],
      },
    })

    // Clear selection
    setSelectedFields(prev => {
      const updated = { ...prev }
      delete updated[sourceType]
      return updated
    })
    setFieldSearches(prev => {
      const updated = { ...prev }
      delete updated[sourceType]
      return updated
    })
  }

  const removeField = (sourceType: string, field: string) => {
    const sourceConfig = tiConfig[sourceType]
    if (sourceConfig) {
      setTiConfig({
        ...tiConfig,
        [sourceType]: {
          ...sourceConfig,
          fields: sourceConfig.fields.filter(f => f.field !== field),
        },
      })
    }
  }

  // Toggle source expansion
  const toggleExpanded = (sourceType: string) => {
    setExpandedSources(prev => ({ ...prev, [sourceType]: !prev[sourceType] }))
  }

  // Get configured field count for a source
  const getFieldCount = (sourceType: string): number => {
    return tiConfig[sourceType]?.fields?.length || 0
  }

  // Get display name for a TI source type
  const getSourceDisplayName = (sourceType: string): string => {
    const info = TI_SOURCE_INFO[sourceType as keyof typeof TI_SOURCE_INFO]
    return info?.name || sourceType
  }

  // Get supported indicator types for a source
  const getSupportedTypes = (sourceType: string): TIIndicatorType[] => {
    return TI_SOURCE_SUPPORTED_TYPES[sourceType as TISourceType] || []
  }

  // Get filtered fields for a source (excluding already configured)
  const getFilteredFields = (sourceType: string) => {
    const search = fieldSearches[sourceType] || ''
    const sourceConfig = tiConfig[sourceType]
    const configuredFields = sourceConfig?.fields?.map(f => f.field) || []

    return availableFields
      .filter(f => !configuredFields.includes(f))
      .filter(f => f.toLowerCase().includes(search.toLowerCase()))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Threat Intelligence Enrichment</h3>
        <p className="text-sm text-muted-foreground">
          Configure which threat intelligence sources to use for enriching logs from this index pattern.
          For each source, select fields and specify what type of indicator they contain.
        </p>
      </div>

      {tiSources.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>No enabled threat intelligence sources found.</p>
          <p className="text-sm mt-2">
            Configure and enable TI sources in{' '}
            <Link to="/settings?tab=ti" className="text-primary hover:underline">
              Settings → Threat Intel
            </Link>
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {tiSources.map((source) => {
            const sourceType = source.source_type
            const sourceConfig = tiConfig[sourceType]
            const isEnabled = !!sourceConfig?.enabled
            const displayName = getSourceDisplayName(sourceType)
            const supportedTypes = getSupportedTypes(sourceType)
            const selectedField = selectedFields[sourceType]
            const fieldSearch = fieldSearches[sourceType] || ''
            const showDropdown = showDropdowns[sourceType]
            const filteredFields = getFilteredFields(sourceType)
            const isExpanded = expandedSources[sourceType] ?? false
            const fieldCount = getFieldCount(sourceType)

            return (
              <Collapsible
                key={sourceType}
                open={isExpanded}
                onOpenChange={() => toggleExpanded(sourceType)}
              >
                <div className="border rounded-lg">
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50">
                    <div className="flex items-center gap-3">
                      <ChevronDown
                        className={`h-4 w-4 transition-transform ${isExpanded ? 'rotate-0' : '-rotate-90'}`}
                      />
                      <div className="text-left">
                        <div className="font-medium">{displayName}</div>
                        <div className="text-xs text-muted-foreground">
                          Supports: {supportedTypes.map(t => TI_INDICATOR_TYPE_INFO[t].label).join(', ')}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={isEnabled && fieldCount > 0 ? 'default' : 'secondary'}>
                        {fieldCount} field{fieldCount !== 1 ? 's' : ''}
                      </Badge>
                      <Switch
                        checked={isEnabled}
                        onCheckedChange={(checked) => {
                          toggleSource(sourceType, checked)
                          // Auto-expand when enabling
                          if (checked && !isExpanded) {
                            setExpandedSources(prev => ({ ...prev, [sourceType]: true }))
                          }
                        }}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </div>
                  </CollapsibleTrigger>

                  <CollapsibleContent>
                    {isEnabled && (
                      <div className="px-4 pb-4 pt-2 border-t space-y-3">
                        <Label className="text-sm">Fields to Check</Label>

                        {/* Field Selection with Search */}
                        <div className="flex gap-2">
                          <div
                            ref={(el) => { dropdownRefs.current[sourceType] = el }}
                            className="relative flex-1"
                          >
                            <div className="relative">
                              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                              <Input
                                value={fieldSearch}
                                onChange={(e) => {
                                  setFieldSearches(prev => ({ ...prev, [sourceType]: e.target.value }))
                                  setSelectedFields(prev => ({ ...prev, [sourceType]: e.target.value }))
                                  setShowDropdowns(prev => ({ ...prev, [sourceType]: true }))
                                }}
                                onFocus={() => setShowDropdowns(prev => ({ ...prev, [sourceType]: true }))}
                                placeholder="Search and add fields..."
                                className="pl-9"
                              />
                            </div>
                            {showDropdown && availableFields.length > 0 && (
                              <div className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-60 overflow-y-auto">
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
                                      onClick={() => selectField(sourceType, field)}
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

                          {/* Indicator Type Selection - only show when field is selected */}
                          {selectedField && (
                            <Select
                              value=""
                              onValueChange={(type) => addFieldWithType(sourceType, type as TIIndicatorType)}
                            >
                              <SelectTrigger className="w-48">
                                <SelectValue placeholder="Select type..." />
                              </SelectTrigger>
                              <SelectContent>
                                {supportedTypes.map((type) => (
                                  <SelectItem key={type} value={type}>
                                    {TI_INDICATOR_TYPE_INFO[type].label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          )}
                        </div>

                        {/* Configured Fields List */}
                        {sourceConfig?.fields && sourceConfig.fields.length > 0 ? (
                          <div className="space-y-2">
                            {sourceConfig.fields.map((fieldConfig) => (
                              <div
                                key={fieldConfig.field}
                                className="flex items-center justify-between p-2 bg-muted/50 rounded"
                              >
                                <div className="flex items-center gap-2">
                                  <code className="text-sm font-mono">{fieldConfig.field}</code>
                                  <Badge variant="outline" className="text-xs">
                                    {TI_INDICATOR_TYPE_INFO[fieldConfig.type]?.label || fieldConfig.type}
                                  </Badge>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => removeField(sourceType, fieldConfig.field)}
                                  className="hover:bg-muted rounded-full p-1"
                                >
                                  <X className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground italic">
                            No fields configured. Search and select a field, then choose its indicator type.
                          </p>
                        )}
                      </div>
                    )}

                    {!isEnabled && (
                      <div className="px-4 pb-4 pt-2 border-t">
                        <p className="text-xs text-muted-foreground italic">
                          Enable this source to configure field mappings.
                        </p>
                      </div>
                    )}
                  </CollapsibleContent>
                </div>
              </Collapsible>
            )
          })}
        </div>
      )}

    </div>
  )
}
