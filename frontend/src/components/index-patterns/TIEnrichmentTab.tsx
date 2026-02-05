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
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Loader2, X, Search, ChevronDown, Shield } from 'lucide-react'
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

  // Track expansion state for sources and types
  const [expandedSources, setExpandedSources] = useState<Record<string, boolean>>({})
  const [expandedTypes, setExpandedTypes] = useState<Record<string, boolean>>({})

  // Track search and dropdown state per source+type combination
  const [fieldSearches, setFieldSearches] = useState<Record<string, string>>({})
  const [showDropdowns, setShowDropdowns] = useState<Record<string, boolean>>({})
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
      Object.entries(dropdownRefs.current).forEach(([key, ref]) => {
        if (ref && !ref.contains(event.target as Node)) {
          setShowDropdowns(prev => ({ ...prev, [key]: false }))
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

  const addField = (sourceType: string, indicatorType: TIIndicatorType, field: string) => {
    const sourceConfig = tiConfig[sourceType] || { enabled: true, fields: [] }
    const fieldConfig: TIFieldConfig = { field, type: indicatorType }

    // Check if field already exists for this type
    if (sourceConfig.fields.some(f => f.field === field && f.type === indicatorType)) {
      return
    }

    setTiConfig({
      ...tiConfig,
      [sourceType]: {
        ...sourceConfig,
        fields: [...sourceConfig.fields, fieldConfig],
      },
    })

    // Clear search
    const key = `${sourceType}-${indicatorType}`
    setFieldSearches(prev => ({ ...prev, [key]: '' }))
    setShowDropdowns(prev => ({ ...prev, [key]: false }))
  }

  const removeField = (sourceType: string, field: string, indicatorType: TIIndicatorType) => {
    const sourceConfig = tiConfig[sourceType]
    if (sourceConfig) {
      setTiConfig({
        ...tiConfig,
        [sourceType]: {
          ...sourceConfig,
          fields: sourceConfig.fields.filter(f => !(f.field === field && f.type === indicatorType)),
        },
      })
    }
  }

  // Toggle source expansion
  const toggleSourceExpanded = (sourceType: string) => {
    setExpandedSources(prev => ({ ...prev, [sourceType]: !prev[sourceType] }))
  }

  // Toggle type expansion within a source
  const toggleTypeExpanded = (sourceType: string, indicatorType: TIIndicatorType) => {
    const key = `${sourceType}-${indicatorType}`
    setExpandedTypes(prev => ({ ...prev, [key]: !prev[key] }))
  }

  // Get configured field count for a source
  const getSourceFieldCount = (sourceType: string): number => {
    return tiConfig[sourceType]?.fields?.length || 0
  }

  // Get configured field count for a specific type within a source
  const getTypeFieldCount = (sourceType: string, indicatorType: TIIndicatorType): number => {
    const sourceConfig = tiConfig[sourceType]
    if (!sourceConfig) return 0
    return sourceConfig.fields.filter(f => f.type === indicatorType).length
  }

  // Get fields configured for a specific type within a source
  const getFieldsForType = (sourceType: string, indicatorType: TIIndicatorType): TIFieldConfig[] => {
    const sourceConfig = tiConfig[sourceType]
    if (!sourceConfig) return []
    return sourceConfig.fields.filter(f => f.type === indicatorType)
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

  // Get filtered fields for a source+type (excluding already configured for that type)
  const getFilteredFields = (sourceType: string, indicatorType: TIIndicatorType) => {
    const key = `${sourceType}-${indicatorType}`
    const search = fieldSearches[key] || ''
    const configuredFields = getFieldsForType(sourceType, indicatorType).map(f => f.field)

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
          For each source, map your log fields to indicator types.
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
        <div className="space-y-3">
          {tiSources.map((source) => {
            const sourceType = source.source_type
            const sourceConfig = tiConfig[sourceType]
            const isEnabled = !!sourceConfig?.enabled
            const displayName = getSourceDisplayName(sourceType)
            const supportedTypes = getSupportedTypes(sourceType)
            const isSourceExpanded = expandedSources[sourceType] ?? false
            const sourceFieldCount = getSourceFieldCount(sourceType)

            return (
              <Collapsible
                key={sourceType}
                open={isSourceExpanded}
                onOpenChange={() => toggleSourceExpanded(sourceType)}
              >
                <div className="border rounded-lg">
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50">
                    <div className="flex items-center gap-3">
                      <ChevronDown
                        className={`h-4 w-4 transition-transform ${isSourceExpanded ? 'rotate-0' : '-rotate-90'}`}
                      />
                      <div className="text-left">
                        <div className="font-medium">{displayName}</div>
                        <div className="text-xs text-muted-foreground">
                          Supports: {supportedTypes.map(t => TI_INDICATOR_TYPE_INFO[t].label).join(', ')}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={isEnabled && sourceFieldCount > 0 ? 'default' : 'secondary'}>
                        {sourceFieldCount} field{sourceFieldCount !== 1 ? 's' : ''}
                      </Badge>
                      <Switch
                        checked={isEnabled}
                        onCheckedChange={(checked) => {
                          toggleSource(sourceType, checked)
                          // Auto-expand when enabling
                          if (checked && !isSourceExpanded) {
                            setExpandedSources(prev => ({ ...prev, [sourceType]: true }))
                          }
                        }}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </div>
                  </CollapsibleTrigger>

                  <CollapsibleContent>
                    {isEnabled ? (
                      <div className="px-4 pb-4 pt-2 border-t space-y-2">
                        {/* Indicator Type Categories */}
                        {supportedTypes.map((indicatorType) => {
                          const key = `${sourceType}-${indicatorType}`
                          const isTypeExpanded = expandedTypes[key] ?? false
                          const typeFieldCount = getTypeFieldCount(sourceType, indicatorType)
                          const fieldsForType = getFieldsForType(sourceType, indicatorType)
                          const fieldSearch = fieldSearches[key] || ''
                          const showDropdown = showDropdowns[key]
                          const filteredFields = getFilteredFields(sourceType, indicatorType)
                          const typeInfo = TI_INDICATOR_TYPE_INFO[indicatorType]

                          return (
                            <Collapsible
                              key={key}
                              open={isTypeExpanded}
                              onOpenChange={() => toggleTypeExpanded(sourceType, indicatorType)}
                            >
                              <div className={`border rounded-lg ${isTypeExpanded ? 'ring-1 ring-primary/50' : ''}`}>
                                <CollapsibleTrigger className="flex items-center justify-between w-full p-3 hover:bg-muted/50">
                                  <div className="flex items-center gap-2">
                                    <ChevronDown
                                      className={`h-3.5 w-3.5 transition-transform ${isTypeExpanded ? 'rotate-0' : '-rotate-90'}`}
                                    />
                                    <div className="text-left">
                                      <div className="font-medium text-sm">{typeInfo.label}</div>
                                      <div className="text-xs text-muted-foreground">
                                        {typeInfo.description}
                                      </div>
                                    </div>
                                  </div>
                                  <Badge variant={typeFieldCount > 0 ? 'default' : 'secondary'} className="text-xs">
                                    {typeFieldCount} field{typeFieldCount !== 1 ? 's' : ''}
                                  </Badge>
                                </CollapsibleTrigger>

                                <CollapsibleContent>
                                  <div className="px-3 pb-3 pt-2 border-t space-y-3">
                                    {/* Field Search */}
                                    <div
                                      ref={(el) => { dropdownRefs.current[key] = el }}
                                      className="relative"
                                    >
                                      <div className="relative">
                                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                        <Input
                                          value={fieldSearch}
                                          onChange={(e) => {
                                            setFieldSearches(prev => ({ ...prev, [key]: e.target.value }))
                                            setShowDropdowns(prev => ({ ...prev, [key]: true }))
                                          }}
                                          onFocus={() => setShowDropdowns(prev => ({ ...prev, [key]: true }))}
                                          placeholder="Search and add fields..."
                                          className="pl-9"
                                        />
                                      </div>
                                      {showDropdown && availableFields.length > 0 && (
                                        <div className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-48 overflow-y-auto">
                                          {filteredFields.length === 0 ? (
                                            <div className="px-3 py-2 text-sm text-muted-foreground">
                                              No matching fields
                                            </div>
                                          ) : (
                                            filteredFields.slice(0, 50).map((field) => (
                                              <button
                                                key={field}
                                                type="button"
                                                className="w-full px-3 py-2 text-left text-sm font-mono hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground outline-none"
                                                onClick={() => addField(sourceType, indicatorType, field)}
                                              >
                                                {field}
                                              </button>
                                            ))
                                          )}
                                          {filteredFields.length > 50 && (
                                            <div className="px-3 py-2 text-xs text-muted-foreground border-t">
                                              Showing first 50 of {filteredFields.length} matches
                                            </div>
                                          )}
                                        </div>
                                      )}
                                    </div>

                                    {/* Configured Fields List */}
                                    {fieldsForType.length > 0 ? (
                                      <div className="space-y-1">
                                        {fieldsForType.map((fieldConfig) => (
                                          <div
                                            key={fieldConfig.field}
                                            className="flex items-center justify-between py-1.5 px-2 bg-muted/50 rounded text-sm"
                                          >
                                            <code className="font-mono">{fieldConfig.field}</code>
                                            <button
                                              type="button"
                                              onClick={() => removeField(sourceType, fieldConfig.field, indicatorType)}
                                              className="hover:bg-muted rounded-full p-1"
                                            >
                                              <X className="h-3.5 w-3.5" />
                                            </button>
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <p className="text-xs text-muted-foreground italic">
                                        No fields mapped. Search and select fields above.
                                      </p>
                                    )}
                                  </div>
                                </CollapsibleContent>
                              </div>
                            </Collapsible>
                          )
                        })}
                      </div>
                    ) : (
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
