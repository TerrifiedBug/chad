import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  IndexPattern,
  indexPatternsApi,
  mispApi,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import {
  AlertTriangle,
  ChevronDown,
  Loader2,
  Save,
  Search,
  X,
} from 'lucide-react'

// IOC types supported for detection
const IOC_TYPES = [
  { value: 'ip-dst', label: 'Destination IP', description: 'Destination IP addresses (e.g., dest_ip, dst_addr)' },
  { value: 'ip-src', label: 'Source IP', description: 'Source IP addresses (e.g., src_ip, source_addr)' },
  { value: 'domain', label: 'Domain', description: 'Domain names and hostnames' },
  { value: 'md5', label: 'MD5 Hash', description: '32-character MD5 file hashes' },
  { value: 'sha256', label: 'SHA256 Hash', description: '64-character SHA256 file hashes' },
  { value: 'url', label: 'URL', description: 'Full URLs including protocol' },
] as const

interface IOCDetectionTabProps {
  pattern: IndexPattern
  onPatternUpdated: (pattern: IndexPattern) => void
}

export function IOCDetectionTab({ pattern, onPatternUpdated }: IOCDetectionTabProps) {
  const { showToast } = useToast()
  const [iocEnabled, setIocEnabled] = useState(pattern.ioc_detection_enabled)
  const [fieldMappings, setFieldMappings] = useState<Record<string, string[]>>(
    pattern.ioc_field_mappings || {}
  )
  const [isSaving, setIsSaving] = useState(false)
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(true)

  // Track search and dropdown state per IOC type
  const [fieldSearches, setFieldSearches] = useState<Record<string, string>>({})
  const [showDropdowns, setShowDropdowns] = useState<Record<string, boolean>>({})
  const [expandedTypes, setExpandedTypes] = useState<Record<string, boolean>>({})
  const dropdownRefs = useRef<Record<string, HTMLDivElement | null>>({})

  // Check MISP status
  const { data: mispStatus, isLoading: isLoadingMisp } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
    staleTime: 60 * 1000, // 1 minute
  })

  // Load available fields
  useEffect(() => {
    const loadFields = async () => {
      setIsLoadingFields(true)
      try {
        const fields = await indexPatternsApi.getFields(pattern.id)
        setAvailableFields(fields.sort())
      } catch (err) {
        console.error('Failed to load fields:', err)
      } finally {
        setIsLoadingFields(false)
      }
    }
    loadFields()
  }, [pattern.id])

  // Initialize state from pattern
  useEffect(() => {
    setIocEnabled(pattern.ioc_detection_enabled)
    setFieldMappings(pattern.ioc_field_mappings || {})
  }, [pattern.ioc_detection_enabled, pattern.ioc_field_mappings])

  // Handle click outside to close dropdowns
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      Object.entries(dropdownRefs.current).forEach(([iocType, ref]) => {
        if (ref && !ref.contains(event.target as Node)) {
          setShowDropdowns(prev => ({ ...prev, [iocType]: false }))
        }
      })
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSave = async () => {
    setIsSaving(true)
    try {
      // Clean up empty arrays from field mappings
      const cleanedMappings: Record<string, string[]> = {}
      for (const [iocType, fields] of Object.entries(fieldMappings)) {
        if (fields.length > 0) {
          cleanedMappings[iocType] = fields
        }
      }

      const updated = await indexPatternsApi.update(pattern.id, {
        ioc_detection_enabled: iocEnabled,
        ioc_field_mappings: Object.keys(cleanedMappings).length > 0 ? cleanedMappings : null,
      })
      onPatternUpdated(updated)
      showToast('IOC detection settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const toggleExpanded = (iocType: string) => {
    setExpandedTypes(prev => ({ ...prev, [iocType]: !prev[iocType] }))
  }

  const selectField = (iocType: string, field: string) => {
    const currentFields = fieldMappings[iocType] || []
    if (!currentFields.includes(field)) {
      setFieldMappings({
        ...fieldMappings,
        [iocType]: [...currentFields, field],
      })
    }
    setFieldSearches(prev => ({ ...prev, [iocType]: '' }))
    setShowDropdowns(prev => ({ ...prev, [iocType]: false }))
  }

  const removeField = (iocType: string, field: string) => {
    const currentFields = fieldMappings[iocType] || []
    setFieldMappings({
      ...fieldMappings,
      [iocType]: currentFields.filter(f => f !== field),
    })
  }

  const getFilteredFields = (iocType: string) => {
    const search = fieldSearches[iocType] || ''
    const configuredFields = fieldMappings[iocType] || []

    return availableFields
      .filter(f => !configuredFields.includes(f))
      .filter(f => f.toLowerCase().includes(search.toLowerCase()))
  }

  const getConfiguredFieldCount = (iocType: string): number => {
    return (fieldMappings[iocType] || []).length
  }

  const isMispConfigured = mispStatus?.configured && mispStatus?.connected

  if (isLoadingMisp || isLoadingFields) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">IOC Detection</h3>
        <p className="text-sm text-muted-foreground">
          Automatically detect indicators of compromise (IOCs) in logs by matching field values
          against your MISP instance. Matches will be enriched on alerts.
        </p>
      </div>

      {!isMispConfigured && (
        <div className="flex items-start gap-3 p-4 bg-yellow-50 dark:bg-yellow-950/30 border border-yellow-200 dark:border-yellow-900 rounded-lg">
          <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
              MISP Not Configured
            </p>
            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
              IOC detection requires a configured and connected MISP instance.
              Configure MISP in Settings → Threat Intel → MISP.
            </p>
          </div>
        </div>
      )}

      {/* Mode explanation */}
      <div className="p-4 bg-muted/50 border rounded-lg">
        <p className="text-sm text-muted-foreground">
          <strong>Current mode:</strong> {pattern.mode === 'push' ? 'Push' : 'Pull'}
          {pattern.mode === 'push' ? (
            <span className="block mt-1">
              IOC matching occurs in real-time as logs arrive in CHAD.
            </span>
          ) : (
            <span className="block mt-1">
              IOC matching queries OpenSearch on scheduled intervals.
            </span>
          )}
        </p>
      </div>

      <div className="flex items-center justify-between p-4 border rounded-lg">
        <div>
          <Label className="font-medium">Enable IOC Detection</Label>
          <p className="text-sm text-muted-foreground">
            Check logs against MISP IOCs
          </p>
        </div>
        <Switch
          checked={iocEnabled}
          onCheckedChange={setIocEnabled}
          disabled={!isMispConfigured}
        />
      </div>

      {iocEnabled && isMispConfigured && (
        <div className="space-y-3">
          <div>
            <Label className="text-base font-medium">Field Mappings</Label>
            <p className="text-sm text-muted-foreground">
              Map log fields to IOC types. When a log arrives, these fields will be checked
              against the corresponding IOC type in MISP.
            </p>
          </div>

          <div className="space-y-2">
            {IOC_TYPES.map((iocType) => {
              const isExpanded = expandedTypes[iocType.value] ?? false
              const fieldCount = getConfiguredFieldCount(iocType.value)
              const fieldSearch = fieldSearches[iocType.value] || ''
              const showDropdown = showDropdowns[iocType.value]
              const filteredFields = getFilteredFields(iocType.value)
              const configuredFields = fieldMappings[iocType.value] || []

              return (
                <Collapsible
                  key={iocType.value}
                  open={isExpanded}
                  onOpenChange={() => toggleExpanded(iocType.value)}
                >
                  <div className="border rounded-lg">
                    <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50">
                      <div className="flex items-center gap-3">
                        <ChevronDown
                          className={`h-4 w-4 transition-transform ${isExpanded ? 'rotate-0' : '-rotate-90'}`}
                        />
                        <div className="text-left">
                          <div className="font-medium">{iocType.label}</div>
                          <div className="text-xs text-muted-foreground">
                            {iocType.description}
                          </div>
                        </div>
                      </div>
                      <Badge variant={fieldCount > 0 ? 'default' : 'secondary'}>
                        {fieldCount} field{fieldCount !== 1 ? 's' : ''}
                      </Badge>
                    </CollapsibleTrigger>

                    <CollapsibleContent>
                      <div className="px-4 pb-4 pt-2 border-t space-y-3">
                        {/* Field Search */}
                        <div
                          ref={(el) => { dropdownRefs.current[iocType.value] = el }}
                          className="relative"
                        >
                          <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                              value={fieldSearch}
                              onChange={(e) => {
                                setFieldSearches(prev => ({ ...prev, [iocType.value]: e.target.value }))
                                setShowDropdowns(prev => ({ ...prev, [iocType.value]: true }))
                              }}
                              onFocus={() => setShowDropdowns(prev => ({ ...prev, [iocType.value]: true }))}
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
                                    onClick={() => selectField(iocType.value, field)}
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

                        {/* Configured Fields List */}
                        {configuredFields.length > 0 ? (
                          <div className="space-y-2">
                            {configuredFields.map((field) => (
                              <div
                                key={field}
                                className="flex items-center justify-between p-2 bg-muted/50 rounded"
                              >
                                <code className="text-sm font-mono">{field}</code>
                                <button
                                  type="button"
                                  onClick={() => removeField(iocType.value, field)}
                                  className="hover:bg-muted rounded-full p-1"
                                >
                                  <X className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground italic">
                            No fields configured. Search and select fields to check for this IOC type.
                          </p>
                        )}
                      </div>
                    </CollapsibleContent>
                  </div>
                </Collapsible>
              )
            })}
          </div>
        </div>
      )}

      <div className="flex justify-end pt-4 border-t">
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              Save Changes
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
