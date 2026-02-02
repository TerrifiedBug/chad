import { useState, useEffect } from 'react'
import { IndexPattern, indexPatternsApi, tiApi, TISourceConfig, TIConfig, TI_SOURCE_INFO } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Loader2, Save, X } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface TIEnrichmentTabProps {
  pattern: IndexPattern
  onPatternUpdated: (pattern: IndexPattern) => void
}

export function TIEnrichmentTab({ pattern, onPatternUpdated }: TIEnrichmentTabProps) {
  const { showToast } = useToast()
  const [tiSources, setTiSources] = useState<TISourceConfig[]>([])
  const [tiConfig, setTiConfig] = useState<TIConfig>(pattern.ti_config || {})
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [availableFields, setAvailableFields] = useState<string[]>([])

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
        setAvailableFields(fields)
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

  const handleSave = async () => {
    setIsSaving(true)
    try {
      const updated = await indexPatternsApi.update(pattern.id, {
        ti_config: Object.keys(tiConfig).length > 0 ? tiConfig : null,
      })
      onPatternUpdated(updated)
      showToast('Threat intelligence settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

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

  const addField = (sourceType: string, field: string) => {
    const sourceConfig = tiConfig[sourceType] || { enabled: true, fields: [] }
    if (!sourceConfig.fields.includes(field)) {
      setTiConfig({
        ...tiConfig,
        [sourceType]: {
          ...sourceConfig,
          fields: [...sourceConfig.fields, field],
        },
      })
    }
  }

  const removeField = (sourceType: string, field: string) => {
    const sourceConfig = tiConfig[sourceType]
    if (sourceConfig) {
      setTiConfig({
        ...tiConfig,
        [sourceType]: {
          ...sourceConfig,
          fields: sourceConfig.fields.filter(f => f !== field),
        },
      })
    }
  }

  // Get display name for a TI source type
  const getSourceDisplayName = (sourceType: string): string => {
    const info = TI_SOURCE_INFO[sourceType as keyof typeof TI_SOURCE_INFO]
    return info?.name || sourceType
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
        </p>
      </div>

      {tiSources.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <p>No enabled threat intelligence sources found.</p>
          <p className="text-sm">Configure and enable TI sources in Settings → Threat Intel.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tiSources.map((source) => {
            const sourceConfig = tiConfig[source.source_type]
            const isEnabled = !!sourceConfig?.enabled
            const displayName = getSourceDisplayName(source.source_type)

            return (
              <div key={source.source_type} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <Label className="font-medium">{displayName}</Label>
                    <p className="text-xs text-muted-foreground capitalize">{source.source_type}</p>
                  </div>
                  <Switch
                    checked={isEnabled}
                    onCheckedChange={(checked) => toggleSource(source.source_type, checked)}
                  />
                </div>

                {isEnabled && (
                  <div className="space-y-3 pt-3 border-t">
                    <Label className="text-sm">Fields to Check</Label>
                    <div className="flex gap-2">
                      <Select
                        value=""
                        onValueChange={(field) => addField(source.source_type, field)}
                      >
                        <SelectTrigger className="flex-1">
                          <SelectValue placeholder="Add field to check..." />
                        </SelectTrigger>
                        <SelectContent>
                          {availableFields
                            .filter(f => !sourceConfig?.fields?.includes(f))
                            .map((field) => (
                              <SelectItem key={field} value={field}>
                                {field}
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {sourceConfig?.fields && sourceConfig.fields.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {sourceConfig.fields.map((field) => (
                          <Badge key={field} variant="secondary" className="flex items-center gap-1 pr-1">
                            {field}
                            <button
                              type="button"
                              onClick={() => removeField(source.source_type, field)}
                              className="ml-1 hover:bg-muted rounded-full p-0.5"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    )}

                    <p className="text-xs text-muted-foreground">
                      Select fields containing IPs, domains, or hashes to check against {displayName}.
                    </p>
                  </div>
                )}
              </div>
            )
          })}
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
