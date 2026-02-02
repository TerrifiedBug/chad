import { useState, useEffect } from 'react'
import { IndexPattern, indexPatternsApi, tiApi, TISource, TIConfig } from '@/lib/api'
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
  const [tiSources, setTiSources] = useState<TISource[]>([])
  const [tiConfig, setTiConfig] = useState<TIConfig>(pattern.ti_config || {})
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [availableFields, setAvailableFields] = useState<string[]>([])

  // Load TI sources and available fields
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true)
      try {
        const [sources, fields] = await Promise.all([
          tiApi.getSources(),
          indexPatternsApi.getFields(pattern.id),
        ])
        setTiSources(sources.filter(s => s.enabled))
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

  const toggleSource = (sourceName: string, enabled: boolean) => {
    if (enabled) {
      setTiConfig({
        ...tiConfig,
        [sourceName]: { enabled: true, fields: [] },
      })
    } else {
      const newConfig = { ...tiConfig }
      delete newConfig[sourceName]
      setTiConfig(newConfig)
    }
  }

  const addField = (sourceName: string, field: string) => {
    const sourceConfig = tiConfig[sourceName] || { enabled: true, fields: [] }
    if (!sourceConfig.fields.includes(field)) {
      setTiConfig({
        ...tiConfig,
        [sourceName]: {
          ...sourceConfig,
          fields: [...sourceConfig.fields, field],
        },
      })
    }
  }

  const removeField = (sourceName: string, field: string) => {
    const sourceConfig = tiConfig[sourceName]
    if (sourceConfig) {
      setTiConfig({
        ...tiConfig,
        [sourceName]: {
          ...sourceConfig,
          fields: sourceConfig.fields.filter(f => f !== field),
        },
      })
    }
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
            const sourceConfig = tiConfig[source.name]
            const isEnabled = !!sourceConfig?.enabled

            return (
              <div key={source.name} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <Label className="font-medium">{source.name}</Label>
                    <p className="text-xs text-muted-foreground capitalize">{source.type}</p>
                  </div>
                  <Switch
                    checked={isEnabled}
                    onCheckedChange={(checked) => toggleSource(source.name, checked)}
                  />
                </div>

                {isEnabled && (
                  <div className="space-y-3 pt-3 border-t">
                    <Label className="text-sm">Fields to Check</Label>
                    <div className="flex gap-2">
                      <Select
                        value=""
                        onValueChange={(field) => addField(source.name, field)}
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
                              onClick={() => removeField(source.name, field)}
                              className="ml-1 hover:bg-muted rounded-full p-0.5"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    )}

                    <p className="text-xs text-muted-foreground">
                      Select fields containing IPs, domains, or hashes to check against {source.name}.
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
