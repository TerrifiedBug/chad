import { useState, useEffect, useRef } from 'react'
import {
  IndexPattern,
  indexPatternsApi,
  enrichmentWebhooksApi,
  indexPatternEnrichmentsApi,
  EnrichmentWebhook,
  IndexPatternEnrichmentConfig,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Loader2, Save, Search, Webhook } from 'lucide-react'
import { Link } from 'react-router-dom'

interface WebhooksTabProps {
  pattern: IndexPattern
  onPatternUpdated?: (pattern: IndexPattern) => void
}

export function WebhooksTab({ pattern }: WebhooksTabProps) {
  const { showToast } = useToast()
  const [webhooks, setWebhooks] = useState<EnrichmentWebhook[]>([])
  const [configs, setConfigs] = useState<IndexPatternEnrichmentConfig[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [availableFields, setAvailableFields] = useState<string[]>([])

  // Track field search per webhook
  const [fieldSearches, setFieldSearches] = useState<Record<string, string>>({})
  const [showDropdowns, setShowDropdowns] = useState<Record<string, boolean>>({})
  const dropdownRefs = useRef<Record<string, HTMLDivElement | null>>({})

  // Load webhooks and current config
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true)
      try {
        const [webhookList, enrichments, fields] = await Promise.all([
          enrichmentWebhooksApi.list(),
          indexPatternEnrichmentsApi.get(pattern.id),
          indexPatternsApi.getFields(pattern.id),
        ])
        // Only show active webhooks
        setWebhooks(webhookList.filter((w) => w.is_active))
        setConfigs(enrichments.enrichments)
        setAvailableFields(fields.sort())

        // Initialize field searches with current config values
        const initialSearches: Record<string, string> = {}
        enrichments.enrichments.forEach((c) => {
          initialSearches[c.webhook_id] = c.field_to_send
        })
        setFieldSearches(initialSearches)
      } catch (err) {
        console.error('Failed to load webhook data:', err)
        showToast('Failed to load webhook configuration', 'error')
      } finally {
        setIsLoading(false)
      }
    }
    loadData()
  }, [pattern.id, showToast])

  // Handle click outside to close dropdowns
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      Object.entries(dropdownRefs.current).forEach(([webhookId, ref]) => {
        if (ref && !ref.contains(event.target as Node)) {
          setShowDropdowns((prev) => ({ ...prev, [webhookId]: false }))
        }
      })
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSave = async () => {
    setIsSaving(true)
    try {
      const enrichmentsPayload = configs.map((c) => ({
        webhook_id: c.webhook_id,
        field_to_send: c.field_to_send,
        is_enabled: c.is_enabled,
      }))

      const updated = await indexPatternEnrichmentsApi.update(pattern.id, {
        enrichments: enrichmentsPayload,
      })
      setConfigs(updated.enrichments)
      showToast('Webhook enrichment settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const toggleWebhook = (webhookId: string, enabled: boolean) => {
    if (enabled) {
      // Check if config already exists
      const existing = configs.find((c) => c.webhook_id === webhookId)
      if (existing) {
        // Just enable it
        setConfigs((prev) =>
          prev.map((c) =>
            c.webhook_id === webhookId ? { ...c, is_enabled: true } : c
          )
        )
      } else {
        // Add new config
        const webhook = webhooks.find((w) => w.id === webhookId)
        if (webhook) {
          setConfigs((prev) => [
            ...prev,
            {
              webhook_id: webhookId,
              webhook_name: webhook.name,
              webhook_namespace: webhook.namespace,
              field_to_send: '',
              is_enabled: true,
            },
          ])
        }
      }
    } else {
      // Remove config entirely
      setConfigs((prev) => prev.filter((c) => c.webhook_id !== webhookId))
      setFieldSearches((prev) => {
        const updated = { ...prev }
        delete updated[webhookId]
        return updated
      })
    }
  }

  const selectField = (webhookId: string, field: string) => {
    setFieldSearches((prev) => ({ ...prev, [webhookId]: field }))
    setConfigs((prev) =>
      prev.map((c) =>
        c.webhook_id === webhookId ? { ...c, field_to_send: field } : c
      )
    )
    setShowDropdowns((prev) => ({ ...prev, [webhookId]: false }))
  }

  const getFilteredFields = (search: string) => {
    return availableFields.filter((f) =>
      f.toLowerCase().includes(search.toLowerCase())
    )
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
        <h3 className="text-lg font-medium">Custom Enrichment Webhooks</h3>
        <p className="text-sm text-muted-foreground">
          Configure which enrichment webhooks are used to enrich alerts from this index pattern.
          For each webhook, specify which field value to send for lookup.
        </p>
      </div>

      {webhooks.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Webhook className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>No active enrichment webhooks configured.</p>
          <p className="text-sm mt-2">
            Configure webhooks in{' '}
            <Link to="/settings?tab=enrichment" className="text-primary hover:underline">
              Settings → Enrichment
            </Link>
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {webhooks.map((webhook) => {
            const config = configs.find((c) => c.webhook_id === webhook.id)
            const isEnabled = !!config?.is_enabled
            const fieldSearch = fieldSearches[webhook.id] || ''
            const showDropdown = showDropdowns[webhook.id]
            const filteredFields = getFilteredFields(fieldSearch)

            return (
              <div key={webhook.id} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <Label className="font-medium">{webhook.name}</Label>
                      <Badge variant="outline" className="text-xs font-mono">
                        {webhook.namespace}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {webhook.method} {webhook.url}
                    </p>
                  </div>
                  <Switch
                    checked={isEnabled}
                    onCheckedChange={(checked) => toggleWebhook(webhook.id, checked)}
                  />
                </div>

                {isEnabled && (
                  <div className="space-y-3 pt-3 border-t">
                    <div>
                      <Label className="text-sm">Field to Send</Label>
                      <p className="text-xs text-muted-foreground mb-2">
                        The value of this field will be sent to the webhook for enrichment lookup.
                      </p>
                    </div>

                    <div
                      ref={(el) => {
                        dropdownRefs.current[webhook.id] = el
                      }}
                      className="relative"
                    >
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                          value={fieldSearch}
                          onChange={(e) => {
                            setFieldSearches((prev) => ({
                              ...prev,
                              [webhook.id]: e.target.value,
                            }))
                            setShowDropdowns((prev) => ({
                              ...prev,
                              [webhook.id]: true,
                            }))
                            // Also update config
                            setConfigs((prev) =>
                              prev.map((c) =>
                                c.webhook_id === webhook.id
                                  ? { ...c, field_to_send: e.target.value }
                                  : c
                              )
                            )
                          }}
                          onFocus={() =>
                            setShowDropdowns((prev) => ({
                              ...prev,
                              [webhook.id]: true,
                            }))
                          }
                          placeholder="Search and select a field..."
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
                                onClick={() => selectField(webhook.id, field)}
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

                    {config?.field_to_send && (
                      <div className="flex items-center gap-2 p-2 bg-muted/50 rounded">
                        <span className="text-sm">Selected:</span>
                        <code className="text-sm font-mono">{config.field_to_send}</code>
                      </div>
                    )}

                    {!config?.field_to_send && (
                      <p className="text-xs text-amber-600 dark:text-amber-400">
                        A field must be selected for enrichment to work.
                      </p>
                    )}
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
