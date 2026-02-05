import { useState, useEffect } from 'react'
import {
  IndexPattern,
  indexPatternsApi,
  enrichmentWebhooksApi,
  indexPatternEnrichmentsApi,
  EnrichmentWebhook,
  IndexPatternEnrichmentConfig,
  IndexPatternEnrichmentsUpdate,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { SearchableFieldSelect } from '@/components/ui/searchable-field-select'
import { Loader2, Webhook } from 'lucide-react'
import { Link } from 'react-router-dom'

interface WebhooksTabProps {
  pattern: IndexPattern
  onDirtyChange?: (isDirty: boolean) => void
  onPendingChange?: (changes: IndexPatternEnrichmentsUpdate) => void
}

export function WebhooksTab({ pattern, onDirtyChange, onPendingChange }: WebhooksTabProps) {
  const { showToast } = useToast()
  const [webhooks, setWebhooks] = useState<EnrichmentWebhook[]>([])
  const [configs, setConfigs] = useState<IndexPatternEnrichmentConfig[]>([])
  const [originalConfigs, setOriginalConfigs] = useState<IndexPatternEnrichmentConfig[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [availableFields, setAvailableFields] = useState<string[]>([])

  // Load webhooks and current config
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true)
      try {
        // Gracefully handle empty webhooks/configs - don't show error for "no data"
        const [webhookList, enrichmentConfigs, fields] = await Promise.all([
          enrichmentWebhooksApi.list().catch(() => []),
          indexPatternEnrichmentsApi.get(pattern.id).catch(() => []),
          indexPatternsApi.getFields(pattern.id),
        ])
        // Only show active webhooks
        setWebhooks((webhookList || []).filter((w) => w.is_active))
        // Backend returns array directly
        setConfigs(enrichmentConfigs || [])
        setOriginalConfigs(enrichmentConfigs || [])
        setAvailableFields(fields.sort())
      } catch (err) {
        // Only show error for field loading failure (critical for functionality)
        console.error('Failed to load fields:', err)
        showToast('Failed to load available fields', 'error')
      } finally {
        setIsLoading(false)
      }
    }
    loadData()
  }, [pattern.id, showToast])

  // Track dirty state and report pending changes
  useEffect(() => {
    const isDirty = JSON.stringify(configs) !== JSON.stringify(originalConfigs)
    onDirtyChange?.(isDirty)
    if (isDirty) {
      const enrichmentsPayload = configs.map((c) => ({
        webhook_id: c.webhook_id,
        field_to_send: c.field_to_send,
        is_enabled: c.is_enabled,
      }))
      onPendingChange?.({ enrichments: enrichmentsPayload })
    }
  }, [configs, originalConfigs, onDirtyChange, onPendingChange])

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
    }
  }

  const updateFieldToSend = (webhookId: string, field: string) => {
    setConfigs((prev) =>
      prev.map((c) =>
        c.webhook_id === webhookId ? { ...c, field_to_send: field } : c
      )
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

                    <SearchableFieldSelect
                      fields={availableFields}
                      value={config?.field_to_send || ''}
                      placeholder="Search and select a field..."
                      onSelect={(field) => updateFieldToSend(webhook.id, field)}
                      onChange={(value) => updateFieldToSend(webhook.id, value)}
                    />

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

    </div>
  )
}
