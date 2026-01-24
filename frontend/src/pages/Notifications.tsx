import { useState, useEffect } from 'react'
import { webhooksApi, notificationsApi, Webhook, WebhookProvider, NotificationSettings } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
  Pencil,
  Plus,
  Send,
  Trash2,
} from 'lucide-react'

// System event configuration with grouping
const SYSTEM_EVENT_GROUPS = [
  {
    name: 'Security',
    events: [
      { id: 'user_locked', label: 'User Account Locked' },
    ],
  },
  {
    name: 'Sync Events',
    events: [
      { id: 'sigmahq_sync_complete', label: 'SigmaHQ Sync Complete' },
      { id: 'attack_sync_complete', label: 'ATT&CK Sync Complete' },
      { id: 'sigmahq_new_rules', label: 'New Rules Available' },
      { id: 'sync_failed', label: 'Sync Failed' },
    ],
  },
  {
    name: 'Health Alerts',
    events: [
      { id: 'health_warning', label: 'Health Warning' },
      { id: 'health_critical', label: 'Health Critical' },
    ],
  },
]

// Alert severities
const ALERT_SEVERITIES = [
  { id: 'critical', label: 'Critical', color: 'bg-red-500' },
  { id: 'high', label: 'High', color: 'bg-orange-500' },
  { id: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { id: 'low', label: 'Low', color: 'bg-blue-500' },
  { id: 'informational', label: 'Info', color: 'bg-gray-500' },
]

const providerLabels: Record<WebhookProvider, string> = {
  generic: 'Generic',
  discord: 'Discord',
  slack: 'Slack',
}

type WebhookFormData = {
  name: string
  url: string
  auth_header: string
  provider: WebhookProvider
  enabled: boolean
}

const emptyFormData: WebhookFormData = {
  name: '',
  url: '',
  auth_header: '',
  provider: 'generic',
  enabled: true,
}

export default function Notifications() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [settings, setSettings] = useState<NotificationSettings | null>(null)

  // Track which webhooks are expanded
  const [expandedWebhooks, setExpandedWebhooks] = useState<Set<string>>(new Set())

  // Dialog states
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(emptyFormData)
  const [isSaving, setIsSaving] = useState(false)

  // Delete modal state
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Test state
  const [testingId, setTestingId] = useState<string | null>(null)

  // Saving notification settings
  const [savingSystem, setSavingSystem] = useState<string | null>(null)
  const [savingAlert, setSavingAlert] = useState<string | null>(null)

  // Generate summary text for a webhook
  const getWebhookSummary = (webhookId: string): string => {
    const parts: string[] = []

    // Count system events
    const systemEventCount = settings?.system_events.filter(
      e => e.webhook_ids.includes(webhookId)
    ).length ?? 0
    if (systemEventCount > 0) {
      parts.push(`${systemEventCount} system event${systemEventCount > 1 ? 's' : ''}`)
    }

    // Get alert severities
    const alertConfig = settings?.alert_notifications.find(a => a.webhook_id === webhookId)
    if (alertConfig && alertConfig.severities.length > 0) {
      const severityLabels = alertConfig.severities
        .map(s => ALERT_SEVERITIES.find(sev => sev.id === s)?.label)
        .filter(Boolean)
      parts.push(severityLabels.join(', '))
    }

    return parts.length > 0 ? parts.join(' · ') : 'No notifications configured'
  }

  const toggleExpanded = (webhookId: string) => {
    setExpandedWebhooks(prev => {
      const next = new Set(prev)
      if (next.has(webhookId)) {
        next.delete(webhookId)
      } else {
        next.add(webhookId)
      }
      return next
    })
  }

  const handleToggleEnabled = async (webhook: Webhook) => {
    try {
      const updated = await webhooksApi.update(webhook.id, { enabled: !webhook.enabled })
      setWebhooks(webhooks.map(w => w.id === updated.id ? updated : w))
      showToast(updated.enabled ? 'Webhook enabled' : 'Webhook disabled')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update webhook', 'error')
    }
  }

  const handleTest = async (webhook: Webhook) => {
    setTestingId(webhook.id)
    try {
      const result = await webhooksApi.test(webhook.id)
      if (result.success) {
        showToast('Test notification sent successfully')
      } else {
        showToast(result.error || 'Test failed', 'error')
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Test failed', 'error')
    } finally {
      setTestingId(null)
    }
  }

  const openEditDialog = (webhook: Webhook) => {
    setEditingWebhook(webhook)
    setFormData({
      name: webhook.name,
      url: webhook.url,
      auth_header: '',
      provider: webhook.provider,
      enabled: webhook.enabled,
    })
    setDialogOpen(true)
  }

  const openDeleteModal = (webhook: Webhook) => {
    setWebhookToDelete(webhook)
    setDeleteModalOpen(true)
  }

  // Check if a webhook is enabled for a system event
  const isSystemEventEnabled = (eventType: string, webhookId: string): boolean => {
    if (!settings) return false
    const eventConfig = settings.system_events.find(e => e.event_type === eventType)
    return eventConfig?.webhook_ids.includes(webhookId) ?? false
  }

  // Toggle system event webhook
  const toggleSystemEvent = async (eventType: string, webhookId: string) => {
    if (!settings) return

    setSavingSystem(`${eventType}-${webhookId}`)
    try {
      const eventConfig = settings.system_events.find(e => e.event_type === eventType)
      const currentWebhookIds = eventConfig?.webhook_ids ?? []
      const newWebhookIds = currentWebhookIds.includes(webhookId)
        ? currentWebhookIds.filter(id => id !== webhookId)
        : [...currentWebhookIds, webhookId]

      await notificationsApi.updateSystem(eventType, newWebhookIds)

      setSettings(prev => {
        if (!prev) return prev
        const existingEventIndex = prev.system_events.findIndex(e => e.event_type === eventType)
        const newSystemEvents = [...prev.system_events]
        if (existingEventIndex >= 0) {
          newSystemEvents[existingEventIndex] = { event_type: eventType, webhook_ids: newWebhookIds }
        } else {
          newSystemEvents.push({ event_type: eventType, webhook_ids: newWebhookIds })
        }
        return { ...prev, system_events: newSystemEvents }
      })
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update', 'error')
    } finally {
      setSavingSystem(null)
    }
  }

  // Get alert notification config for a webhook
  const getAlertConfig = (webhookId: string) => {
    return settings?.alert_notifications.find(a => a.webhook_id === webhookId)
  }

  // Check if a severity is enabled for a webhook
  const isSeverityEnabled = (webhookId: string, severity: string): boolean => {
    const config = getAlertConfig(webhookId)
    return config?.severities.includes(severity) ?? false
  }

  // Toggle severity for a webhook
  const toggleSeverity = async (webhookId: string, severity: string) => {
    if (!settings) return

    setSavingAlert(`${webhookId}-${severity}`)
    try {
      const config = getAlertConfig(webhookId)
      const currentSeverities = config?.severities ?? []
      const newSeverities = currentSeverities.includes(severity)
        ? currentSeverities.filter(s => s !== severity)
        : [...currentSeverities, severity]

      const enabled = newSeverities.length > 0
      await notificationsApi.updateAlert(webhookId, newSeverities, enabled)

      setSettings(prev => {
        if (!prev) return prev
        const existingIndex = prev.alert_notifications.findIndex(a => a.webhook_id === webhookId)
        const webhook = webhooks.find(w => w.id === webhookId)
        const newAlertNotifications = [...prev.alert_notifications]
        if (existingIndex >= 0) {
          newAlertNotifications[existingIndex] = {
            ...newAlertNotifications[existingIndex],
            severities: newSeverities,
            enabled,
          }
        } else {
          newAlertNotifications.push({
            webhook_id: webhookId,
            webhook_name: webhook?.name ?? 'Unknown',
            severities: newSeverities,
            enabled,
          })
        }
        return { ...prev, alert_notifications: newAlertNotifications }
      })
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update', 'error')
    } finally {
      setSavingAlert(null)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [webhooksData, notificationData] = await Promise.all([
        webhooksApi.list(),
        notificationsApi.get(),
      ])
      setWebhooks(webhooksData)
      setSettings(notificationData)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load data', 'error')
    } finally {
      setIsLoading(false)
    }
  }

  const SystemEventsSection = ({ webhookId }: { webhookId: string }) => (
    <div className="space-y-4">
      <h4 className="font-medium text-sm">System Events</h4>
      {SYSTEM_EVENT_GROUPS.map(group => (
        <div key={group.name} className="space-y-2">
          <p className="text-xs text-muted-foreground font-medium">{group.name}</p>
          <div className="space-y-2 pl-2">
            {group.events.map(event => {
              const isEnabled = isSystemEventEnabled(event.id, webhookId)
              const isSaving = savingSystem === `${event.id}-${webhookId}`
              return (
                <label
                  key={event.id}
                  className="flex items-center gap-2 cursor-pointer"
                >
                  <Checkbox
                    checked={isEnabled}
                    onCheckedChange={() => toggleSystemEvent(event.id, webhookId)}
                    disabled={isSaving}
                  />
                  <span className="text-sm">{event.label}</span>
                  {isSaving && <Loader2 className="h-3 w-3 animate-spin" />}
                </label>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )

  const AlertSeveritiesSection = ({ webhookId }: { webhookId: string }) => (
    <div className="space-y-4">
      <div>
        <h4 className="font-medium text-sm">Alert Severities</h4>
        <p className="text-xs text-muted-foreground mt-1">
          Which alert severities should trigger notifications?
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        {ALERT_SEVERITIES.map(severity => {
          const isEnabled = isSeverityEnabled(webhookId, severity.id)
          const isSaving = savingAlert === `${webhookId}-${severity.id}`
          return (
            <button
              key={severity.id}
              onClick={() => toggleSeverity(webhookId, severity.id)}
              disabled={isSaving}
              className={`
                inline-flex items-center gap-2 px-3 py-1.5 rounded-md border transition-colors
                ${isEnabled
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border bg-background text-muted-foreground hover:bg-muted'
                }
                ${isSaving ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
              `}
            >
              <span className={`w-2 h-2 rounded-full ${severity.color}`} />
              <span className="text-sm">{severity.label}</span>
              {isSaving && <Loader2 className="h-3 w-3 animate-spin" />}
            </button>
          )
        })}
      </div>
      {!getAlertConfig(webhookId)?.severities.length && (
        <p className="text-xs text-muted-foreground">
          No alert notifications enabled for this webhook.
        </p>
      )}
    </div>
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Notifications</h2>
          <p className="text-sm text-muted-foreground">
            Configure webhook endpoints and what notifications they receive
          </p>
        </div>
        <Button onClick={() => { setEditingWebhook(null); setFormData(emptyFormData); setDialogOpen(true) }}>
          <Plus className="mr-2 h-4 w-4" />
          Add Webhook
        </Button>
      </div>

      {webhooks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ExternalLink className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No notification webhooks configured</h3>
            <p className="text-sm text-muted-foreground text-center max-w-md mb-4">
              Add webhook endpoints to receive alerts and system notifications via Discord, Slack, or custom HTTP endpoints.
            </p>
            <Button onClick={() => { setEditingWebhook(null); setFormData(emptyFormData); setDialogOpen(true) }}>
              <Plus className="mr-2 h-4 w-4" />
              Add Webhook
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {webhooks.map(webhook => (
            <Collapsible
              key={webhook.id}
              open={expandedWebhooks.has(webhook.id)}
              onOpenChange={() => toggleExpanded(webhook.id)}
            >
              <Card className={webhook.enabled ? '' : 'opacity-60'}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CollapsibleTrigger asChild>
                      <button className="flex items-center gap-3 text-left hover:bg-muted/50 -ml-2 pl-2 pr-4 py-1 rounded-md transition-colors">
                        {expandedWebhooks.has(webhook.id) ? (
                          <ChevronUp className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        )}
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{webhook.name}</span>
                            <Badge variant="secondary" className="text-xs">
                              {providerLabels[webhook.provider]}
                            </Badge>
                            {!webhook.enabled && (
                              <Badge variant="outline" className="text-xs text-muted-foreground">
                                Disabled
                              </Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground mt-0.5">
                            {getWebhookSummary(webhook.id)}
                          </p>
                        </div>
                      </button>
                    </CollapsibleTrigger>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={webhook.enabled}
                        onCheckedChange={() => handleToggleEnabled(webhook)}
                        aria-label={webhook.enabled ? 'Disable webhook' : 'Enable webhook'}
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTest(webhook)}
                        disabled={testingId === webhook.id || !webhook.enabled}
                      >
                        {testingId === webhook.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Send className="h-4 w-4" />
                        )}
                        <span className="ml-1">Test</span>
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEditDialog(webhook)}
                      >
                        <Pencil className="h-4 w-4" />
                        <span className="ml-1">Edit</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => openDeleteModal(webhook)}
                        className="text-destructive hover:text-destructive hover:bg-destructive/10"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CollapsibleContent>
                  <CardContent className="pt-4 border-t">
                    <div className="grid md:grid-cols-2 gap-6">
                      <SystemEventsSection webhookId={webhook.id} />
                      <AlertSeveritiesSection webhookId={webhook.id} />
                    </div>
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>
          ))}
        </div>
      )}
    </div>
  )
}
