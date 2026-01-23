import { useState, useEffect } from 'react'
import { notificationsApi, webhooksApi, NotificationSettings, Webhook } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Loader2 } from 'lucide-react'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

// System event types with human-readable labels
const SYSTEM_EVENT_TYPES = [
  { id: 'user_locked', label: 'User Account Locked' },
  { id: 'sigmahq_sync_complete', label: 'SigmaHQ Sync Complete' },
  { id: 'sigmahq_new_rules', label: 'SigmaHQ New Rules Available' },
  { id: 'attack_sync_complete', label: 'ATT&CK Sync Complete' },
  { id: 'sync_failed', label: 'Sync Failed' },
  { id: 'health_warning', label: 'Health Warning' },
  { id: 'health_critical', label: 'Health Critical' },
]

// Alert severities with colors for badges
const ALERT_SEVERITIES = [
  { id: 'critical', label: 'Critical', color: 'bg-red-500' },
  { id: 'high', label: 'High', color: 'bg-orange-500' },
  { id: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { id: 'low', label: 'Low', color: 'bg-blue-500' },
  { id: 'informational', label: 'Info', color: 'bg-gray-500' },
]

export default function NotificationsSettings() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [settings, setSettings] = useState<NotificationSettings | null>(null)
  const [savingSystem, setSavingSystem] = useState<string | null>(null)
  const [savingAlert, setSavingAlert] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [webhooksData, notificationData] = await Promise.all([
        webhooksApi.list(),
        notificationsApi.get(),
      ])
      setWebhooks(webhooksData.filter(w => w.enabled))
      setSettings(notificationData)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load notifications settings', 'error')
    } finally {
      setIsLoading(false)
    }
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

      // Update local state
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
      showToast('Notification setting updated')
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

      // Determine if enabled (has any severities)
      const enabled = newSeverities.length > 0

      await notificationsApi.updateAlert(webhookId, newSeverities, enabled)

      // Update local state
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
      showToast('Alert notification updated')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update', 'error')
    } finally {
      setSavingAlert(null)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (webhooks.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <h3 className="text-lg font-medium mb-2">No webhooks available</h3>
          <p className="text-sm text-muted-foreground text-center max-w-md">
            Configure webhook endpoints in the Webhooks tab before setting up notifications.
            Only enabled webhooks can receive notifications.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* System Notifications Section */}
      <Card>
        <CardHeader>
          <CardTitle>System Notifications</CardTitle>
          <CardDescription>
            Configure which webhooks receive notifications for system events
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[250px]">Event Type</TableHead>
                  {webhooks.map(webhook => (
                    <TableHead key={webhook.id} className="text-center">
                      {webhook.name}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {SYSTEM_EVENT_TYPES.map(event => (
                  <TableRow key={event.id}>
                    <TableCell className="font-medium">{event.label}</TableCell>
                    {webhooks.map(webhook => (
                      <TableCell key={webhook.id} className="text-center">
                        <div className="flex justify-center">
                          <Checkbox
                            checked={isSystemEventEnabled(event.id, webhook.id)}
                            onCheckedChange={() => toggleSystemEvent(event.id, webhook.id)}
                            disabled={savingSystem === `${event.id}-${webhook.id}`}
                            aria-label={`Enable ${event.label} notifications for ${webhook.name}`}
                          />
                        </div>
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Alert Notifications Section */}
      <Card>
        <CardHeader>
          <CardTitle>Alert Notifications</CardTitle>
          <CardDescription>
            Configure which alert severities are sent to each webhook
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {webhooks.map(webhook => (
              <div key={webhook.id} className="space-y-3">
                <h4 className="font-medium">{webhook.name}</h4>
                <div className="flex flex-wrap gap-3">
                  {ALERT_SEVERITIES.map(severity => {
                    const isEnabled = isSeverityEnabled(webhook.id, severity.id)
                    const isSaving = savingAlert === `${webhook.id}-${severity.id}`
                    return (
                      <button
                        key={severity.id}
                        onClick={() => toggleSeverity(webhook.id, severity.id)}
                        disabled={isSaving}
                        className={`
                          inline-flex items-center gap-2 px-3 py-1.5 rounded-md border transition-colors
                          ${isEnabled
                            ? 'border-transparent bg-primary/10 text-primary'
                            : 'border-border bg-background text-muted-foreground hover:bg-muted'
                          }
                          ${isSaving ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                        `}
                        aria-label={`${isEnabled ? 'Disable' : 'Enable'} ${severity.label} alerts for ${webhook.name}`}
                      >
                        <Badge
                          variant="secondary"
                          className={`${severity.color} text-white text-xs px-1.5 py-0`}
                        >
                          {severity.label}
                        </Badge>
                        <Checkbox
                          checked={isEnabled}
                          className="pointer-events-none"
                          tabIndex={-1}
                        />
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
