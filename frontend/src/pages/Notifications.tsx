import { useState, useEffect, useCallback } from 'react'
import { webhooksApi, notificationsApi, jiraApi, Webhook, WebhookProvider, NotificationSettings, JiraConfig, JiraConfigUpdate, JiraProject, JiraIssueType } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
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
  Settings,
  Trash2,
  TestTube,
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
      { id: 'sigmahq_sync_complete', label: 'Sigma Sync - All Completions', description: 'Fires on every successful sync (manual or scheduled)' },
      { id: 'attack_sync_complete', label: 'ATT&CK Sync Complete' },
      { id: 'sigmahq_new_rules', label: 'Sigma Sync - New Rules Only', description: 'Fires only when new or updated rules are found' },
      { id: 'sigmahq_sync_failed', label: 'SigmaHQ Sync Failed' },
      { id: 'attack_sync_failed', label: 'ATT&CK Sync Failed' },
    ],
  },
  {
    name: 'Health & Infrastructure',
    events: [
      { id: 'health_warning', label: 'Health Warning' },
      { id: 'health_critical', label: 'Health Critical' },
      { id: 'opensearch_connection_lost', label: 'OpenSearch Connection Lost' },
      { id: 'opensearch_connection_restored', label: 'OpenSearch Connection Restored' },
    ],
  },
  {
    name: 'Data Freshness',
    events: [
      { id: 'data_freshness_warning', label: 'Data Freshness Warning', description: 'Index data is older than warning threshold' },
      { id: 'data_freshness_critical', label: 'Data Freshness Critical', description: 'Index data is older than critical threshold' },
    ],
  },
  {
    name: 'Rule Operations',
    events: [
      { id: 'rule_deployment_failed', label: 'Rule Deployment Failed' },
      { id: 'percolator_query_error', label: 'Percolator Query Error' },
    ],
  },
  {
    name: 'Integration Failures',
    events: [
      { id: 'maxmind_update_failed', label: 'MaxMind Update Failed' },
      { id: 'ai_mapping_failed', label: 'AI Mapping Failed' },
      { id: 'webhook_delivery_failed', label: 'Webhook Delivery Failed' },
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
  header_name: string
  header_value: string
  provider: WebhookProvider
  enabled: boolean
}

const emptyFormData: WebhookFormData = {
  name: '',
  url: '',
  header_name: '',
  header_value: '',
  provider: 'generic',
  enabled: true,
}

const providerPlaceholders: Record<WebhookProvider, { name: string; url: string }> = {
  generic: { name: 'Alert Webhook', url: 'https://your-endpoint.com/webhook' },
  discord: { name: 'Discord Alerts', url: 'https://discord.com/api/webhooks/...' },
  slack: { name: 'Slack Alerts', url: 'https://hooks.slack.com/services/...' },
}

export default function Notifications() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [settings, setSettings] = useState<NotificationSettings | null>(null)
  const [jiraConfig, setJiraConfig] = useState<JiraConfig | null>(null)
  const [jiraConfigured, setJiraConfigured] = useState(false)

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

  // Jira modal state
  const [jiraModalOpen, setJiraModalOpen] = useState(false)
  const [jiraFormData, setJiraFormData] = useState<Partial<JiraConfigUpdate>>({})
  const [jiraProjects, setJiraProjects] = useState<JiraProject[]>([])
  const [jiraIssueTypes, setJiraIssueTypes] = useState<JiraIssueType[]>([])
  const [isSavingJira, setIsSavingJira] = useState(false)
  const [isTestingJira, setIsTestingJira] = useState(false)

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
      header_name: webhook.header_name || '',
      header_value: '',
      provider: webhook.provider,
      enabled: webhook.enabled,
    })
    setDialogOpen(true)
  }

  const openDeleteModal = (webhook: Webhook) => {
    setWebhookToDelete(webhook)
    setDeleteModalOpen(true)
  }

  const openJiraModal = () => {
    // Initialize form data with current config or empty values for new setup
    setJiraFormData({
      jira_url: jiraConfig?.jira_url || '',
      email: jiraConfig?.email || '',
      default_project: jiraConfig?.default_project || '',
      default_issue_type: jiraConfig?.default_issue_type || '',
      is_enabled: jiraConfig?.is_enabled ?? false,
      alert_severities: jiraConfig?.alert_severities || [],
    })

    // Clear existing projects/issue types when opening for fresh setup
    if (!jiraConfig) {
      setJiraProjects([])
      setJiraIssueTypes([])
    } else if (jiraConfig.jira_url && jiraConfig.has_api_token) {
      // Load projects if we have a URL
      loadJiraProjects()
    }

    setJiraModalOpen(true)
  }

  const loadJiraProjects = async () => {
    try {
      const projects = await jiraApi.getProjects()
      setJiraProjects(projects)

      // Load issue types for the first project
      if (projects.length > 0 && jiraFormData?.default_project) {
        const projectKey = projects.find(p => p.key === jiraFormData.default_project)?.key || projects[0].key
        await loadJiraIssueTypes(projectKey)
      }
    } catch (err) {
      console.error('Failed to load Jira projects:', err)
    }
  }

  const loadJiraIssueTypes = async (projectKey: string) => {
    try {
      const issueTypes = await jiraApi.getIssueTypes(projectKey)
      setJiraIssueTypes(issueTypes)
    } catch (err) {
      console.error('Failed to load Jira issue types:', err)
    }
  }

  const handleSaveJira = async () => {
    if (!jiraFormData) return

    setIsSavingJira(true)
    try {
      const updated = await jiraApi.updateConfig(jiraFormData as JiraConfigUpdate)
      setJiraConfig(updated)
      setJiraConfigured(!!updated)
      setJiraModalOpen(false)
      showToast('Jira configuration saved successfully')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save Jira configuration', 'error')
    } finally {
      setIsSavingJira(false)
    }
  }

  const handleTestJira = async () => {
    if (!jiraFormData?.jira_url || !jiraFormData?.email) {
      showToast('Jira URL and email are required to test', 'error')
      return
    }

    setIsTestingJira(true)
    try {
      const result = await jiraApi.testConnection({
        jira_url: jiraFormData.jira_url,
        email: jiraFormData.email,
        api_token: jiraFormData.api_token || '',
      })

      if (result.success) {
        showToast(`Successfully connected to ${result.server_title || 'Jira'}`)
      } else {
        showToast(result.error || 'Connection failed', 'error')
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Connection test failed', 'error')
    } finally {
      setIsTestingJira(false)
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
      const includeIoc = config?.include_ioc_alerts ?? false
      await notificationsApi.updateAlert(webhookId, newSeverities, enabled, includeIoc)

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

  // Toggle IOC alerts for a webhook
  const toggleIocAlerts = async (webhookId: string, includeIoc: boolean) => {
    if (!settings) return

    setSavingAlert(`${webhookId}-ioc`)
    try {
      const config = getAlertConfig(webhookId)
      const severities = config?.severities ?? []
      const enabled = config?.enabled ?? false
      await notificationsApi.updateAlert(webhookId, severities, enabled, includeIoc)

      setSettings(prev => {
        if (!prev) return prev
        const existingIndex = prev.alert_notifications.findIndex(a => a.webhook_id === webhookId)
        const webhook = webhooks.find(w => w.id === webhookId)
        const newAlertNotifications = [...prev.alert_notifications]
        if (existingIndex >= 0) {
          newAlertNotifications[existingIndex] = {
            ...newAlertNotifications[existingIndex],
            include_ioc_alerts: includeIoc,
          }
        } else {
          newAlertNotifications.push({
            webhook_id: webhookId,
            webhook_name: webhook?.name ?? 'Unknown',
            severities: [],
            enabled: false,
            include_ioc_alerts: includeIoc,
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

  // Load data function - must be declared before useEffect that uses it
  const loadData = useCallback(async () => {
    try {
      const [webhooksData, notificationData, jiraStatus] = await Promise.all([
        webhooksApi.list(),
        notificationsApi.get(),
        jiraApi.getConfig(),
      ])
      setWebhooks(webhooksData)
      setSettings(notificationData)
      setJiraConfigured(jiraStatus.configured)
      setJiraConfig(jiraStatus.config)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load data', 'error')
    } finally {
      setIsLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    loadData()
  }, [loadData])

  const SystemEventsSection = ({ webhookId }: { webhookId: string }) => (
    <div className="space-y-3">
      <h4 className="font-medium text-sm">System Events</h4>
      <div className="space-y-3">
        {SYSTEM_EVENT_GROUPS.map(group => (
          <div key={group.name}>
            <p className="text-xs text-muted-foreground font-medium mb-2">{group.name}</p>
            <div className="flex flex-wrap gap-1.5">
              {group.events.map(event => {
                const isEnabled = isSystemEventEnabled(event.id, webhookId)
                const isSaving = savingSystem === `${event.id}-${webhookId}`
                return (
                  <button
                    key={event.id}
                    onClick={() => toggleSystemEvent(event.id, webhookId)}
                    disabled={isSaving}
                    title={'description' in event ? event.description : undefined}
                    className={`
                      inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs transition-colors
                      ${isEnabled
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border bg-background text-muted-foreground hover:bg-muted'
                      }
                      ${isSaving ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                  >
                    {event.label}
                    {isSaving && <Loader2 className="h-3 w-3 animate-spin" />}
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </div>
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
      <div className="flex items-center justify-between pt-2 border-t">
        <div>
          <Label className="text-sm">Include IOC Alerts</Label>
          <p className="text-xs text-muted-foreground">
            Send notifications for IOC detection matches
          </p>
        </div>
        <Switch
          checked={getAlertConfig(webhookId)?.include_ioc_alerts ?? false}
          onCheckedChange={(checked) => toggleIocAlerts(webhookId, checked)}
        />
      </div>
    </div>
  )

  const handleSave = async () => {
    if (!formData.name.trim()) {
      showToast('Name is required', 'error')
      return
    }
    if (!formData.url.trim()) {
      showToast('URL is required', 'error')
      return
    }

    setIsSaving(true)
    try {
      if (editingWebhook) {
        const updateData: Partial<{ name: string; url: string; header_name: string; header_value: string; provider: WebhookProvider; enabled: boolean }> = {
          name: formData.name,
          url: formData.url,
          provider: formData.provider,
          enabled: formData.enabled,
        }
        // Only include header fields for generic provider
        if (formData.provider === 'generic') {
          if (formData.header_name) {
            updateData.header_name = formData.header_name
          }
          if (formData.header_value) {
            updateData.header_value = formData.header_value
          }
        }
        const updated = await webhooksApi.update(editingWebhook.id, updateData)
        setWebhooks(webhooks.map(w => w.id === updated.id ? updated : w))
        showToast('Webhook updated')
      } else {
        const created = await webhooksApi.create({
          name: formData.name,
          url: formData.url,
          // Only include header fields for generic provider
          header_name: formData.provider === 'generic' && formData.header_name ? formData.header_name : undefined,
          header_value: formData.provider === 'generic' && formData.header_value ? formData.header_value : undefined,
          provider: formData.provider,
          enabled: formData.enabled,
        })
        setWebhooks([...webhooks, created])
        // Auto-expand new webhook
        setExpandedWebhooks(prev => new Set([...prev, created.id]))
        showToast('Webhook created')
      }
      setDialogOpen(false)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save webhook', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!webhookToDelete) return

    setIsDeleting(true)
    try {
      await webhooksApi.delete(webhookToDelete.id)
      setWebhooks(webhooks.filter(w => w.id !== webhookToDelete.id))
      showToast('Webhook deleted')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete webhook', 'error')
    } finally {
      setIsDeleting(false)
      setDeleteModalOpen(false)
      setWebhookToDelete(null)
    }
  }

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
          <h2 className="text-lg font-semibold">Notifications & Alerts</h2>
          <p className="text-sm text-muted-foreground">
            Configure notification destinations for security alerts and system events
          </p>
        </div>
        <Button onClick={() => { setEditingWebhook(null); setFormData(emptyFormData); setDialogOpen(true) }}>
          <Plus className="mr-2 h-4 w-4" />
          Add Webhook
        </Button>
      </div>

      {/* Jira Integration Status */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.005 1.005 0 0 0 23.013 0z" />
              </svg>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium">Jira Cloud</span>
                  {jiraConfigured ? (
                    jiraConfig?.is_enabled ? (
                      <Badge variant="secondary" className="text-xs bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        Active
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-xs text-muted-foreground">
                        Disabled
                      </Badge>
                    )
                  ) : (
                    <Badge variant="outline" className="text-xs text-muted-foreground">
                      Not Configured
                    </Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground mt-0.5">
                  {jiraConfigured && jiraConfig ? (
                    jiraConfig.alert_severities.length > 0 ? (
                      <>
                        Creating tickets for:{' '}
                        {jiraConfig.alert_severities
                          .map(s => ALERT_SEVERITIES.find(sev => sev.id === s)?.label)
                          .filter(Boolean)
                          .join(', ')}
                      </>
                    ) : (
                      'No severities configured for ticket creation'
                    )
                  ) : (
                    'Configure Jira to automatically create tickets for alerts'
                  )}
                </p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                openJiraModal()
              }}
            >
              <Settings className="h-4 w-4 mr-1" />
              {jiraConfigured ? 'Configure' : 'Setup'}
            </Button>
          </div>
        </CardHeader>
      </Card>

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

      {/* Add/Edit Webhook Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingWebhook ? 'Edit Webhook' : 'Add Webhook'}
            </DialogTitle>
            <DialogDescription>
              {editingWebhook
                ? 'Update the webhook configuration.'
                : 'Configure a new webhook endpoint to receive notifications.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="webhook-name">Name</Label>
              <Input
                id="webhook-name"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                placeholder={providerPlaceholders[formData.provider]?.name || 'Alert Webhook'}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="webhook-provider">Provider</Label>
              <Select
                value={formData.provider}
                onValueChange={(value: WebhookProvider) => setFormData({
                  ...formData,
                  provider: value,
                  // Clear header fields when switching away from generic
                  header_name: value === 'generic' ? formData.header_name : '',
                  header_value: value === 'generic' ? formData.header_value : '',
                })}
              >
                <SelectTrigger id="webhook-provider">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="generic">Generic Webhook</SelectItem>
                  <SelectItem value="discord">Discord</SelectItem>
                  <SelectItem value="slack">Slack</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Formats payloads for the selected platform
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="webhook-url">Webhook URL</Label>
              <Input
                id="webhook-url"
                value={formData.url}
                onChange={e => setFormData({ ...formData, url: e.target.value })}
                placeholder={providerPlaceholders[formData.provider]?.url || 'https://your-endpoint.com/webhook'}
              />
            </div>
            {formData.provider === 'generic' && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="webhook-header-name">Header Name (optional)</Label>
                  <Input
                    id="webhook-header-name"
                    value={formData.header_name}
                    onChange={e => setFormData({ ...formData, header_name: e.target.value })}
                    placeholder="Authorization"
                  />
                  <p className="text-xs text-muted-foreground">
                    Custom header name (e.g., X-API-Key, Authorization)
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="webhook-header-value">Header Value (optional)</Label>
                  <Input
                    id="webhook-header-value"
                    type="password"
                    value={formData.header_value}
                    onChange={e => setFormData({ ...formData, header_value: e.target.value })}
                    placeholder={editingWebhook?.has_auth ? 'Enter new value to change' : 'Bearer token or API key'}
                  />
                  <p className="text-xs text-muted-foreground">
                    {editingWebhook?.has_auth ? 'Leave blank to keep existing' : 'Value for the custom header'}
                  </p>
                </div>
              </>
            )}
            <div className="flex items-center justify-between">
              <div>
                <Label>Enabled</Label>
                <p className="text-xs text-muted-foreground">
                  Receive notifications when enabled
                </p>
              </div>
              <Switch
                checked={formData.enabled}
                onCheckedChange={enabled => setFormData({ ...formData, enabled })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={isSaving}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : editingWebhook ? (
                'Update'
              ) : (
                'Create'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <DeleteConfirmModal
        open={deleteModalOpen}
        onOpenChange={setDeleteModalOpen}
        title="Delete Webhook"
        description="Are you sure you want to delete this webhook? This action cannot be undone."
        itemName={webhookToDelete?.name}
        onConfirm={handleDelete}
        isDeleting={isDeleting}
      />

      {/* Jira Configuration Modal */}
      <Dialog open={jiraModalOpen} onOpenChange={setJiraModalOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Configure Jira Integration</DialogTitle>
            <DialogDescription>
              Configure Jira Cloud to automatically create tickets for alerts
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
              {/* Jira URL */}
              <div className="space-y-2">
                <Label htmlFor="jira-url">Jira URL *</Label>
                <Input
                  id="jira-url"
                  placeholder="https://your-domain.atlassian.net"
                  value={jiraFormData.jira_url || ''}
                  onChange={e => setJiraFormData({ ...jiraFormData, jira_url: e.target.value })}
                />
              </div>

              {/* Email */}
              <div className="space-y-2">
                <Label htmlFor="jira-email">Email *</Label>
                <Input
                  id="jira-email"
                  type="email"
                  placeholder="user@example.com"
                  value={jiraFormData.email || ''}
                  onChange={e => setJiraFormData({ ...jiraFormData, email: e.target.value })}
                />
              </div>

              {/* API Token */}
              <div className="space-y-2">
                <Label htmlFor="jira-token">API Token</Label>
                <Input
                  id="jira-token"
                  type="password"
                  placeholder="Leave blank to keep existing"
                  value={jiraFormData.api_token || ''}
                  onChange={e => setJiraFormData({ ...jiraFormData, api_token: e.target.value })}
                />
                <p className="text-xs text-muted-foreground">
                  {jiraConfig?.has_api_token ? 'Leave blank to keep existing token' : 'Generate from Jira User Settings'}
                </p>
              </div>

              {/* Default Project */}
              <div className="space-y-2">
                <Label htmlFor="jira-project">Default Project *</Label>
                <Select
                  value={jiraFormData.default_project}
                  onValueChange={value => {
                    setJiraFormData({ ...jiraFormData, default_project: value })
                    loadJiraIssueTypes(value)
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select project" />
                  </SelectTrigger>
                  <SelectContent>
                    {jiraProjects.map(project => (
                      <SelectItem key={project.key} value={project.key}>
                        {project.name} ({project.key})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Default Issue Type */}
              <div className="space-y-2">
                <Label htmlFor="jira-issue-type">Default Issue Type *</Label>
                <Select
                  value={jiraFormData.default_issue_type}
                  onValueChange={value => setJiraFormData({ ...jiraFormData, default_issue_type: value })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select issue type" />
                  </SelectTrigger>
                  <SelectContent>
                    {jiraIssueTypes.map(issueType => (
                      <SelectItem key={issueType.id} value={issueType.name}>
                        {issueType.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Alert Severities */}
              <div className="space-y-2">
                <Label>Alert Severities for Ticket Creation</Label>
                <div className="flex flex-wrap gap-2">
                  {ALERT_SEVERITIES.map(severity => {
                    const isSelected = jiraFormData.alert_severities?.includes(severity.id) || false
                    return (
                      <button
                        key={severity.id}
                        type="button"
                        onClick={() => {
                          const current = jiraFormData.alert_severities || []
                          setJiraFormData({
                            ...jiraFormData,
                            alert_severities: isSelected
                              ? current.filter(s => s !== severity.id)
                              : [...current, severity.id],
                          })
                        }}
                        className={`
                          inline-flex items-center gap-2 px-3 py-1.5 rounded-md border transition-colors
                          ${isSelected
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'border-border bg-background text-muted-foreground hover:bg-muted'
                          }
                        `}
                      >
                        <span className={`w-2 h-2 rounded-full ${severity.color}`} />
                        <span className="text-sm">{severity.label}</span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Enabled Switch */}
              <div className="flex items-center justify-between">
                <div>
                  <Label>Enabled</Label>
                  <p className="text-xs text-muted-foreground">
                    Create tickets for alerts when enabled
                  </p>
                </div>
                <Switch
                  checked={jiraFormData.is_enabled}
                  onCheckedChange={enabled => setJiraFormData({ ...jiraFormData, is_enabled: enabled })}
                />
              </div>

              {/* Test Connection */}
              <div className="flex items-center gap-2 pt-4 border-t">
                <Button
                  variant="outline"
                  onClick={handleTestJira}
                  disabled={isTestingJira || !jiraFormData.jira_url || !jiraFormData.email}
                  className="flex-1"
                >
                  {isTestingJira ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <TestTube className="mr-2 h-4 w-4" />
                      Test Connection
                    </>
                  )}
                </Button>
              </div>
            </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setJiraModalOpen(false)} disabled={isSavingJira}>
              Cancel
            </Button>
            <Button onClick={handleSaveJira} disabled={isSavingJira || !jiraFormData.jira_url || !jiraFormData.email || !jiraFormData.default_project || !jiraFormData.default_issue_type}>
              {isSavingJira ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>Save Configuration</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
