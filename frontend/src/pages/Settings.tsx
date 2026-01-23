import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { settingsApiExtended, settingsApi, statsApi, permissionsApi, OpenSearchStatusResponse, AIProvider, AISettings, AISettingsUpdate } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Loader2, Plus, Save, Send, Trash2, Users, FileText } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

// Helper to download files with auth
async function downloadWithAuth(url: string, filename: string) {
  const token = localStorage.getItem('chad-token')
  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!response.ok) {
    throw new Error(`Download failed: ${response.statusText}`)
  }
  const blob = await response.blob()
  const downloadUrl = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = downloadUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(downloadUrl)
}

type WebhookProvider = 'generic' | 'discord' | 'slack'

type Webhook = {
  url: string
  name: string
  provider: WebhookProvider
  severity_filter: 'all' | 'critical' | 'high' | 'medium' | 'low'
  enabled: boolean
}

const providerInfo: Record<WebhookProvider, { label: string; placeholder: string; help: string }> = {
  generic: {
    label: 'Generic Webhook',
    placeholder: 'https://api.example.com/webhook',
    help: 'Raw alert JSON will be POST-ed to this URL',
  },
  discord: {
    label: 'Discord',
    placeholder: 'https://discord.com/api/webhooks/...',
    help: 'Discord webhook URL from Server Settings > Integrations',
  },
  slack: {
    label: 'Slack',
    placeholder: 'https://hooks.slack.com/services/...',
    help: 'Slack webhook URL from your Slack app configuration',
  },
}

export default function SettingsPage() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)

  // Webhook settings
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [webhooksEnabled, setWebhooksEnabled] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState<number | null>(null)
  const [webhookTestResults, setWebhookTestResults] = useState<Record<number, { success: boolean; error?: string }>>({})


  // Session settings
  const [sessionTimeout, setSessionTimeout] = useState(480)

  // Rate limiting settings
  const [rateLimitEnabled, setRateLimitEnabled] = useState(true)
  const [rateLimitMaxAttempts, setRateLimitMaxAttempts] = useState(5)
  const [rateLimitLockoutMinutes, setRateLimitLockoutMinutes] = useState(15)

  // App URL setting
  const [appUrl, setAppUrl] = useState('')

  // Active tab for programmatic navigation
  const [activeTab, setActiveTab] = useState('general')

  // SSO settings
  const [ssoEnabled, setSsoEnabled] = useState(false)
  const [ssoIssuerUrl, setSsoIssuerUrl] = useState('')
  const [ssoClientId, setSsoClientId] = useState('')
  const [ssoClientSecret, setSsoClientSecret] = useState('')
  const [ssoProviderName, setSsoProviderName] = useState('SSO')
  const [ssoDefaultRole, setSsoDefaultRole] = useState('analyst')

  // SSO Role Mapping
  const [ssoRoleMappingEnabled, setSsoRoleMappingEnabled] = useState(false)
  const [ssoRoleClaim, setSsoRoleClaim] = useState('')
  const [ssoAdminValues, setSsoAdminValues] = useState('')
  const [ssoAnalystValues, setSsoAnalystValues] = useState('')
  const [ssoViewerValues, setSsoViewerValues] = useState('')

  // SigmaHQ sync settings
  const [sigmahqSyncEnabled, setSigmahqSyncEnabled] = useState(false)
  const [sigmahqSyncInterval, setSigmahqSyncInterval] = useState(24)
  const [sigmahqLastSync, setSigmahqLastSync] = useState<string | null>(null)

  // OpenSearch settings
  const [osStatus, setOsStatus] = useState<OpenSearchStatusResponse | null>(null)
  const [osConnectionStatus, setOsConnectionStatus] = useState<{
    connected: boolean
    version?: string
    error?: string
  } | null>(null)
  const [osConnectionLoading, setOsConnectionLoading] = useState(false)

  // Audit to OpenSearch
  const [auditOpenSearchEnabled, setAuditOpenSearchEnabled] = useState(false)

  // Role permissions
  const [permissions, setPermissions] = useState<Record<string, Record<string, boolean>>>({})
  const [permissionDescriptions, setPermissionDescriptions] = useState<Record<string, string>>({})

  // AI settings
  const [aiSettings, setAiSettings] = useState<AISettings>({
    ai_provider: 'disabled',
    ai_ollama_url: 'http://localhost:11434',
    ai_ollama_model: 'llama3',
    ai_openai_model: 'gpt-4o',
    ai_anthropic_model: 'claude-sonnet-4-20250514',
    ai_allow_log_samples: false,
  })
  const [aiOpenAIKey, setAiOpenAIKey] = useState('')
  const [aiAnthropicKey, setAiAnthropicKey] = useState('')

  useEffect(() => {
    loadSettings()
    loadOpenSearchStatus()
    loadAppUrl()
    loadPermissions()
  }, [])

  // Check OpenSearch connection when the tab is selected
  useEffect(() => {
    if (activeTab === 'opensearch') {
      checkOpenSearchConnection()
    }
  }, [activeTab])

  const loadAppUrl = async () => {
    try {
      const response = await settingsApi.getAppUrl()
      setAppUrl(response.url || '')
    } catch (err) {
      console.log('Failed to load APP_URL')
    }
  }

  const loadSettings = async () => {
    try {
      const settings = await settingsApiExtended.getAll()

      // Webhook
      if (settings.webhooks && typeof settings.webhooks === 'object') {
        const webhookSettings = settings.webhooks as Record<string, unknown>
        setWebhooksEnabled((webhookSettings.enabled as boolean) || false)
        if (Array.isArray(webhookSettings.webhooks)) {
          // Ensure provider field exists (migration for older configs)
          setWebhooks((webhookSettings.webhooks as Webhook[]).map(w => ({
            ...w,
            provider: w.provider || 'generic',
          })))
        } else if (webhookSettings.global_url) {
          // Migrate legacy single webhook
          setWebhooks([{
            url: webhookSettings.global_url as string,
            name: 'Default Webhook',
            provider: 'generic',
            severity_filter: 'all',
            enabled: true,
          }])
        }
      }

      // Session
      if (settings.session && typeof settings.session === 'object') {
        const session = settings.session as Record<string, unknown>
        setSessionTimeout((session.timeout_minutes as number) || 480)
      }

      // Rate limiting
      if (settings.rate_limiting && typeof settings.rate_limiting === 'object') {
        const rateLimiting = settings.rate_limiting as Record<string, unknown>
        setRateLimitEnabled(rateLimiting.enabled !== false)
        setRateLimitMaxAttempts((rateLimiting.max_attempts as number) || 5)
        setRateLimitLockoutMinutes((rateLimiting.lockout_minutes as number) || 15)
      }

      // SSO
      if (settings.sso && typeof settings.sso === 'object') {
        const sso = settings.sso as Record<string, unknown>
        setSsoEnabled((sso.enabled as boolean) || false)
        setSsoIssuerUrl((sso.issuer_url as string) || '')
        setSsoClientId((sso.client_id as string) || '')
        // Don't load client secret - it's masked by the API
        setSsoProviderName((sso.provider_name as string) || 'SSO')
        setSsoDefaultRole((sso.default_role as string) || 'analyst')
        // Role mapping settings
        setSsoRoleMappingEnabled((sso.role_mapping_enabled as boolean) || false)
        setSsoRoleClaim((sso.role_claim as string) || '')
        setSsoAdminValues((sso.admin_values as string) || '')
        setSsoAnalystValues((sso.analyst_values as string) || '')
        setSsoViewerValues((sso.viewer_values as string) || '')
      }

      // SigmaHQ sync settings
      if (settings.sigmahq_sync && typeof settings.sigmahq_sync === 'object') {
        const sigmahq = settings.sigmahq_sync as Record<string, unknown>
        setSigmahqSyncEnabled((sigmahq.enabled as boolean) || false)
        setSigmahqSyncInterval((sigmahq.interval_hours as number) || 24)
        setSigmahqLastSync((sigmahq.last_sync as string) || null)
      }

      // Audit OpenSearch settings
      if (settings.audit_opensearch_enabled && typeof settings.audit_opensearch_enabled === 'object') {
        const auditOs = settings.audit_opensearch_enabled as Record<string, unknown>
        setAuditOpenSearchEnabled((auditOs.enabled as boolean) || false)
      }

      // AI settings
      if (settings.ai && typeof settings.ai === 'object') {
        const ai = settings.ai as Record<string, unknown>
        setAiSettings({
          ai_provider: (ai.ai_provider as AIProvider) || 'disabled',
          ai_ollama_url: (ai.ai_ollama_url as string) || 'http://localhost:11434',
          ai_ollama_model: (ai.ai_ollama_model as string) || 'llama3',
          ai_openai_model: (ai.ai_openai_model as string) || 'gpt-4o',
          ai_anthropic_model: (ai.ai_anthropic_model as string) || 'claude-sonnet-4-20250514',
          ai_allow_log_samples: (ai.ai_allow_log_samples as boolean) || false,
        })
      }
    } catch (err) {
      // Settings may not exist yet, that's okay
      console.log('No settings found, using defaults')
    } finally {
      setIsLoading(false)
    }
  }

  const loadOpenSearchStatus = async () => {
    try {
      const status = await settingsApi.getOpenSearchStatus()
      setOsStatus(status)
    } catch (err) {
      console.log('Failed to load OpenSearch status')
    }
  }

  const loadPermissions = async () => {
    try {
      const data = await permissionsApi.getAll()
      setPermissions(data.roles)
      setPermissionDescriptions(data.descriptions)
    } catch (err) {
      console.error('Failed to load permissions:', err)
    }
  }

  const checkOpenSearchConnection = async () => {
    setOsConnectionLoading(true)
    try {
      const health = await statsApi.getHealth()
      if (health.status === 'healthy' && health.opensearch) {
        const osInfo = health.opensearch as { version?: string }
        setOsConnectionStatus({
          connected: true,
          version: osInfo.version || 'Unknown',
        })
      } else {
        setOsConnectionStatus({
          connected: false,
          error: health.error || 'Connection failed',
        })
      }
    } catch (err) {
      setOsConnectionStatus({
        connected: false,
        error: err instanceof Error ? err.message : 'Connection failed',
      })
    } finally {
      setOsConnectionLoading(false)
    }
  }

  const addWebhook = () => {
    setWebhooks([
      ...webhooks,
      {
        url: '',
        name: `Webhook ${webhooks.length + 1}`,
        provider: 'generic',
        severity_filter: 'all',
        enabled: true,
      },
    ])
  }

  const updateWebhook = (index: number, updates: Partial<Webhook>) => {
    setWebhooks(webhooks.map((w, i) => (i === index ? { ...w, ...updates } : w)))
  }

  const removeWebhook = (index: number) => {
    setWebhooks(webhooks.filter((_, i) => i !== index))
    // Clear test result for removed webhook
    const newResults = { ...webhookTestResults }
    delete newResults[index]
    setWebhookTestResults(newResults)
  }

  const testWebhook = async (index: number) => {
    const webhook = webhooks[index]
    if (!webhook.url) {
      setWebhookTestResults(prev => ({
        ...prev,
        [index]: { success: false, error: 'Please enter a webhook URL' },
      }))
      return
    }

    setTestingWebhook(index)
    setWebhookTestResults(prev => {
      const newResults = { ...prev }
      delete newResults[index]
      return newResults
    })

    try {
      const result = await settingsApi.testWebhook(webhook.url, webhook.provider)
      setWebhookTestResults(prev => ({
        ...prev,
        [index]: { success: result.success, error: result.error || undefined },
      }))
    } catch (err) {
      setWebhookTestResults(prev => ({
        ...prev,
        [index]: { success: false, error: err instanceof Error ? err.message : 'Test failed' },
      }))
    } finally {
      setTestingWebhook(null)
    }
  }

  const saveWebhooks = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('webhooks', {
        enabled: webhooksEnabled,
        webhooks: webhooks,
      })
      showToast('Webhook settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveSession = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('session', {
        timeout_minutes: sessionTimeout,
      })
      showToast('Session settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveRateLimiting = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('rate_limiting', {
        enabled: rateLimitEnabled,
        max_attempts: rateLimitMaxAttempts,
        lockout_minutes: rateLimitLockoutMinutes,
      })
      showToast('Rate limiting settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveSso = async () => {
    setIsSaving(true)
    try {
      // Build SSO config - only include client_secret if it was changed
      const ssoConfig: Record<string, unknown> = {
        enabled: ssoEnabled,
        issuer_url: ssoIssuerUrl,
        client_id: ssoClientId,
        provider_name: ssoProviderName,
        default_role: ssoDefaultRole,
        // Role mapping settings
        role_mapping_enabled: ssoRoleMappingEnabled,
        role_claim: ssoRoleClaim,
        admin_values: ssoAdminValues,
        analyst_values: ssoAnalystValues,
        viewer_values: ssoViewerValues,
      }
      // Only include client_secret if user entered a new one
      if (ssoClientSecret && ssoClientSecret !== '********') {
        ssoConfig.client_secret = ssoClientSecret
      }

      await settingsApiExtended.update('sso', ssoConfig)
      showToast('SSO settings saved')
      setSsoClientSecret('') // Clear the secret field after save
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveSigmahqSync = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('sigmahq_sync', {
        enabled: sigmahqSyncEnabled,
        interval_hours: sigmahqSyncInterval,
      })
      showToast('SigmaHQ sync settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveAuditOpenSearch = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('audit_opensearch_enabled', {
        enabled: auditOpenSearchEnabled,
      })
      showToast('Audit log settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveAiSettings = async () => {
    setIsSaving(true)
    try {
      const update: AISettingsUpdate = {
        ...aiSettings,
        ...(aiOpenAIKey && { ai_openai_key: aiOpenAIKey }),
        ...(aiAnthropicKey && { ai_anthropic_key: aiAnthropicKey }),
      }
      await settingsApiExtended.update('ai', update)
      showToast('AI settings saved')
      setAiOpenAIKey('')
      setAiAnthropicKey('')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveAppUrl = async () => {
    setIsSaving(true)
    try {
      await settingsApi.setAppUrl(appUrl)
      showToast('Application URL saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">Loading...</div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Configure your CHAD installation</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" asChild>
            <Link to="/settings/audit">
              <FileText className="mr-2 h-4 w-4" /> View Audit Log
            </Link>
          </Button>
          <Button variant="outline" asChild>
            <Link to="/settings/users">
              <Users className="mr-2 h-4 w-4" /> Manage Users
            </Link>
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="sso">SSO</TabsTrigger>
          <TabsTrigger value="ai">AI</TabsTrigger>
          <TabsTrigger value="opensearch">OpenSearch</TabsTrigger>
          <TabsTrigger value="sigmahq">SigmaHQ</TabsTrigger>
          <TabsTrigger value="export">Export</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Application URL</CardTitle>
              <CardDescription>
                Public URL of your CHAD installation. Required for SSO redirects and webhook alert links.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="app-url">Application URL</Label>
                <Input
                  id="app-url"
                  value={appUrl}
                  onChange={(e) => setAppUrl(e.target.value)}
                  placeholder="https://chad.example.com"
                />
                <p className="text-sm text-muted-foreground">
                  Example: https://chad.example.com (no trailing slash)
                </p>
              </div>
              <Button onClick={saveAppUrl} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="webhooks" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Webhook Notifications</CardTitle>
              <CardDescription>
                Configure webhook endpoints for alert notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label>Enable Webhooks</Label>
                  <p className="text-sm text-muted-foreground">
                    Send notifications when alerts are created
                  </p>
                </div>
                <Switch
                  checked={webhooksEnabled}
                  onCheckedChange={setWebhooksEnabled}
                />
              </div>

              {webhooksEnabled && (
                <div className="space-y-4 pt-4 border-t">
                  {webhooks.map((webhook, index) => (
                    <div
                      key={index}
                      className="p-4 border rounded-lg space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={webhook.enabled}
                            onCheckedChange={(checked) =>
                              updateWebhook(index, { enabled: checked })
                            }
                          />
                          <Input
                            value={webhook.name}
                            onChange={(e) =>
                              updateWebhook(index, { name: e.target.value })
                            }
                            placeholder="Webhook name"
                            className="w-48"
                          />
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => testWebhook(index)}
                            disabled={testingWebhook === index}
                          >
                            {testingWebhook === index ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Send className="h-4 w-4" />
                            )}
                            <span className="ml-1">Test</span>
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeWebhook(index)}
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                      {webhookTestResults[index] && (
                        <div
                          className={`text-sm px-3 py-2 rounded-md ${
                            webhookTestResults[index].success
                              ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                              : 'bg-destructive/10 text-destructive'
                          }`}
                        >
                          {webhookTestResults[index].success
                            ? 'Test notification sent successfully!'
                            : `Test failed: ${webhookTestResults[index].error}`}
                        </div>
                      )}
                      <div className="grid grid-cols-3 gap-4">
                        <div className="space-y-2">
                          <Label>Provider</Label>
                          <Select
                            value={webhook.provider}
                            onValueChange={(value) =>
                              updateWebhook(index, {
                                provider: value as WebhookProvider,
                              })
                            }
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="z-50 bg-popover">
                              <SelectItem value="generic">Generic</SelectItem>
                              <SelectItem value="discord">Discord</SelectItem>
                              <SelectItem value="slack">Slack</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>Minimum Severity</Label>
                          <Select
                            value={webhook.severity_filter}
                            onValueChange={(value) =>
                              updateWebhook(index, {
                                severity_filter: value as Webhook['severity_filter'],
                              })
                            }
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="z-50 bg-popover">
                              <SelectItem value="all">All Severities</SelectItem>
                              <SelectItem value="low">Low and above</SelectItem>
                              <SelectItem value="medium">Medium and above</SelectItem>
                              <SelectItem value="high">High and above</SelectItem>
                              <SelectItem value="critical">Critical only</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div></div>
                      </div>
                      <div className="space-y-2">
                        <Label>Webhook URL</Label>
                        <Input
                          value={webhook.url}
                          onChange={(e) =>
                            updateWebhook(index, { url: e.target.value })
                          }
                          placeholder={providerInfo[webhook.provider].placeholder}
                        />
                        <p className="text-xs text-muted-foreground">
                          {providerInfo[webhook.provider].help}
                        </p>
                      </div>
                    </div>
                  ))}

                  <Button
                    variant="outline"
                    onClick={addWebhook}
                    className="w-full"
                  >
                    <Plus className="mr-2 h-4 w-4" /> Add Webhook
                  </Button>
                </div>
              )}

              <Button onClick={saveWebhooks} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="mt-4 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Session Settings</CardTitle>
              <CardDescription>
                Configure authentication and session behavior
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                <Input
                  id="session-timeout"
                  type="number"
                  value={sessionTimeout}
                  onChange={(e) =>
                    setSessionTimeout(parseInt(e.target.value) || 480)
                  }
                  min={15}
                  max={10080}
                />
                <p className="text-sm text-muted-foreground">
                  How long until users are logged out due to inactivity (15 min -
                  7 days)
                </p>
              </div>
              <Button onClick={saveSession} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Rate Limiting</CardTitle>
              <CardDescription>
                Protect against brute force attacks by limiting failed login attempts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label>Enable Rate Limiting</Label>
                  <p className="text-sm text-muted-foreground">
                    Lock accounts after too many failed login attempts
                  </p>
                </div>
                <Switch
                  checked={rateLimitEnabled}
                  onCheckedChange={setRateLimitEnabled}
                />
              </div>

              {rateLimitEnabled && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="rate-limit-max-attempts">Max Failed Attempts</Label>
                    <Input
                      id="rate-limit-max-attempts"
                      type="number"
                      min={1}
                      max={20}
                      value={rateLimitMaxAttempts}
                      onChange={(e) => setRateLimitMaxAttempts(parseInt(e.target.value) || 5)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Number of failed attempts before account lockout
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="rate-limit-lockout-minutes">Lockout Duration (minutes)</Label>
                    <Input
                      id="rate-limit-lockout-minutes"
                      type="number"
                      min={1}
                      max={1440}
                      value={rateLimitLockoutMinutes}
                      onChange={(e) => setRateLimitLockoutMinutes(parseInt(e.target.value) || 15)}
                    />
                    <p className="text-xs text-muted-foreground">
                      How long to lock the account after max attempts
                    </p>
                  </div>
                </>
              )}

              <Button onClick={saveRateLimiting} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="permissions" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Role Permissions</CardTitle>
              <CardDescription>
                Configure what each role can do. Admin permissions cannot be modified.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {['analyst', 'viewer'].map((role) => (
                  <div key={role} className="space-y-4">
                    <h3 className="font-medium capitalize text-lg border-b pb-2">{role}</h3>
                    <div className="grid gap-3">
                      {Object.entries(permissionDescriptions).map(([perm, desc]) => (
                        <div key={perm} className="flex items-center justify-between py-2">
                          <div className="space-y-0.5">
                            <Label className="text-sm font-medium">
                              {perm.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                            </Label>
                            <p className="text-xs text-muted-foreground">{desc}</p>
                          </div>
                          <Switch
                            checked={permissions[role]?.[perm] ?? false}
                            onCheckedChange={async (checked) => {
                              try {
                                await permissionsApi.update(role, perm, checked)
                                setPermissions((prev) => ({
                                  ...prev,
                                  [role]: { ...prev[role], [perm]: checked },
                                }))
                                showToast(`Permission updated for ${role}`)
                              } catch (err) {
                                showToast(
                                  err instanceof Error ? err.message : 'Failed to update permission',
                                  'error'
                                )
                              }
                            }}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {Object.keys(permissionDescriptions).length === 0 && (
                  <p className="text-muted-foreground text-sm">
                    No permissions configured. The permissions API may not be available.
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sso" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Single Sign-On (SSO)</CardTitle>
              <CardDescription>
                Configure OIDC provider for enterprise authentication
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!appUrl && (
                <div className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 p-3 rounded-md">
                  <strong>Warning:</strong> APP URL must be configured for SSO redirects to work correctly.
                  <Button variant="link" className="p-0 h-auto ml-1" onClick={() => setActiveTab('general')}>
                    Configure APP URL
                  </Button>
                </div>
              )}
              <div className="flex items-center justify-between">
                <div>
                  <Label>Enable SSO</Label>
                  <p className="text-sm text-muted-foreground">
                    Allow users to login with your identity provider
                  </p>
                </div>
                <Switch checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
              </div>

              {ssoEnabled && (
                <div className="space-y-4 pt-4 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="sso-provider-name">Provider Name</Label>
                    <Input
                      id="sso-provider-name"
                      value={ssoProviderName}
                      onChange={(e) => setSsoProviderName(e.target.value)}
                      placeholder="Microsoft"
                    />
                    <p className="text-xs text-muted-foreground">
                      Display name on the login button (e.g., "Microsoft", "Okta", "Google")
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso-issuer">Issuer URL</Label>
                    <Input
                      id="sso-issuer"
                      value={ssoIssuerUrl}
                      onChange={(e) => setSsoIssuerUrl(e.target.value)}
                      placeholder="https://login.microsoftonline.com/tenant-id/v2.0"
                    />
                    <p className="text-xs text-muted-foreground">
                      OIDC issuer URL from your identity provider
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso-client-id">Client ID</Label>
                    <Input
                      id="sso-client-id"
                      value={ssoClientId}
                      onChange={(e) => setSsoClientId(e.target.value)}
                      placeholder="your-client-id"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso-client-secret">Client Secret</Label>
                    <Input
                      id="sso-client-secret"
                      type="password"
                      value={ssoClientSecret}
                      onChange={(e) => setSsoClientSecret(e.target.value)}
                      placeholder="Enter new secret to change"
                    />
                    <p className="text-xs text-muted-foreground">
                      Leave blank to keep existing secret
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Default Role for New SSO Users</Label>
                    <Select value={ssoDefaultRole} onValueChange={setSsoDefaultRole}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="analyst">Analyst</SelectItem>
                        <SelectItem value="viewer">Viewer</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      Role assigned to users when role mapping is disabled or no match found
                    </p>
                  </div>

                  {/* Role Mapping Section */}
                  <div className="pt-4 border-t space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label>Enable Role Mapping</Label>
                        <p className="text-sm text-muted-foreground">
                          Automatically assign roles based on IdP claims
                        </p>
                      </div>
                      <Switch
                        checked={ssoRoleMappingEnabled}
                        onCheckedChange={setSsoRoleMappingEnabled}
                      />
                    </div>

                    {ssoRoleMappingEnabled && (
                      <div className="space-y-4 pl-4 border-l-2 border-muted">
                        <div className="space-y-2">
                          <Label htmlFor="role-claim">Role Claim</Label>
                          <Input
                            id="role-claim"
                            value={ssoRoleClaim}
                            onChange={(e) => setSsoRoleClaim(e.target.value)}
                            placeholder="groups"
                          />
                          <p className="text-xs text-muted-foreground">
                            The claim name in the token containing user roles (e.g., "groups", "roles", "role")
                          </p>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="admin-values">Admin Claim Values</Label>
                          <Input
                            id="admin-values"
                            value={ssoAdminValues}
                            onChange={(e) => setSsoAdminValues(e.target.value)}
                            placeholder="chad-admins, security-team"
                          />
                          <p className="text-xs text-muted-foreground">
                            Comma-separated values that grant Admin role
                          </p>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="analyst-values">Analyst Claim Values</Label>
                          <Input
                            id="analyst-values"
                            value={ssoAnalystValues}
                            onChange={(e) => setSsoAnalystValues(e.target.value)}
                            placeholder="chad-analysts, soc-analysts"
                          />
                          <p className="text-xs text-muted-foreground">
                            Comma-separated values that grant Analyst role
                          </p>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="viewer-values">Viewer Claim Values</Label>
                          <Input
                            id="viewer-values"
                            value={ssoViewerValues}
                            onChange={(e) => setSsoViewerValues(e.target.value)}
                            placeholder="chad-viewers, read-only"
                          />
                          <p className="text-xs text-muted-foreground">
                            Comma-separated values that grant Viewer role
                          </p>
                        </div>

                        <div className="p-3 bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 rounded-md text-sm">
                          <strong>Note:</strong> Role mapping syncs on every login. If a user's groups change in the IdP, their CHAD role will update on next sign-in.
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="pt-4 border-t">
                    <div className="p-3 bg-muted rounded-md">
                      <p className="text-sm font-medium mb-1">Callback URL</p>
                      <code className="text-xs bg-background px-2 py-1 rounded">
                        {window.location.origin}/api/auth/sso/callback
                      </code>
                      <p className="text-xs text-muted-foreground mt-1">
                        Register this URL in your identity provider
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <Button onClick={saveSso} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ai" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>AI Field Mapping</CardTitle>
              <CardDescription>
                Configure AI providers to suggest field mappings between Sigma rules and your log data
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>AI Provider</Label>
                <Select
                  value={aiSettings.ai_provider}
                  onValueChange={(value) =>
                    setAiSettings({ ...aiSettings, ai_provider: value as AIProvider })
                  }
                >
                  <SelectTrigger className="w-64">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    <SelectItem value="disabled">Disabled</SelectItem>
                    <SelectItem value="ollama">Ollama (Local)</SelectItem>
                    <SelectItem value="openai">OpenAI</SelectItem>
                    <SelectItem value="anthropic">Anthropic</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Choose an AI provider for generating field mapping suggestions
                </p>
              </div>

              {aiSettings.ai_provider === 'ollama' && (
                <div className="space-y-4 pt-4 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="ollama-url">Ollama URL</Label>
                    <Input
                      id="ollama-url"
                      value={aiSettings.ai_ollama_url}
                      onChange={(e) =>
                        setAiSettings({ ...aiSettings, ai_ollama_url: e.target.value })
                      }
                      placeholder="http://localhost:11434"
                    />
                    <p className="text-xs text-muted-foreground">
                      URL of your local Ollama instance
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="ollama-model">Model</Label>
                    <Input
                      id="ollama-model"
                      value={aiSettings.ai_ollama_model}
                      onChange={(e) =>
                        setAiSettings({ ...aiSettings, ai_ollama_model: e.target.value })
                      }
                      placeholder="llama3"
                    />
                    <p className="text-xs text-muted-foreground">
                      Ollama model name (e.g., llama3, mistral, codellama)
                    </p>
                  </div>
                  <div className="flex items-center justify-between pt-2">
                    <div className="space-y-0.5">
                      <Label>Allow Log Samples</Label>
                      <p className="text-sm text-muted-foreground">
                        Include sample log data to improve mapping accuracy
                      </p>
                    </div>
                    <Switch
                      checked={aiSettings.ai_allow_log_samples}
                      onCheckedChange={(checked) =>
                        setAiSettings({ ...aiSettings, ai_allow_log_samples: checked })
                      }
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Since Ollama runs locally, log samples stay on your machine
                  </p>
                </div>
              )}

              {aiSettings.ai_provider === 'openai' && (
                <div className="space-y-4 pt-4 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="openai-key">API Key</Label>
                    <Input
                      id="openai-key"
                      type="password"
                      value={aiOpenAIKey}
                      onChange={(e) => setAiOpenAIKey(e.target.value)}
                      placeholder="Enter new key to change"
                    />
                    <p className="text-xs text-muted-foreground">
                      Leave blank to keep existing key
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="openai-model">Model</Label>
                    <Select
                      value={aiSettings.ai_openai_model}
                      onValueChange={(value) =>
                        setAiSettings({ ...aiSettings, ai_openai_model: value })
                      }
                    >
                      <SelectTrigger id="openai-model" className="w-64">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="gpt-4o">GPT-4o</SelectItem>
                        <SelectItem value="gpt-4o-mini">GPT-4o Mini</SelectItem>
                        <SelectItem value="gpt-4-turbo">GPT-4 Turbo</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="p-3 bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 rounded-md text-sm">
                    <strong>Privacy:</strong> Only field names are sent to OpenAI. Log samples are never sent to cloud providers.
                  </div>
                </div>
              )}

              {aiSettings.ai_provider === 'anthropic' && (
                <div className="space-y-4 pt-4 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="anthropic-key">API Key</Label>
                    <Input
                      id="anthropic-key"
                      type="password"
                      value={aiAnthropicKey}
                      onChange={(e) => setAiAnthropicKey(e.target.value)}
                      placeholder="Enter new key to change"
                    />
                    <p className="text-xs text-muted-foreground">
                      Leave blank to keep existing key
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="anthropic-model">Model</Label>
                    <Select
                      value={aiSettings.ai_anthropic_model}
                      onValueChange={(value) =>
                        setAiSettings({ ...aiSettings, ai_anthropic_model: value })
                      }
                    >
                      <SelectTrigger id="anthropic-model" className="w-64">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="claude-sonnet-4-20250514">Claude Sonnet 4</SelectItem>
                        <SelectItem value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet</SelectItem>
                        <SelectItem value="claude-3-haiku-20240307">Claude 3 Haiku</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="p-3 bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 rounded-md text-sm">
                    <strong>Privacy:</strong> Only field names are sent to Anthropic. Log samples are never sent to cloud providers.
                  </div>
                </div>
              )}

              <Button onClick={saveAiSettings} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="opensearch" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>OpenSearch Connection</CardTitle>
              <CardDescription>
                Manage your OpenSearch cluster connection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Connection Status Indicator */}
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center gap-3">
                  {osConnectionLoading ? (
                    <div className="h-3 w-3 rounded-full bg-gray-400 animate-pulse" />
                  ) : osConnectionStatus?.connected ? (
                    <div className="h-3 w-3 rounded-full bg-green-500" />
                  ) : (
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                  )}
                  <div>
                    <p className="font-medium">
                      {osConnectionLoading
                        ? 'Checking connection...'
                        : osConnectionStatus?.connected
                        ? 'Connected'
                        : 'Disconnected'}
                    </p>
                    {osConnectionStatus?.connected && osConnectionStatus.version && (
                      <p className="text-sm text-muted-foreground">
                        Version: {osConnectionStatus.version}
                      </p>
                    )}
                    {osConnectionStatus?.error && (
                      <p className="text-sm text-destructive">{osConnectionStatus.error}</p>
                    )}
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={checkOpenSearchConnection}
                  disabled={osConnectionLoading}
                >
                  Test Connection
                </Button>
              </div>

              {osStatus?.configured && osStatus.config ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Host:</span>
                      <span className="ml-2 font-mono">{osStatus.config.host}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Port:</span>
                      <span className="ml-2 font-mono">{osStatus.config.port}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Username:</span>
                      <span className="ml-2 font-mono">{osStatus.config.username || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">SSL:</span>
                      <span className="ml-2">{osStatus.config.use_ssl ? 'Enabled' : 'Disabled'}</span>
                    </div>
                  </div>
                  <div className="pt-2 border-t">
                    <Button variant="outline" asChild>
                      <Link to="/opensearch-wizard">Reconfigure OpenSearch</Link>
                    </Button>
                  </div>
                </div>
              ) : (
                <div>
                  <p className="text-sm text-muted-foreground mb-4">
                    OpenSearch is not configured. Configure it to enable rule deployment and alerting.
                  </p>
                  <Button variant="default" asChild>
                    <Link to="/opensearch-wizard">Configure OpenSearch</Link>
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="mt-4">
            <CardHeader>
              <CardTitle>Audit Log Storage</CardTitle>
              <CardDescription>
                Store audit logs in OpenSearch for advanced search and long-term retention
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Write Audit Logs to OpenSearch</Label>
                  <p className="text-sm text-muted-foreground">
                    In addition to the database, also write audit events to the <code className="text-xs bg-muted px-1 py-0.5 rounded">chad-audit-logs</code> index
                  </p>
                </div>
                <Switch
                  checked={auditOpenSearchEnabled}
                  onCheckedChange={setAuditOpenSearchEnabled}
                  disabled={!osStatus?.configured}
                  aria-label="Enable audit log storage in OpenSearch"
                />
              </div>

              {!osStatus?.configured && (
                <p className="text-sm text-yellow-600 dark:text-yellow-400">
                  OpenSearch must be configured to enable this feature.
                </p>
              )}

              <Button onClick={saveAuditOpenSearch} disabled={isSaving || !osStatus?.configured}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sigmahq" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>SigmaHQ Auto-Sync</CardTitle>
              <CardDescription>
                Configure automatic synchronization of the SigmaHQ rules repository.
                When enabled, CHAD will periodically pull the latest rules from SigmaHQ.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Auto-Sync</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically sync SigmaHQ rules repository on a schedule
                  </p>
                </div>
                <Switch
                  checked={sigmahqSyncEnabled}
                  onCheckedChange={setSigmahqSyncEnabled}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="sync-interval">Sync Interval (hours)</Label>
                <Select
                  value={sigmahqSyncInterval.toString()}
                  onValueChange={(v) => setSigmahqSyncInterval(parseInt(v))}
                  disabled={!sigmahqSyncEnabled}
                >
                  <SelectTrigger id="sync-interval" className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    <SelectItem value="6">Every 6 hours</SelectItem>
                    <SelectItem value="12">Every 12 hours</SelectItem>
                    <SelectItem value="24">Daily (24 hours)</SelectItem>
                    <SelectItem value="48">Every 2 days</SelectItem>
                    <SelectItem value="168">Weekly</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  How often to check for new rules in the SigmaHQ repository
                </p>
              </div>

              {sigmahqLastSync && (
                <div className="text-sm text-muted-foreground">
                  Last synced: {new Date(sigmahqLastSync).toLocaleString()}
                </div>
              )}

              <div className="pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-4">
                  You can also manually sync at any time from the SigmaHQ browser page.
                </p>
                <Button onClick={saveSigmahqSync} disabled={isSaving}>
                  {isSaving ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="mr-2 h-4 w-4" />
                      Save Settings
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="export" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Export Rules</CardTitle>
              <CardDescription>
                Download detection rules as Sigma YAML files
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Export all rules in your library as a ZIP archive containing individual YAML files.
              </p>
              <Button
                onClick={async () => {
                  try {
                    await downloadWithAuth('/api/export/rules', `chad-rules-${new Date().toISOString().slice(0, 10)}.zip`)
                  } catch (err) {
                    showToast(err instanceof Error ? err.message : 'Export failed', 'error')
                  }
                }}
              >
                Export All Rules (ZIP)
              </Button>
            </CardContent>
          </Card>

          <Card className="mt-4">
            <CardHeader>
              <CardTitle>Configuration Backup</CardTitle>
              <CardDescription>
                Download system configuration (excludes sensitive data like passwords and tokens)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                The configuration backup includes: index patterns, general settings, webhooks, and role permissions.
                Sensitive data like OpenSearch credentials and API tokens are excluded for security.
              </p>
              <Button
                onClick={async () => {
                  try {
                    await downloadWithAuth('/api/export/config', `chad-config-${new Date().toISOString().slice(0, 10)}.json`)
                  } catch (err) {
                    showToast(err instanceof Error ? err.message : 'Export failed', 'error')
                  }
                }}
              >
                Export Configuration (JSON)
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
