import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { settingsApiExtended, settingsApi, statsApi, api, configApi, ImportMode, ImportSummary, OpenSearchStatusResponse, AIProvider, AISettings, AISettingsUpdate, AITestResponse, HealthSettings, alertClusteringApi, AlertClusteringSettings, queueApi, QueueSettings, healthApi } from '@/lib/api'
import Notifications from '@/pages/Notifications'
import GeoIPSettings from '@/pages/GeoIPSettings'
import TISettings from '@/pages/TISettings'
import EnrichmentWebhooksSettings from '@/pages/EnrichmentWebhooksSettings'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { CheckCircle2, ChevronDown, Download, Loader2, Save, Upload, XCircle } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
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

export default function SettingsPage() {
  const { showToast } = useToast()
  const [searchParams] = useSearchParams()
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)

  // Session settings
  const [sessionTimeout, setSessionTimeout] = useState(480)

  // Rate limiting settings
  const [rateLimitEnabled, setRateLimitEnabled] = useState(true)
  const [rateLimitMaxAttempts, setRateLimitMaxAttempts] = useState(5)
  const [rateLimitLockoutMinutes, setRateLimitLockoutMinutes] = useState(15)

  // 2FA settings
  const [force2FAOnSignup, setForce2FAOnSignup] = useState(false)

  // API key rate limiting
  const [apiKeyRateLimit, setApiKeyRateLimit] = useState(100)

  // Active tab for programmatic navigation - read from URL param if present
  const activeTab = searchParams.get('tab') || 'general'

  // SSO settings
  const [ssoEnabled, setSsoEnabled] = useState(false)
  const [ssoIssuerUrl, setSsoIssuerUrl] = useState('')
  const [ssoClientId, setSsoClientId] = useState('')
  const [ssoClientSecret, setSsoClientSecret] = useState('')
  const [ssoProviderName, setSsoProviderName] = useState('SSO')
  const [ssoDefaultRole, setSsoDefaultRole] = useState('analyst')

  // SSO Advanced settings
  const [ssoTokenAuthMethod, setSsoTokenAuthMethod] = useState('client_secret_post')
  const [ssoScopes, setSsoScopes] = useState('openid email profile')

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

  // ATT&CK sync settings
  const [attackSyncEnabled, setAttackSyncEnabled] = useState(false)
  const [attackSyncInterval, setAttackSyncInterval] = useState(168)
  const [attackLastSync, setAttackLastSync] = useState<string | null>(null)

  // OpenSearch settings
  const [osStatus, setOsStatus] = useState<OpenSearchStatusResponse | null>(null)
  const [osConnectionStatus, setOsConnectionStatus] = useState<{
    connected: boolean
    version?: string
    error?: string
  } | null>(null)
  const [osConnectionLoading, setOsConnectionLoading] = useState(false)

  // Health monitoring settings
  const [healthSettings, setHealthSettings] = useState<HealthSettings>({
    no_data_minutes: 15,
    error_rate_percent: 5.0,
    detection_latency_warning_ms: 2,
    detection_latency_critical_ms: 10,
    opensearch_latency_warning_ms: 1,
    opensearch_latency_critical_ms: 5,
    queue_warning: 10000,
    queue_critical: 100000,
    data_freshness_warning_minutes: 60,
    data_freshness_critical_minutes: 240,
  })
  const [healthSettingsForm, setHealthSettingsForm] = useState<HealthSettings>(healthSettings)
  const [isSavingHealthSettings, setIsSavingHealthSettings] = useState(false)

  // Health check intervals
  const [healthCheckIntervals, setHealthCheckIntervals] = useState({
    jira_interval_seconds: 900,
    sigmahq_interval_seconds: 3600,
    mitre_attack_interval_seconds: 3600,
    opensearch_interval_seconds: 300,
    ti_interval_seconds: 1800,
  })
  const [healthCheckIntervalsForm, setHealthCheckIntervalsForm] = useState(healthCheckIntervals)
  const [isSavingHealthCheckIntervals, setIsSavingHealthCheckIntervals] = useState(false)

  // Pull mode settings
  const [pullModeSettings, setPullModeSettings] = useState({
    max_retries: 3,
    retry_delay_seconds: 5,
    consecutive_failures_warning: 3,
    consecutive_failures_critical: 10,
  })
  const [pullModeSettingsForm, setPullModeSettingsForm] = useState(pullModeSettings)
  const [isSavingPullModeSettings, setIsSavingPullModeSettings] = useState(false)

  // Version cleanup settings
  const [versionCleanupEnabled, setVersionCleanupEnabled] = useState(true)
  const [versionCleanupMinKeep, setVersionCleanupMinKeep] = useState(10)
  const [versionCleanupMaxAgeDays, setVersionCleanupMaxAgeDays] = useState(90)
  const [isSavingVersionCleanup, setIsSavingVersionCleanup] = useState(false)

  // System log retention settings
  const [systemLogRetention, setSystemLogRetention] = useState(14)
  const [isSavingSystemLogRetention, setIsSavingSystemLogRetention] = useState(false)

  // Audit to OpenSearch
  const [auditOpenSearchEnabled, setAuditOpenSearchEnabled] = useState(false)

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
  const [aiOpenAIKeyConfigured, setAiOpenAIKeyConfigured] = useState(false)
  const [aiAnthropicKeyConfigured, setAiAnthropicKeyConfigured] = useState(false)
  const [aiTestLoading, setAiTestLoading] = useState(false)
  const [aiTestResult, setAiTestResult] = useState<AITestResponse | null>(null)
  const [aiLastTested, setAiLastTested] = useState<string | null>(null)
  const [aiLastTestSuccess, setAiLastTestSuccess] = useState<boolean | null>(null)

  // Import/Export state
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importMode, setImportMode] = useState<ImportMode>('skip')
  const [isImporting, setIsImporting] = useState(false)
  const [importPreview, setImportPreview] = useState<ImportSummary | null>(null)
  const [importResult, setImportResult] = useState<ImportSummary | null>(null)

  // Alert Clustering settings
  const [alertClusteringSettings, setAlertClusteringSettings] = useState<AlertClusteringSettings>({
    enabled: false,
    window_minutes: 60,
  })
  const [alertClusteringForm, setAlertClusteringForm] = useState<AlertClusteringSettings>(alertClusteringSettings)
  const [isSavingAlertClustering, setIsSavingAlertClustering] = useState(false)

  // Rule deployment settings
  const [deploymentThreshold, setDeploymentThreshold] = useState(100)

  // Queue settings
  const [queueSettings, setQueueSettings] = useState<QueueSettings>({
    max_queue_size: 100000,
    warning_threshold: 10000,
    critical_threshold: 50000,
    backpressure_mode: 'drop',
    batch_size: 500,
    batch_timeout_seconds: 5,
    message_ttl_seconds: 1800,
  })
  const [queueSettingsForm, setQueueSettingsForm] = useState<QueueSettings>(queueSettings)
  const [isSavingQueueSettings, setIsSavingQueueSettings] = useState(false)

  useEffect(() => {
    loadSettings()
    loadOpenSearchStatus()
    loadSecuritySettings()
    loadHealthSettings()
    loadAlertClusteringSettings()
    loadQueueSettings()
    loadRuleSettings()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loadSecuritySettings = async () => {
    try {
      const security = await settingsApi.getSecuritySettings()
      setForce2FAOnSignup(security.force_2fa_on_signup)
      setApiKeyRateLimit(security.api_key_rate_limit)
    } catch (error) {
      console.error('Failed to load security settings:', error)
    }
  }

  const loadHealthSettings = async () => {
    try {
      const [thresholds, intervals, pullMode] = await Promise.all([
        settingsApi.getHealthSettings(),
        api.get('/health/intervals'),
        healthApi.getPullModeSettings()
      ] as const)
      // Convert ms to seconds for display
      const displayThresholds = {
        ...thresholds,
        detection_latency_warning_ms: thresholds.detection_latency_warning_ms / 1000,
        detection_latency_critical_ms: thresholds.detection_latency_critical_ms / 1000,
        opensearch_latency_warning_ms: thresholds.opensearch_latency_warning_ms / 1000,
        opensearch_latency_critical_ms: thresholds.opensearch_latency_critical_ms / 1000,
      }
      setHealthSettings(displayThresholds)
      setHealthSettingsForm(displayThresholds)
      setHealthCheckIntervals(intervals as typeof healthCheckIntervals)
      setHealthCheckIntervalsForm(intervals as typeof healthCheckIntervals)
      setPullModeSettings(pullMode)
      setPullModeSettingsForm(pullMode)
    } catch (err) {
      console.error('Failed to load health settings:', err)
    }
  }

  const loadAlertClusteringSettings = async () => {
    try {
      const settings = await alertClusteringApi.getSettings()
      setAlertClusteringSettings(settings)
      setAlertClusteringForm(settings)
    } catch (err) {
      console.error('Failed to load alert clustering settings:', err)
    }
  }

  const loadRuleSettings = async () => {
    try {
      const ruleSettings = await settingsApi.getRuleSettings()
      setDeploymentThreshold(ruleSettings.deployment_alert_threshold)
    } catch {
      // Use default
    }
  }

  const saveAlertClusteringSettings = async () => {
    setIsSavingAlertClustering(true)
    try {
      await alertClusteringApi.updateSettings(alertClusteringForm)
      setAlertClusteringSettings(alertClusteringForm)
      showToast('Alert clustering settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save alert clustering settings', 'error')
    } finally {
      setIsSavingAlertClustering(false)
    }
  }

  const loadQueueSettings = async () => {
    try {
      const settings = await queueApi.getSettings()
      setQueueSettings(settings)
      setQueueSettingsForm(settings)
    } catch (err) {
      // Queue settings may not be available if Redis is not configured
      console.error('Failed to load queue settings:', err)
    }
  }

  const saveQueueSettings = async () => {
    setIsSavingQueueSettings(true)
    try {
      const updated = await queueApi.updateSettings(queueSettingsForm)
      setQueueSettings(updated)
      showToast('Queue settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save queue settings', 'error')
    } finally {
      setIsSavingQueueSettings(false)
    }
  }

  // Check OpenSearch connection when the tab is selected
  useEffect(() => {
    if (activeTab === 'opensearch') {
      checkOpenSearchConnection()
    }
  }, [activeTab])

  const loadSettings = async () => {
    try {
      const settings = await settingsApiExtended.getAll()

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
        // Advanced settings
        setSsoTokenAuthMethod((sso.token_auth_method as string) || 'client_secret_post')
        setSsoScopes((sso.scopes as string) || 'openid email profile')
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

      // ATT&CK sync settings
      if (settings.attack_sync && typeof settings.attack_sync === 'object') {
        const attack = settings.attack_sync as Record<string, unknown>
        setAttackSyncEnabled((attack.enabled as boolean) || false)
        setAttackSyncInterval((attack.interval_hours as number) || 168)
        setAttackLastSync((attack.last_sync as string) || null)
      }

      // Version cleanup settings
      if (settings.version_cleanup && typeof settings.version_cleanup === 'object') {
        const cleanup = settings.version_cleanup as Record<string, unknown>
        setVersionCleanupEnabled(cleanup.enabled !== false)
        setVersionCleanupMinKeep((cleanup.min_keep as number) || 10)
        setVersionCleanupMaxAgeDays((cleanup.max_age_days as number) || 90)
      }

      // System log retention settings
      if (settings.system_log_retention && typeof settings.system_log_retention === 'object') {
        const retention = settings.system_log_retention as Record<string, unknown>
        setSystemLogRetention((retention.retention_days as number) || 14)
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
        // Check if keys are configured (they'll be masked as "********")
        setAiOpenAIKeyConfigured(ai.ai_openai_key === '********')
        setAiAnthropicKeyConfigured(ai.ai_anthropic_key === '********')
        // Set last tested time and success status if available
        if (ai.last_tested) {
          setAiLastTested(ai.last_tested as string)
        }
        if (ai.last_test_success !== undefined) {
          setAiLastTestSuccess(ai.last_test_success as boolean)
        }
      }
    } catch {
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
    } catch {
      console.log('Failed to load OpenSearch status')
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

  // Combined save for all security settings
  const saveAllSecuritySettings = async () => {
    setIsSaving(true)
    try {
      await Promise.all([
        settingsApiExtended.update('session', {
          timeout_minutes: sessionTimeout,
        }),
        settingsApiExtended.update('rate_limiting', {
          enabled: rateLimitEnabled,
          max_attempts: rateLimitMaxAttempts,
          lockout_minutes: rateLimitLockoutMinutes,
        }),
        settingsApi.updateSecuritySettings({
          force_2fa_on_signup: force2FAOnSignup,
          api_key_rate_limit: apiKeyRateLimit
        })
      ])
      showToast('All security settings saved')
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
        // Advanced settings
        token_auth_method: ssoTokenAuthMethod,
        scopes: ssoScopes,
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

  const saveAttackSync = async () => {
    setIsSaving(true)
    try {
      await settingsApiExtended.update('attack_sync', {
        enabled: attackSyncEnabled,
        interval_hours: attackSyncInterval,
      })
      showToast('ATT&CK sync settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const saveVersionCleanup = async () => {
    setIsSavingVersionCleanup(true)
    try {
      await settingsApiExtended.update('version_cleanup', {
        enabled: versionCleanupEnabled,
        min_keep: versionCleanupMinKeep,
        max_age_days: versionCleanupMaxAgeDays,
      })
      showToast('Version cleanup settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSavingVersionCleanup(false)
    }
  }

  const saveSystemLogRetention = async () => {
    setIsSavingSystemLogRetention(true)
    try {
      await settingsApiExtended.update('system_log_retention', {
        retention_days: systemLogRetention,
      })
      showToast('System log retention settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSavingSystemLogRetention(false)
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
      // Update key configured status if new keys were provided
      if (aiOpenAIKey) setAiOpenAIKeyConfigured(true)
      if (aiAnthropicKey) setAiAnthropicKeyConfigured(true)
      setAiOpenAIKey('')
      setAiAnthropicKey('')
      // Clear test result since settings changed
      setAiTestResult(null)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const testAiConnection = async () => {
    setAiTestLoading(true)
    setAiTestResult(null)
    try {
      const result = await settingsApi.testAI()
      setAiTestResult(result)
      if (result.last_tested) {
        setAiLastTested(result.last_tested)
      }
      if (result.last_test_success !== undefined) {
        setAiLastTestSuccess(result.last_test_success)
      }
    } catch (err) {
      setAiTestResult({
        success: false,
        provider: aiSettings.ai_provider,
        error: err instanceof Error ? err.message : 'Test failed',
      })
    } finally {
      setAiTestLoading(false)
    }
  }

  const saveHealthSettings = async () => {
    setIsSavingHealthSettings(true)
    try {
      // Convert seconds to ms for API
      const apiData = {
        ...healthSettingsForm,
        detection_latency_warning_ms: healthSettingsForm.detection_latency_warning_ms * 1000,
        detection_latency_critical_ms: healthSettingsForm.detection_latency_critical_ms * 1000,
        opensearch_latency_warning_ms: healthSettingsForm.opensearch_latency_warning_ms * 1000,
        opensearch_latency_critical_ms: healthSettingsForm.opensearch_latency_critical_ms * 1000,
      }
      await settingsApi.updateHealthSettings(apiData)
      setHealthSettings(healthSettingsForm)
      showToast('Health settings saved successfully')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save health settings', 'error')
    } finally {
      setIsSavingHealthSettings(false)
    }
  }

  const savePullModeSettings = async () => {
    setIsSavingPullModeSettings(true)
    try {
      await healthApi.updatePullModeSettings(pullModeSettingsForm)
      setPullModeSettings(pullModeSettingsForm)
      showToast('Pull mode settings saved successfully')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save pull mode settings', 'error')
    } finally {
      setIsSavingPullModeSettings(false)
    }
  }


  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Loading skeleton */}
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-72 mt-2" />
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-10 w-full" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-10 w-full" />
            </div>
            <div className="flex justify-end pt-4">
              <Skeleton className="h-10 w-24" />
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">

      {/* Notifications Section */}
      {activeTab === 'notifications' && (
        <Notifications />
      )}

      {/* Security Section - combines security, permissions, and sso */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          {/* Session & Rate Limiting */}
          <Collapsible defaultOpen>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Session & Rate Limiting</CardTitle>
                      <CardDescription>Configure session timeout and brute force protection</CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200 [&[data-state=open]]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6" data-form-type="other" data-lpignore="true" data-1p-ignore="true" data-protonpass-ignore="true">
                  {/* Hidden autofill trap to prevent password managers from offering TOTP */}
                  <div aria-hidden="true" style={{ position: 'absolute', left: '-9999px', opacity: 0 }}>
                    <input
                      type="text"
                      name="otp"
                      id="trap-otp"
                      tabIndex={-1}
                      autoComplete="one-time-code"
                      data-protonpass-ignore="true"
                      data-lpignore="true"
                      data-1p-ignore="true"
                    />
                  </div>

                  {/* Session Settings */}
                  <div className="space-y-4">
                    <h4 className="text-sm font-medium">Session Settings</h4>
                    <div className="space-y-2">
                      <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                      <Input
                        id="session-timeout"
                        type="number"
                        autoComplete="off"
                        className="w-32"
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
                  </div>

                  <div className="border-t pt-6">
                    <h4 className="text-sm font-medium mb-4">Rate Limiting</h4>
                    <div className="space-y-4">
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
                              autoComplete="off"
                              className="w-32"
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
                              autoComplete="off"
                              className="w-32"
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
                    </div>
                  </div>

                  <div className="border-t pt-6">
                    <h4 className="text-sm font-medium mb-4">API Key Rate Limiting</h4>
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="api-key-rate-limit">Requests Per Minute</Label>
                        <Input
                          id="api-key-rate-limit"
                          type="number"
                          autoComplete="off"
                          className="w-32"
                          min={1}
                          max={10000}
                          value={apiKeyRateLimit}
                          onChange={(e) => setApiKeyRateLimit(parseInt(e.target.value) || 100)}
                        />
                        <p className="text-xs text-muted-foreground">
                          Maximum API requests per minute per API key (applies to external API endpoints)
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="border-t pt-6" data-lpignore="true" data-1p-ignore="true" data-protonpass-ignore="true">
                    <h4 className="text-sm font-medium mb-4">Multi-Factor Policy</h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <Label>Require Multi-Factor Authentication</Label>
                          <p className="text-sm text-muted-foreground">
                            Users without MFA must set it up on login. Users can still enable MFA from their Account page if this is disabled.
                          </p>
                        </div>
                        <Switch
                          checked={force2FAOnSignup}
                          onCheckedChange={setForce2FAOnSignup}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Single save button for all security settings */}
                  <div className="flex justify-end pt-6 border-t">
                    <Button onClick={saveAllSecuritySettings} disabled={isSaving}>
                      {isSaving ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="mr-2 h-4 w-4" />
                          Save All Settings
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        </div>
      )}

      {/* SSO Section */}
      {activeTab === 'sso' && (
        <Card>
          <CardHeader>
            <CardTitle>Single Sign-On (SSO)</CardTitle>
            <CardDescription>Configure OIDC provider for enterprise authentication</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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

                {/* Advanced OAuth Settings */}
                <div className="pt-4 border-t space-y-4">
                  <h4 className="text-sm font-medium">Advanced OAuth Settings</h4>

                  <div className="space-y-2">
                    <Label>OAuth Scopes</Label>
                    <Input
                      value={ssoScopes}
                      onChange={(e) => setSsoScopes(e.target.value)}
                      placeholder="openid email profile"
                    />
                    <p className="text-xs text-muted-foreground">
                      Space-separated list of scopes to request. Add "groups" or "roles" if needed for role mapping.
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Token Auth Method</Label>
                    <Select value={ssoTokenAuthMethod} onValueChange={setSsoTokenAuthMethod}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="client_secret_post">POST Body (Most Common)</SelectItem>
                        <SelectItem value="client_secret_basic">HTTP Basic Auth</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      How credentials are sent to the token endpoint. Try switching if you get "Invalid client secret" errors.
                    </p>
                  </div>
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
      )}

      {/* AI Section */}
      {activeTab === 'ai' && (
        <Card>
          <CardHeader>
            <CardTitle>AI Field Mapping</CardTitle>
            <CardDescription>
              Configure AI providers to suggest field mappings between Sigma rules and your log data
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Connection Status Indicator */}
            {aiSettings.ai_provider !== 'disabled' && (
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center gap-3">
                  {aiTestLoading ? (
                    <div className="h-3 w-3 rounded-full bg-gray-400 animate-pulse" />
                  ) : aiTestResult?.success ? (
                    <div className="h-3 w-3 rounded-full bg-green-500" />
                  ) : aiTestResult ? (
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                  ) : aiLastTestSuccess === true ? (
                    <div className="h-3 w-3 rounded-full bg-green-500" />
                  ) : aiLastTestSuccess === false ? (
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                  ) : (
                    <div className="h-3 w-3 rounded-full bg-gray-300" />
                  )}
                  <div>
                    <p className="font-medium">
                      {aiTestLoading
                        ? 'Testing connection...'
                        : aiTestResult?.success
                        ? 'Connected'
                        : aiTestResult
                        ? 'Connection failed'
                        : aiLastTestSuccess === true
                        ? 'Connected'
                        : aiLastTestSuccess === false
                        ? 'Connection failed'
                        : 'Not tested'}
                    </p>
                    {aiTestResult && !aiTestResult.success && (
                      <p className="text-sm text-destructive">
                        {aiTestResult.error || 'Unknown error'}
                      </p>
                    )}
                    {aiLastTested && !aiTestLoading && (
                      <p className="text-xs text-muted-foreground">
                        Last tested: {new Date(aiLastTested).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={testAiConnection}
                  disabled={aiTestLoading}
                >
                  {aiTestLoading ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-1" />
                  ) : null}
                  Test Connection
                </Button>
              </div>
            )}

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
                  <div className="flex items-center justify-between">
                    <Label htmlFor="openai-key">API Key</Label>
                    {aiOpenAIKeyConfigured ? (
                      <span className="flex items-center text-xs text-green-600 dark:text-green-400">
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Configured
                      </span>
                    ) : (
                      <span className="flex items-center text-xs text-muted-foreground">
                        <XCircle className="h-3 w-3 mr-1" />
                        Not configured
                      </span>
                    )}
                  </div>
                  <Input
                    id="openai-key"
                    type="password"
                    value={aiOpenAIKey}
                    onChange={(e) => setAiOpenAIKey(e.target.value)}
                    placeholder={aiOpenAIKeyConfigured ? "Enter new key to change" : "Enter API key"}
                  />
                  {aiOpenAIKeyConfigured && (
                    <p className="text-xs text-muted-foreground">
                      Leave blank to keep existing key
                    </p>
                  )}
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
                  <div className="flex items-center justify-between">
                    <Label htmlFor="anthropic-key">API Key</Label>
                    {aiAnthropicKeyConfigured ? (
                      <span className="flex items-center text-xs text-green-600 dark:text-green-400">
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Configured
                      </span>
                    ) : (
                      <span className="flex items-center text-xs text-muted-foreground">
                        <XCircle className="h-3 w-3 mr-1" />
                        Not configured
                      </span>
                    )}
                  </div>
                  <Input
                    id="anthropic-key"
                    type="password"
                    value={aiAnthropicKey}
                    onChange={(e) => setAiAnthropicKey(e.target.value)}
                    placeholder={aiAnthropicKeyConfigured ? "Enter new key to change" : "Enter API key"}
                  />
                  {aiAnthropicKeyConfigured && (
                    <p className="text-xs text-muted-foreground">
                      Leave blank to keep existing key
                    </p>
                  )}
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
      )}

      {/* GeoIP Settings */}
      {activeTab === 'geoip' && (
        <GeoIPSettings />
      )}

      {/* Threat Intel Settings */}
      {activeTab === 'ti' && (
        <TISettings />
      )}

      {/* Custom Enrichment Webhooks */}
      {activeTab === 'webhooks' && (
        <EnrichmentWebhooksSettings />
      )}

      {/* Queue Section - combines push-queue and pull-queue */}
      {activeTab === 'queue' && (
        <div className="space-y-6">
          {/* Push Queue */}
          <Collapsible defaultOpen>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Push Queue Configuration</CardTitle>
                      <CardDescription>Configure log queue processing and backpressure settings for push mode detection</CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200 [&[data-state=open]]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="max_queue_size">Max Queue Size</Label>
                      <Input
                        id="max_queue_size"
                        type="number"
                        min={1000}
                        value={queueSettingsForm.max_queue_size}
                        onChange={e => setQueueSettingsForm(prev => ({ ...prev, max_queue_size: parseInt(e.target.value) || 100000 }))}
                      />
                      <p className="text-xs text-muted-foreground">Maximum number of messages in queue</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="warning_threshold">Warning Threshold</Label>
                      <Input
                        id="warning_threshold"
                        type="number"
                        min={100}
                        value={queueSettingsForm.warning_threshold}
                        onChange={e => setQueueSettingsForm(prev => ({ ...prev, warning_threshold: parseInt(e.target.value) || 10000 }))}
                      />
                      <p className="text-xs text-muted-foreground">Queue depth warning threshold</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="critical_threshold">Critical Threshold</Label>
                      <Input
                        id="critical_threshold"
                        type="number"
                        min={1000}
                        value={queueSettingsForm.critical_threshold}
                        onChange={e => setQueueSettingsForm(prev => ({ ...prev, critical_threshold: parseInt(e.target.value) || 50000 }))}
                      />
                      <p className="text-xs text-muted-foreground">Queue depth critical threshold (triggers backpressure)</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="backpressure_mode">Backpressure Mode</Label>
                      <Select
                        value={queueSettingsForm.backpressure_mode}
                        onValueChange={value => setQueueSettingsForm(prev => ({ ...prev, backpressure_mode: value as 'reject' | 'drop' }))}
                      >
                        <SelectTrigger id="backpressure_mode">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="reject">Reject (503 - shipper retries)</SelectItem>
                          <SelectItem value="drop">Drop (202 - oldest messages evicted)</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">Behavior when critical threshold exceeded</p>
                    </div>
                  </div>
                  <div className="pt-4 border-t">
                    <h4 className="font-medium mb-4">Worker Settings</h4>
                    <div className="grid gap-4 md:grid-cols-3">
                      <div className="space-y-2">
                        <Label htmlFor="batch_size">Batch Size</Label>
                        <Input
                          id="batch_size"
                          type="number"
                          min={10}
                          max={5000}
                          value={queueSettingsForm.batch_size}
                          onChange={e => setQueueSettingsForm(prev => ({ ...prev, batch_size: parseInt(e.target.value) || 500 }))}
                        />
                        <p className="text-xs text-muted-foreground">Logs per batch</p>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="batch_timeout">Batch Timeout (seconds)</Label>
                        <Input
                          id="batch_timeout"
                          type="number"
                          min={1}
                          max={60}
                          value={queueSettingsForm.batch_timeout_seconds}
                          onChange={e => setQueueSettingsForm(prev => ({ ...prev, batch_timeout_seconds: parseInt(e.target.value) || 5 }))}
                        />
                        <p className="text-xs text-muted-foreground">Max wait for batch to fill</p>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="message_ttl">Message TTL (seconds)</Label>
                        <Input
                          id="message_ttl"
                          type="number"
                          min={60}
                          value={queueSettingsForm.message_ttl_seconds}
                          onChange={e => setQueueSettingsForm(prev => ({ ...prev, message_ttl_seconds: parseInt(e.target.value) || 1800 }))}
                        />
                        <p className="text-xs text-muted-foreground">Message TTL before dead-letter ({Math.round(queueSettingsForm.message_ttl_seconds / 60)} min)</p>
                      </div>
                    </div>
                  </div>
                  <Button onClick={saveQueueSettings} disabled={isSavingQueueSettings}>
                    {isSavingQueueSettings ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Save Settings
                  </Button>
                  <p className="text-sm text-muted-foreground mt-4">
                    Queue statistics and dead letter management are available on the <a href="/health" className="text-primary underline">Health</a> page.
                  </p>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>

          {/* Pull Queue */}
          <Collapsible defaultOpen>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Pull Queue Configuration</CardTitle>
                      <CardDescription>Configure pull mode detection behavior including retry logic and health status thresholds</CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200 [&[data-state=open]]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="pull-max-retries">Max Retries</Label>
                      <Input
                        id="pull-max-retries"
                        type="number"
                        min="1"
                        max="10"
                        value={pullModeSettingsForm.max_retries}
                        onChange={(e) => setPullModeSettingsForm({...pullModeSettingsForm, max_retries: parseInt(e.target.value) || 3})}
                      />
                      <p className="text-xs text-muted-foreground">Retry attempts for failed polls (default: 3)</p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="pull-retry-delay">Retry Delay (seconds)</Label>
                      <Input
                        id="pull-retry-delay"
                        type="number"
                        min="1"
                        max="60"
                        value={pullModeSettingsForm.retry_delay_seconds}
                        onChange={(e) => setPullModeSettingsForm({...pullModeSettingsForm, retry_delay_seconds: parseInt(e.target.value) || 5})}
                      />
                      <p className="text-xs text-muted-foreground">Delay between retries (default: 5)</p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="pull-failures-warning">Failures Warning Threshold</Label>
                      <Input
                        id="pull-failures-warning"
                        type="number"
                        min="1"
                        max="50"
                        value={pullModeSettingsForm.consecutive_failures_warning}
                        onChange={(e) => setPullModeSettingsForm({...pullModeSettingsForm, consecutive_failures_warning: parseInt(e.target.value) || 3})}
                      />
                      <p className="text-xs text-muted-foreground">Consecutive failures before warning (default: 3)</p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="pull-failures-critical">Failures Critical Threshold</Label>
                      <Input
                        id="pull-failures-critical"
                        type="number"
                        min="1"
                        max="100"
                        value={pullModeSettingsForm.consecutive_failures_critical}
                        onChange={(e) => setPullModeSettingsForm({...pullModeSettingsForm, consecutive_failures_critical: parseInt(e.target.value) || 10})}
                      />
                      <p className="text-xs text-muted-foreground">Consecutive failures before critical (default: 10)</p>
                    </div>
                  </div>

                  <div className="flex justify-end pt-4 border-t">
                    <Button
                      onClick={savePullModeSettings}
                      disabled={isSavingPullModeSettings}
                    >
                      {isSavingPullModeSettings ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Saving...</> : <><Save className="h-4 w-4 mr-2" />Save Settings</>}
                    </Button>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        </div>
      )}

      {/* OpenSearch Section */}
      {activeTab === 'opensearch' && (
        <div className="space-y-4">
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

          <Card>
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
        </div>
      )}

      {/* Health Section */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Health Monitoring Thresholds</CardTitle>
              <CardDescription>
                Configure global health monitoring thresholds. These apply to all index patterns unless overridden.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Alerting Thresholds */}
              <div>
                <h4 className="text-sm font-medium mb-4">Alerting Thresholds</h4>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="no-data-minutes">No Data (minutes)</Label>
                    <Input
                      id="no-data-minutes"
                      type="number"
                      min="1"
                      value={healthSettingsForm.no_data_minutes}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, no_data_minutes: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="error-rate">Error Rate (%)</Label>
                    <Input
                      id="error-rate"
                      type="number"
                      min="0"
                      step="0.1"
                      value={healthSettingsForm.error_rate_percent}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, error_rate_percent: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="detection-latency-warning">Detection Latency Warning (seconds)</Label>
                    <Input
                      id="detection-latency-warning"
                      type="number"
                      min="1"
                      step="0.1"
                      value={healthSettingsForm.detection_latency_warning_ms}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, detection_latency_warning_ms: parseFloat(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Default: 2 seconds</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="detection-latency-critical">Detection Latency Critical (seconds)</Label>
                    <Input
                      id="detection-latency-critical"
                      type="number"
                      min="1"
                      step="0.1"
                      value={healthSettingsForm.detection_latency_critical_ms}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, detection_latency_critical_ms: parseFloat(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Default: 10 seconds</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="opensearch-latency-warning">OpenSearch Query Warning (seconds)</Label>
                    <Input
                      id="opensearch-latency-warning"
                      type="number"
                      min="1"
                      step="0.1"
                      value={healthSettingsForm.opensearch_latency_warning_ms}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, opensearch_latency_warning_ms: parseFloat(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Default: 1 second</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="opensearch-latency-critical">OpenSearch Query Critical (seconds)</Label>
                    <Input
                      id="opensearch-latency-critical"
                      type="number"
                      min="1"
                      step="0.1"
                      value={healthSettingsForm.opensearch_latency_critical_ms}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, opensearch_latency_critical_ms: parseFloat(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Default: 5 seconds</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="queue-warning">Queue Warning</Label>
                    <Input
                      id="queue-warning"
                      type="number"
                      min="1"
                      value={healthSettingsForm.queue_warning}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, queue_warning: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="queue-critical">Queue Critical</Label>
                    <Input
                      id="queue-critical"
                      type="number"
                      min="1"
                      value={healthSettingsForm.queue_critical}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, queue_critical: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="data-freshness-warning">Data Freshness Warning (minutes)</Label>
                    <Input
                      id="data-freshness-warning"
                      type="number"
                      min="1"
                      value={healthSettingsForm.data_freshness_warning_minutes}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, data_freshness_warning_minutes: parseInt(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Notify when index data is older than this (default: 60 minutes)</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="data-freshness-critical">Data Freshness Critical (minutes)</Label>
                    <Input
                      id="data-freshness-critical"
                      type="number"
                      min="1"
                      value={healthSettingsForm.data_freshness_critical_minutes}
                      onChange={(e) => setHealthSettingsForm({...healthSettingsForm, data_freshness_critical_minutes: parseInt(e.target.value) || 0})}
                    />
                    <p className="text-xs text-muted-foreground">Critical alert when index data is older than this (default: 240 minutes)</p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-4 border-t">
                <Button
                  onClick={saveHealthSettings}
                  disabled={isSavingHealthSettings}
                >
                  {isSavingHealthSettings ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="h-4 w-4 mr-2" />
                      Save Settings
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Health Check Intervals</CardTitle>
              <CardDescription>
                Configure how frequently the system checks health status of external services.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="jira-interval">Jira Cloud (seconds)</Label>
                  <Input
                    id="jira-interval"
                    type="number"
                    min="60"
                    max="3600"
                    value={healthCheckIntervalsForm.jira_interval_seconds}
                    onChange={(e) => setHealthCheckIntervalsForm({...healthCheckIntervalsForm, jira_interval_seconds: parseInt(e.target.value) || 0})}
                  />
                  <p className="text-xs text-muted-foreground">Default: 900 (15 minutes)</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="sigmahq-interval">SigmaHQ (seconds)</Label>
                  <Input
                    id="sigmahq-interval"
                    type="number"
                    min="60"
                    max="3600"
                    value={healthCheckIntervalsForm.sigmahq_interval_seconds}
                    onChange={(e) => setHealthCheckIntervalsForm({...healthCheckIntervalsForm, sigmahq_interval_seconds: parseInt(e.target.value) || 0})}
                  />
                  <p className="text-xs text-muted-foreground">Default: 3600 (1 hour)</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="attack-interval">MITRE ATT&CK (seconds)</Label>
                  <Input
                    id="attack-interval"
                    type="number"
                    min="60"
                    max="3600"
                    value={healthCheckIntervalsForm.mitre_attack_interval_seconds}
                    onChange={(e) => setHealthCheckIntervalsForm({...healthCheckIntervalsForm, mitre_attack_interval_seconds: parseInt(e.target.value) || 0})}
                  />
                  <p className="text-xs text-muted-foreground">Default: 3600 (1 hour)</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="opensearch-interval">OpenSearch (seconds)</Label>
                  <Input
                    id="opensearch-interval"
                    type="number"
                    min="30"
                    max="600"
                    value={healthCheckIntervalsForm.opensearch_interval_seconds}
                    onChange={(e) => setHealthCheckIntervalsForm({...healthCheckIntervalsForm, opensearch_interval_seconds: parseInt(e.target.value) || 0})}
                  />
                  <p className="text-xs text-muted-foreground">Default: 300 (5 minutes)</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="ti-interval">Threat Intelligence (seconds)</Label>
                  <Input
                    id="ti-interval"
                    type="number"
                    min="60"
                    max="3600"
                    value={healthCheckIntervalsForm.ti_interval_seconds}
                    onChange={(e) => setHealthCheckIntervalsForm({...healthCheckIntervalsForm, ti_interval_seconds: parseInt(e.target.value) || 0})}
                  />
                  <p className="text-xs text-muted-foreground">Default: 3600 (1 hour)</p>
                </div>
              </div>

              <div className="flex justify-end pt-4 border-t">
                <Button
                  onClick={async () => {
                    setIsSavingHealthCheckIntervals(true)
                    try {
                      await api.put('/health/intervals', healthCheckIntervalsForm)
                      setHealthCheckIntervals(healthCheckIntervalsForm)
                      showToast('Health check intervals saved successfully')
                    } catch (err) {
                      showToast(err instanceof Error ? err.message : 'Failed to save health check intervals', 'error')
                    } finally {
                      setIsSavingHealthCheckIntervals(false)
                    }
                  }}
                  disabled={isSavingHealthCheckIntervals}
                >
                  {isSavingHealthCheckIntervals ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Saving...</> : <><Save className="h-4 w-4 mr-2" />Save Settings</>}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* General Section - background-sync content */}
      {activeTab === 'general' && (
        <div className="space-y-4">
          <Collapsible defaultOpen>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>SigmaHQ Auto-Sync</CardTitle>
                      <CardDescription>
                        Configure automatic synchronization of the SigmaHQ rules repository
                      </CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
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
                <Label htmlFor="sigmahq-sync-interval">Sync Interval</Label>
                <Select
                  value={sigmahqSyncInterval.toString()}
                  onValueChange={(v) => setSigmahqSyncInterval(parseInt(v))}
                  disabled={!sigmahqSyncEnabled}
                >
                  <SelectTrigger id="sigmahq-sync-interval" className="w-48">
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

              <p className="text-sm text-muted-foreground">
                You can also manually sync at any time from the SigmaHQ browser page.
              </p>

              <div className="flex justify-end pt-4 border-t">
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
          </CollapsibleContent>
            </Card>
          </Collapsible>

          <Collapsible>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>MITRE ATT&CK Auto-Sync</CardTitle>
                      <CardDescription>
                        Configure automatic synchronization of the MITRE ATT&CK Enterprise framework
                      </CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Auto-Sync</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically sync ATT&CK techniques on a schedule
                  </p>
                </div>
                <Switch
                  checked={attackSyncEnabled}
                  onCheckedChange={setAttackSyncEnabled}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="attack-sync-interval">Sync Interval</Label>
                <Select
                  value={attackSyncInterval.toString()}
                  onValueChange={(v) => setAttackSyncInterval(parseInt(v))}
                  disabled={!attackSyncEnabled}
                >
                  <SelectTrigger id="attack-sync-interval" className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    <SelectItem value="24">Daily</SelectItem>
                    <SelectItem value="168">Weekly</SelectItem>
                    <SelectItem value="336">Every 2 weeks</SelectItem>
                    <SelectItem value="720">Monthly</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  How often to check for ATT&CK framework updates (weekly recommended)
                </p>
              </div>

              {attackLastSync && (
                <div className="text-sm text-muted-foreground">
                  Last synced: {new Date(attackLastSync).toLocaleString()}
                </div>
              )}

              <p className="text-sm text-muted-foreground">
                You can also manually sync from the ATT&CK Matrix page.
              </p>

              <div className="flex justify-end pt-4 border-t">
                <Button onClick={saveAttackSync} disabled={isSaving}>
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
              </CollapsibleContent>
            </Card>
          </Collapsible>

          <Collapsible>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Version Cleanup</CardTitle>
                      <CardDescription>
                        Automatically clean up old rule versions. Runs daily at 3:00 AM.
                      </CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Enable Version Cleanup</Label>
                      <p className="text-sm text-muted-foreground">
                        Automatically delete old versions beyond the retention policy
                      </p>
                    </div>
                    <Switch
                      checked={versionCleanupEnabled}
                      onCheckedChange={setVersionCleanupEnabled}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="version-cleanup-min-keep">Minimum Versions to Keep</Label>
                    <Input
                      id="version-cleanup-min-keep"
                      type="number"
                      min={1}
                      max={100}
                      className="w-32"
                      value={versionCleanupMinKeep}
                      onChange={(e) => setVersionCleanupMinKeep(parseInt(e.target.value) || 10)}
                      disabled={!versionCleanupEnabled}
                    />
                    <p className="text-xs text-muted-foreground">
                      Always keep at least this many versions per rule, regardless of age
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="version-cleanup-max-age">Maximum Age (days)</Label>
                    <Input
                      id="version-cleanup-max-age"
                      type="number"
                      min={1}
                      max={365}
                      className="w-32"
                      value={versionCleanupMaxAgeDays}
                      onChange={(e) => setVersionCleanupMaxAgeDays(parseInt(e.target.value) || 90)}
                      disabled={!versionCleanupEnabled}
                    />
                    <p className="text-xs text-muted-foreground">
                      Delete versions older than this (if more than minimum kept)
                    </p>
                  </div>

                  <div className="flex justify-end pt-4 border-t">
                    <Button onClick={saveVersionCleanup} disabled={isSavingVersionCleanup}>
                      {isSavingVersionCleanup ? (
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
              </CollapsibleContent>
            </Card>
          </Collapsible>

          <Collapsible>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>System Log Retention</CardTitle>
                      <CardDescription>
                        Configure how long system logs are kept before automatic cleanup
                      </CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
                  <div className="flex items-center gap-4">
                    <Label htmlFor="system-log-retention">Keep logs for</Label>
                    <Select
                      value={systemLogRetention.toString()}
                      onValueChange={(v) => setSystemLogRetention(parseInt(v))}
                    >
                      <SelectTrigger id="system-log-retention" className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="7">7 days</SelectItem>
                        <SelectItem value="14">14 days</SelectItem>
                        <SelectItem value="30">30 days</SelectItem>
                        <SelectItem value="60">60 days</SelectItem>
                        <SelectItem value="90">90 days</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Logs older than this will be automatically purged daily at 3 AM.
                  </p>

                  <div className="flex justify-end pt-4 border-t">
                    <Button onClick={saveSystemLogRetention} disabled={isSavingSystemLogRetention}>
                      {isSavingSystemLogRetention ? (
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
              </CollapsibleContent>
            </Card>
          </Collapsible>

          {/* Alert Clustering */}
          <Collapsible>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Alert Clustering</CardTitle>
                      <CardDescription>Group alerts from the same detection rule to reduce noise</CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Alert Clustering</Label>
                  <p className="text-sm text-muted-foreground">
                    Group alerts from the same rule together
                  </p>
                </div>
                <Switch
                  checked={alertClusteringForm.enabled}
                  onCheckedChange={(checked) =>
                    setAlertClusteringForm({ ...alertClusteringForm, enabled: checked })
                  }
                />
              </div>

              {alertClusteringForm.enabled && (
                <div className="space-y-4 pl-4 border-l-2 border-muted">
                  <div className="space-y-2">
                    <Label htmlFor="cluster-window">Time Window (minutes)</Label>
                    <Input
                      id="cluster-window"
                      type="number"
                      min={1}
                      max={1440}
                      className="w-32"
                      value={alertClusteringForm.window_minutes}
                      onChange={(e) =>
                        setAlertClusteringForm({
                          ...alertClusteringForm,
                          window_minutes: parseInt(e.target.value) || 60,
                        })
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      Alerts from the same rule within this time window will be grouped (1-1440 minutes)
                    </p>
                  </div>

                  <div className="p-3 bg-muted rounded-md">
                    <p className="text-sm">
                      <strong>How it works:</strong> Alerts from the same detection rule within the time window
                      are grouped together. The cluster shows a representative alert with a count badge.
                      Click to expand and see all alerts in the cluster.
                    </p>
                  </div>
                </div>
              )}

                  <div className="flex justify-end pt-4 border-t">
                    <Button
                      onClick={saveAlertClusteringSettings}
                      disabled={isSavingAlertClustering}
                    >
                      {isSavingAlertClustering ? (
                        <>
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="h-4 w-4 mr-2" />
                          Save Settings
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>

          {/* Rule Deployment */}
          <Collapsible>
            <Card>
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Rule Deployment</CardTitle>
                      <CardDescription>Configure rule deployment safety checks</CardDescription>
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform duration-200 [[data-state=open]>&]:rotate-180" />
                  </div>
                </CardHeader>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="deployment-threshold">Alert Threshold</Label>
                    <p className="text-sm text-muted-foreground">
                      When deploying a rule, warn if a dry-run against the last 24 hours matches more than this number of logs.
                    </p>
                    <div className="flex items-center gap-2">
                      <Input
                        id="deployment-threshold"
                        type="number"
                        min={1}
                        max={100000}
                        value={deploymentThreshold}
                        onChange={(e) => setDeploymentThreshold(Number(e.target.value))}
                        className="w-32"
                      />
                      <Button
                        size="sm"
                        onClick={async () => {
                          try {
                            await settingsApi.updateRuleSettings({ deployment_alert_threshold: deploymentThreshold })
                            showToast('Deployment threshold saved')
                          } catch {
                            showToast('Failed to save threshold', 'error')
                          }
                        }}
                      >
                        <Save className="h-4 w-4 mr-1" />
                        Save
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        </div>
      )}

      {/* Backup Section - export content */}
      {activeTab === 'backup' && (
        <div className="space-y-4">
          {/* Export Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download className="h-5 w-5" />
                Export Configuration
              </CardTitle>
              <CardDescription>
                Download a complete backup of your CHAD configuration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                The configuration backup includes: index patterns, field mappings, rules with exceptions,
                correlation rules, webhooks, notification settings, TI sources, and users (roles only).
                Sensitive data like passwords, API keys, and OpenSearch credentials are excluded for security.
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={async () => {
                    try {
                      await downloadWithAuth('/api/export/config', `chad-config-${new Date().toISOString().slice(0, 10)}.json`)
                      showToast('Configuration exported successfully', 'success')
                    } catch (err) {
                      showToast(err instanceof Error ? err.message : 'Export failed', 'error')
                    }
                  }}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export Configuration (JSON)
                </Button>
                <Button
                  variant="outline"
                  onClick={async () => {
                    try {
                      await downloadWithAuth('/api/export/rules', `chad-rules-${new Date().toISOString().slice(0, 10)}.zip`)
                      showToast('Rules exported successfully', 'success')
                    } catch (err) {
                      showToast(err instanceof Error ? err.message : 'Export failed', 'error')
                    }
                  }}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export Rules Only (ZIP)
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Import Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                Import Configuration
              </CardTitle>
              <CardDescription>
                Restore configuration from a backup file
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Upload a previously exported configuration file to restore settings.
                You can preview changes before applying them.
              </p>

              {/* File Upload */}
              <div className="space-y-2">
                <Label htmlFor="import-file">Configuration File</Label>
                <div
                  className="relative border-2 border-dashed border-muted-foreground/25 rounded-lg p-6 hover:border-muted-foreground/50 transition-colors cursor-pointer"
                  onClick={() => document.getElementById('import-file')?.click()}
                >
                  <input
                    id="import-file"
                    type="file"
                    accept=".json"
                    className="sr-only"
                    onChange={(e) => {
                      setImportFile(e.target.files?.[0] || null)
                      setImportPreview(null)
                      setImportResult(null)
                    }}
                  />
                  <div className="flex flex-col items-center gap-2 text-center">
                    <Upload className="h-8 w-8 text-muted-foreground" />
                    {importFile ? (
                      <div>
                        <p className="font-medium">{importFile.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {(importFile.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    ) : (
                      <div>
                        <p className="font-medium">Click to select a configuration file</p>
                        <p className="text-sm text-muted-foreground">
                          JSON files exported from CHAD
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Import Mode Selection */}
              <div className="space-y-2">
                <Label>Conflict Resolution</Label>
                <Select
                  value={importMode}
                  onValueChange={(value) => setImportMode(value as ImportMode)}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="skip">
                      Skip existing items
                    </SelectItem>
                    <SelectItem value="overwrite">
                      Overwrite existing items
                    </SelectItem>
                    <SelectItem value="rename">
                      Rename duplicates (add suffix)
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {importMode === 'skip' && 'Existing items will be kept unchanged. Only new items will be imported.'}
                  {importMode === 'overwrite' && 'Existing items will be updated with values from the backup file.'}
                  {importMode === 'rename' && 'Duplicate items will be created with "_imported" suffix.'}
                </p>
              </div>

              {/* Import Buttons */}
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  disabled={!importFile || isImporting}
                  onClick={async () => {
                    if (!importFile) return
                    setIsImporting(true)
                    try {
                      const result = await configApi.importConfig(importFile, importMode, true)
                      setImportPreview(result)
                      setImportResult(null)
                    } catch (err) {
                      showToast(err instanceof Error ? err.message : 'Preview failed', 'error')
                    } finally {
                      setIsImporting(false)
                    }
                  }}
                >
                  {isImporting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                  Preview Changes
                </Button>
                <Button
                  disabled={!importFile || isImporting}
                  onClick={async () => {
                    if (!importFile) return
                    setIsImporting(true)
                    try {
                      const result = await configApi.importConfig(importFile, importMode, false)
                      setImportResult(result)
                      setImportPreview(null)
                      showToast('Configuration imported successfully', 'success')
                    } catch (err) {
                      showToast(err instanceof Error ? err.message : 'Import failed', 'error')
                    } finally {
                      setIsImporting(false)
                    }
                  }}
                >
                  {isImporting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Upload className="h-4 w-4 mr-2" />}
                  Import Configuration
                </Button>
              </div>

              {/* Preview Results */}
              {importPreview && (
                <div className="mt-4 p-4 border rounded-lg bg-muted/50">
                  <h4 className="font-medium mb-2">Preview (Dry Run)</h4>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">Will Create</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importPreview.created).map(([key, value]) => (
                          value > 0 && <li key={key} className="text-green-600">{key}: {value}</li>
                        ))}
                        {Object.values(importPreview.created).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Will Update</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importPreview.updated).map(([key, value]) => (
                          value > 0 && <li key={key} className="text-blue-600">{key}: {value}</li>
                        ))}
                        {Object.values(importPreview.updated).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Will Skip</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importPreview.skipped).map(([key, value]) => (
                          value > 0 && <li key={key} className="text-yellow-600">{key}: {value}</li>
                        ))}
                        {Object.values(importPreview.skipped).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                  </div>
                  {importPreview.errors.length > 0 && (
                    <div className="mt-4">
                      <p className="text-destructive font-medium">Errors:</p>
                      <ul className="mt-1 text-sm text-destructive">
                        {importPreview.errors.map((error, i) => <li key={i}>{error}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Import Results */}
              {importResult && (
                <div className="mt-4 p-4 border rounded-lg bg-green-50 dark:bg-green-950">
                  <h4 className="font-medium mb-2 text-green-800 dark:text-green-200">
                    <CheckCircle2 className="h-4 w-4 inline mr-2" />
                    Import Complete
                  </h4>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">Created</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importResult.created).map(([key, value]) => (
                          value > 0 && <li key={key}>{key}: {value}</li>
                        ))}
                        {Object.values(importResult.created).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Updated</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importResult.updated).map(([key, value]) => (
                          value > 0 && <li key={key}>{key}: {value}</li>
                        ))}
                        {Object.values(importResult.updated).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Skipped</p>
                      <ul className="mt-1 space-y-1">
                        {Object.entries(importResult.skipped).map(([key, value]) => (
                          value > 0 && <li key={key}>{key}: {value}</li>
                        ))}
                        {Object.values(importResult.skipped).every(v => v === 0) && <li className="text-muted-foreground">None</li>}
                      </ul>
                    </div>
                  </div>
                  {importResult.errors.length > 0 && (
                    <div className="mt-4">
                      <p className="text-destructive font-medium">Errors:</p>
                      <ul className="mt-1 text-sm text-destructive">
                        {importResult.errors.map((error, i) => <li key={i}>{error}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
