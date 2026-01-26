import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { settingsApiExtended, settingsApi, statsApi, permissionsApi, OpenSearchStatusResponse, AIProvider, AISettings, AISettingsUpdate, AITestResponse } from '@/lib/api'
import Notifications from '@/pages/Notifications'
import GeoIPSettings from '@/pages/GeoIPSettings'
import TISettings from '@/pages/TISettings'
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
import { CheckCircle2, ChevronDown, ExternalLink, Loader2, RefreshCw, Save, Users, FileText, XCircle } from 'lucide-react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { useVersion } from '@/hooks/use-version'
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
  const { version, updateAvailable, latestVersion, releaseUrl, loading: versionLoading, checkForUpdates } = useVersion()
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

  // Active tab for programmatic navigation - read from URL param if present
  const [activeTab, setActiveTab] = useState(() => {
    const tabParam = searchParams.get('tab')
    return tabParam || 'notifications'
  })

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
  const [aiOpenAIKeyConfigured, setAiOpenAIKeyConfigured] = useState(false)
  const [aiAnthropicKeyConfigured, setAiAnthropicKeyConfigured] = useState(false)
  const [aiTestLoading, setAiTestLoading] = useState(false)
  const [aiTestResult, setAiTestResult] = useState<AITestResponse | null>(null)
  const [aiLastTested, setAiLastTested] = useState<string | null>(null)
  const [aiLastTestSuccess, setAiLastTestSuccess] = useState<boolean | null>(null)

  useEffect(() => {
    loadSettings()
    loadOpenSearchStatus()
    loadPermissions()
    loadSecuritySettings()
  }, [])

  const loadSecuritySettings = async () => {
    try {
      const security = await settingsApi.getSecuritySettings()
      setForce2FAOnSignup(security.force_2fa_on_signup)
    } catch (error) {
      console.error('Failed to load security settings:', error)
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

  const save2FASettings = async () => {
    setIsSaving(true)
    try {
      await settingsApi.updateSecuritySettings({ force_2fa_on_signup: force2FAOnSignup })
      showToast('MFA settings saved')
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
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="sso">SSO</TabsTrigger>
          <TabsTrigger value="ai">AI</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
          <TabsTrigger value="opensearch">OpenSearch</TabsTrigger>
          <TabsTrigger value="background-sync">Background Sync</TabsTrigger>
          <TabsTrigger value="export">Export</TabsTrigger>
          <TabsTrigger value="about" className="flex items-center gap-1">
            About
            {updateAvailable && <span className="h-2 w-2 rounded-full bg-red-500" />}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="notifications" className="mt-4">
          <Notifications />
        </TabsContent>

        <TabsContent value="security" className="mt-4 space-y-6" data-form-type="other" data-lpignore="true" data-1p-ignore="true" data-protonpass-ignore="true">
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
                  autoComplete="off"
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
                      autoComplete="off"
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

          <Card data-lpignore="true" data-1p-ignore="true" data-protonpass-ignore="true">
            <CardHeader>
              <CardTitle>Multi-Factor Policy</CardTitle>
              <CardDescription>
                Configure organization-wide MFA requirements
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
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
              <Button onClick={save2FASettings} disabled={isSaving}>
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
              <div className="space-y-4">
                {['analyst', 'viewer'].map((role) => {
                  const enabledCount = Object.keys(permissionDescriptions).filter(
                    (perm) => permissions[role]?.[perm] ?? false
                  ).length
                  const totalCount = Object.keys(permissionDescriptions).length
                  return (
                    <Collapsible key={role} defaultOpen={false} className="border rounded-lg">
                      <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors [&[data-state=open]>svg]:rotate-180">
                        <div className="flex items-center gap-3">
                          <h3 className="font-medium capitalize text-lg">{role}</h3>
                          <span className="text-sm text-muted-foreground">
                            {enabledCount} of {totalCount} permissions enabled
                          </span>
                        </div>
                        <ChevronDown className="h-4 w-4 transition-transform duration-200" />
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <div className="grid gap-3 p-4 pt-0 border-t">
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
                      </CollapsibleContent>
                    </Collapsible>
                  )
                })}
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
        </TabsContent>

        <TabsContent value="integrations" className="mt-4">
          <div className="space-y-6">
            <GeoIPSettings />
            <TISettings />
          </div>
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

        <TabsContent value="background-sync" className="mt-4 space-y-6">
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

          <Card>
            <CardHeader>
              <CardTitle>MITRE ATT&CK Auto-Sync</CardTitle>
              <CardDescription>
                Configure automatic synchronization of the MITRE ATT&CK Enterprise framework.
                When enabled, CHAD will periodically update technique data from the ATT&CK STIX repository.
              </CardDescription>
            </CardHeader>
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

              <div className="pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-4">
                  You can also manually sync from the ATT&CK Matrix page.
                </p>
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

        <TabsContent value="about" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>About CHAD</CardTitle>
              <CardDescription>
                Cyber Hunting And Detection - A Sigma rule management and alerting platform
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Version Info */}
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="space-y-1">
                    <p className="text-sm font-medium">Current Version</p>
                    <p className="text-2xl font-bold">
                      {versionLoading ? (
                        <Loader2 className="h-6 w-6 animate-spin" />
                      ) : (
                        `v${version || 'Unknown'}`
                      )}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    onClick={checkForUpdates}
                    disabled={versionLoading}
                  >
                    {versionLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <RefreshCw className="h-4 w-4 mr-2" />
                    )}
                    Check for Updates
                  </Button>
                </div>

                {/* Update Available Banner */}
                {updateAvailable && latestVersion && (
                  <div className="p-4 border rounded-lg bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <p className="font-medium text-green-800 dark:text-green-200">
                          Update Available
                        </p>
                        <p className="text-sm text-green-700 dark:text-green-300">
                          Version {latestVersion} is now available. You are running {version}.
                        </p>
                      </div>
                      {releaseUrl && (
                        <Button variant="default" asChild>
                          <a href={releaseUrl} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-4 w-4 mr-2" />
                            View Release
                          </a>
                        </Button>
                      )}
                    </div>
                  </div>
                )}

                {/* No Update Available */}
                {!updateAvailable && !versionLoading && version && (
                  <div className="p-4 border rounded-lg bg-muted/50">
                    <p className="text-sm text-muted-foreground">
                      You are running the latest version of CHAD.
                    </p>
                  </div>
                )}
              </div>

              {/* Links */}
              <div className="space-y-2 pt-4 border-t">
                <h3 className="font-medium">Resources</h3>
                <div className="grid gap-2">
                  <a
                    href="https://github.com/TerrifiedBug/chad"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <ExternalLink className="h-4 w-4" />
                    GitHub Repository
                  </a>
                  <a
                    href="https://github.com/TerrifiedBug/chad/releases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <ExternalLink className="h-4 w-4" />
                    Release Notes / Changelog
                  </a>
                  <a
                    href="https://github.com/TerrifiedBug/chad/issues"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <ExternalLink className="h-4 w-4" />
                    Report an Issue
                  </a>
                </div>
              </div>

              {/* Credits */}
              <div className="space-y-2 pt-4 border-t">
                <h3 className="font-medium">Built With</h3>
                <p className="text-sm text-muted-foreground">
                  CHAD uses pySigma for Sigma rule processing and OpenSearch for detection and alerting.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
