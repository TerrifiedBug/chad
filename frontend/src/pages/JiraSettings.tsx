import { useEffect, useState, useCallback } from 'react'
import {
  jiraApi,
  JiraConfig,
  JiraProject,
  JiraIssueType,
  JiraConfigUpdate,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { Check, Loader2, Trash2, XCircle } from 'lucide-react'

// Available severity levels
const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' },
]

export default function JiraSettings() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)

  // Config state
  const [configured, setConfigured] = useState(false)
  const [config, setConfig] = useState<JiraConfig | null>(null)

  // Form state
  const [jiraUrl, setJiraUrl] = useState('')
  const [email, setEmail] = useState('')
  const [apiToken, setApiToken] = useState('')
  const [defaultProject, setDefaultProject] = useState('')
  const [defaultIssueType, setDefaultIssueType] = useState('')
  const [isEnabled, setIsEnabled] = useState(true)
  const [alertSeverities, setAlertSeverities] = useState<string[]>([])

  // Projects and issue types
  const [projects, setProjects] = useState<JiraProject[]>([])
  const [issueTypes, setIssueTypes] = useState<JiraIssueType[]>([])
  const [loadingProjects, setLoadingProjects] = useState(false)
  const [loadingIssueTypes, setLoadingIssueTypes] = useState(false)

  // Test result
  const [testResult, setTestResult] = useState<{
    success: boolean
    error?: string | null
    server_title?: string | null
  } | null>(null)

  // Load functions - must be declared before useEffect that uses them
  const loadProjects = useCallback(async () => {
    setLoadingProjects(true)
    try {
      const projectList = await jiraApi.getProjects()
      setProjects(projectList)
    } catch {
      console.log('Failed to load Jira projects')
    } finally {
      setLoadingProjects(false)
    }
  }, [])

  const loadConfig = useCallback(async () => {
    setIsLoading(true)
    try {
      const status = await jiraApi.getConfig()
      setConfigured(status.configured)
      if (status.config) {
        setConfig(status.config)
        setJiraUrl(status.config.jira_url)
        setEmail(status.config.email)
        setDefaultProject(status.config.default_project)
        setDefaultIssueType(status.config.default_issue_type)
        setIsEnabled(status.config.is_enabled)
        setAlertSeverities(status.config.alert_severities || [])

        // Load projects if configured
        loadProjects()
      }
    } catch {
      console.log('Failed to load Jira config')
    } finally {
      setIsLoading(false)
    }
  }, [loadProjects])

  const loadIssueTypes = useCallback(async (projectKey: string) => {
    setLoadingIssueTypes(true)
    try {
      const types = await jiraApi.getIssueTypes(projectKey)
      setIssueTypes(types)
    } catch {
      console.log('Failed to load issue types')
    } finally {
      setLoadingIssueTypes(false)
    }
  }, [])

  useEffect(() => {
    loadConfig()
  }, [loadConfig])

  // Load issue types when project changes
  useEffect(() => {
    if (defaultProject && configured) {
      loadIssueTypes(defaultProject)
    }
  }, [defaultProject, configured, loadIssueTypes])

  const handleTestConnection = async () => {
    if (!jiraUrl || !email || !apiToken) {
      showToast('Please fill in all connection fields', 'error')
      return
    }

    setIsTesting(true)
    setTestResult(null)
    try {
      const result = await jiraApi.testConnection({
        jira_url: jiraUrl,
        email,
        api_token: apiToken,
      })
      setTestResult(result)
      if (result.success) {
        showToast(`Connected to ${result.server_title || 'Jira Cloud'}`)
      } else {
        showToast(result.error || 'Connection failed', 'error')
      }
    } catch (err) {
      setTestResult({
        success: false,
        error: err instanceof Error ? err.message : 'Connection test failed',
      })
      showToast(err instanceof Error ? err.message : 'Connection test failed', 'error')
    } finally {
      setIsTesting(false)
    }
  }

  const handleTestSavedConnection = async () => {
    setIsTesting(true)
    setTestResult(null)
    try {
      const result = await jiraApi.testSavedConnection()
      setTestResult(result)
      if (result.success) {
        showToast('Connection successful')
      } else {
        showToast(result.error || 'Connection failed', 'error')
      }
    } catch (err) {
      setTestResult({
        success: false,
        error: err instanceof Error ? err.message : 'Connection test failed',
      })
      showToast(err instanceof Error ? err.message : 'Connection test failed', 'error')
    } finally {
      setIsTesting(false)
    }
  }

  const handleSave = async () => {
    if (!jiraUrl || !email || !defaultProject || !defaultIssueType) {
      showToast('Please fill in all required fields', 'error')
      return
    }

    // API token is required for new configurations
    if (!configured && !apiToken) {
      showToast('API token is required for initial configuration', 'error')
      return
    }

    setIsSaving(true)
    try {
      const data: JiraConfigUpdate = {
        jira_url: jiraUrl,
        email,
        default_project: defaultProject,
        default_issue_type: defaultIssueType,
        is_enabled: isEnabled,
        alert_severities: alertSeverities,
      }

      // Only include API token if provided
      if (apiToken) {
        data.api_token = apiToken
      }

      await jiraApi.updateConfig(data)
      setApiToken('') // Clear the token field after save
      showToast('Jira configuration saved')
      loadConfig() // Reload to get updated state
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    setIsDeleting(true)
    try {
      await jiraApi.deleteConfig()
      // Reset all state
      setConfigured(false)
      setConfig(null)
      setJiraUrl('')
      setEmail('')
      setApiToken('')
      setDefaultProject('')
      setDefaultIssueType('')
      setIsEnabled(true)
      setAlertSeverities([])
      setProjects([])
      setIssueTypes([])
      setTestResult(null)
      showToast('Jira configuration deleted')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    } finally {
      setIsDeleting(false)
    }
  }

  const handleSeverityChange = (severity: string, checked: boolean) => {
    if (checked) {
      setAlertSeverities([...alertSeverities, severity])
    } else {
      setAlertSeverities(alertSeverities.filter((s) => s !== severity))
    }
  }

  const handleProjectChange = (projectKey: string) => {
    setDefaultProject(projectKey)
    setDefaultIssueType('') // Reset issue type when project changes
    if (projectKey) {
      loadIssueTypes(projectKey)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.005 1.005 0 0 0 23.013 0z" />
            </svg>
            Jira Cloud Integration
          </CardTitle>
          <CardDescription>
            Automatically create Jira tickets when alerts are triggered based on severity levels.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Enable/Disable Toggle */}
          {configured && (
            <div className="flex items-center justify-between pb-4 border-b">
              <div>
                <Label>Enable Jira Integration</Label>
                <p className="text-sm text-muted-foreground">
                  When enabled, alerts matching configured severities will create Jira tickets
                </p>
              </div>
              <Switch checked={isEnabled} onCheckedChange={setIsEnabled} />
            </div>
          )}

          {/* Connection Settings */}
          <div className="space-y-4">
            <h4 className="font-medium">Connection Settings</h4>

            <div className="space-y-2">
              <Label htmlFor="jira-url">Jira Cloud URL</Label>
              <Input
                id="jira-url"
                value={jiraUrl}
                onChange={(e) => setJiraUrl(e.target.value)}
                placeholder="https://your-domain.atlassian.net"
              />
              <p className="text-xs text-muted-foreground">
                Your Atlassian Cloud URL (e.g., https://company.atlassian.net)
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="jira-email">Email</Label>
              <Input
                id="jira-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@company.com"
              />
              <p className="text-xs text-muted-foreground">
                Email address associated with your Atlassian account
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="jira-token">API Token</Label>
              <Input
                id="jira-token"
                type="password"
                value={apiToken}
                onChange={(e) => setApiToken(e.target.value)}
                placeholder={config?.has_api_token ? '********' : 'Enter API token'}
              />
              <p className="text-xs text-muted-foreground">
                {config?.has_api_token
                  ? 'Leave blank to keep existing token'
                  : 'Generate an API token from '}
                {!config?.has_api_token && (
                  <a
                    href="https://id.atlassian.com/manage-profile/security/api-tokens"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline hover:text-foreground"
                  >
                    Atlassian Account Settings
                  </a>
                )}
              </p>
            </div>

            {/* Test Connection */}
            <div className="flex items-center gap-4">
              {configured && config?.has_api_token ? (
                <Button
                  variant="outline"
                  onClick={handleTestSavedConnection}
                  disabled={isTesting}
                >
                  {isTesting ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  Test Saved Connection
                </Button>
              ) : null}
              {apiToken && (
                <Button
                  variant="outline"
                  onClick={handleTestConnection}
                  disabled={isTesting || !jiraUrl || !email || !apiToken}
                >
                  {isTesting ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  Test Connection
                </Button>
              )}
              {testResult && (
                <span
                  className={`flex items-center text-sm ${
                    testResult.success ? 'text-green-600' : 'text-red-600'
                  }`}
                >
                  {testResult.success ? (
                    <>
                      <Check className="h-4 w-4 mr-1" />
                      Connected{testResult.server_title ? ` to ${testResult.server_title}` : ''}
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 mr-1" />
                      {testResult.error || 'Connection failed'}
                    </>
                  )}
                </span>
              )}
            </div>
          </div>

          {/* Project and Issue Type Selection */}
          {configured && (
            <div className="space-y-4 pt-4 border-t">
              <h4 className="font-medium">Default Ticket Settings</h4>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Default Project</Label>
                  <Select
                    value={defaultProject}
                    onValueChange={handleProjectChange}
                    disabled={loadingProjects}
                  >
                    <SelectTrigger>
                      {loadingProjects ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <SelectValue placeholder="Select project" />
                      )}
                    </SelectTrigger>
                    <SelectContent className="z-50 bg-popover">
                      {projects.map((project) => (
                        <SelectItem key={project.key} value={project.key}>
                          {project.key} - {project.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Project where tickets will be created
                  </p>
                </div>

                <div className="space-y-2">
                  <Label>Default Issue Type</Label>
                  <Select
                    value={defaultIssueType}
                    onValueChange={setDefaultIssueType}
                    disabled={loadingIssueTypes || !defaultProject}
                  >
                    <SelectTrigger>
                      {loadingIssueTypes ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <SelectValue placeholder="Select issue type" />
                      )}
                    </SelectTrigger>
                    <SelectContent className="z-50 bg-popover">
                      {issueTypes.map((type) => (
                        <SelectItem key={type.id} value={type.name}>
                          {type.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Type of issue to create (e.g., Bug, Task)
                  </p>
                </div>
              </div>

              {projects.length === 0 && !loadingProjects && (
                <Button variant="outline" onClick={loadProjects} size="sm">
                  <Loader2
                    className={`h-4 w-4 mr-2 ${loadingProjects ? 'animate-spin' : ''}`}
                  />
                  Load Projects
                </Button>
              )}
            </div>
          )}

          {/* Alert Severity Selection */}
          <div className="space-y-4 pt-4 border-t">
            <div>
              <h4 className="font-medium">Alert Severity Filtering</h4>
              <p className="text-sm text-muted-foreground">
                Select which alert severity levels should automatically create Jira tickets
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {SEVERITY_OPTIONS.map((severity) => (
                <div key={severity.value} className="flex items-center space-x-2">
                  <Checkbox
                    id={`severity-${severity.value}`}
                    checked={alertSeverities.includes(severity.value)}
                    onCheckedChange={(checked) =>
                      handleSeverityChange(severity.value, checked as boolean)
                    }
                  />
                  <Label
                    htmlFor={`severity-${severity.value}`}
                    className="text-sm font-normal cursor-pointer"
                  >
                    {severity.label}
                  </Label>
                </div>
              ))}
            </div>

            {alertSeverities.length === 0 && (
              <p className="text-sm text-yellow-600 dark:text-yellow-400">
                No severities selected. Jira tickets will not be created for any alerts.
              </p>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between pt-4 border-t">
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {configured ? 'Save Changes' : 'Save Configuration'}
            </Button>

            {configured && (
              <Button
                variant="destructive"
                disabled={isDeleting}
                onClick={() => setDeleteModalOpen(true)}
              >
                {isDeleting ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Trash2 className="h-4 w-4 mr-2" />
                )}
                Delete Configuration
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Delete Confirmation Modal */}
      <DeleteConfirmModal
        open={deleteModalOpen}
        onOpenChange={setDeleteModalOpen}
        title="Delete Jira Configuration"
        description="This will remove the Jira integration and stop automatic ticket creation for alerts. This action cannot be undone."
        itemName="Jira Cloud Integration"
        onConfirm={handleDelete}
        isDeleting={isDeleting}
      />
    </div>
  )
}
