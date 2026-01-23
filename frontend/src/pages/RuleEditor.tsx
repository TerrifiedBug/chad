import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  rulesApi,
  indexPatternsApi,
  IndexPattern,
  ValidationError,
  LogMatchResult,
  RuleException,
  ExceptionOperator,
  RuleExceptionCreate,
  DeploymentUnmappedFieldsError,
} from '@/lib/api'
import { YamlEditor } from '@/components/YamlEditor'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import yaml from 'js-yaml'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ArrowLeft, Check, X, Play, AlertCircle, Rocket, RotateCcw, Loader2, Trash2, Plus, Clock, History, Download, AlignLeft, FileCode, FileText, Link2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { ActivityPanel } from '@/components/ActivityPanel'

const DEFAULT_RULE = `title: My Detection Rule
status: experimental
description: |
  Describe what this rule detects
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine|contains: 'suspicious'
  condition: selection
level: medium
`

export default function RuleEditorPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const isNew = !id || id === 'new'

  // Form state
  const [title, setTitle] = useState('')
  const [yamlContent, setYamlContent] = useState(DEFAULT_RULE)
  const [severity, setSeverity] = useState('medium')
  const [indexPatternId, setIndexPatternId] = useState('')
  const [description, setDescription] = useState('')
  const [status, setStatus] = useState<'deployed' | 'undeployed' | 'snoozed'>('undeployed')
  const [snoozeIndefinite, setSnoozeIndefinite] = useState(false)

  // UI state
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(!isNew)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState('')

  // Validation state
  const [validationErrors, setValidationErrors] = useState<ValidationError[]>([])
  const [isValidating, setIsValidating] = useState(false)
  const [isValid, setIsValid] = useState<boolean | null>(null)
  const [generatedQuery, setGeneratedQuery] = useState<Record<string, unknown> | null>(null)
  const [detectedFields, setDetectedFields] = useState<string[]>([])

  // Test state
  const [sampleLog, setSampleLog] = useState('{\n  "CommandLine": "cmd.exe /c whoami"\n}')
  const [isTesting, setIsTesting] = useState(false)
  const [testResults, setTestResults] = useState<LogMatchResult[] | null>(null)

  // Deployment state
  const [deployedAt, setDeployedAt] = useState<string | null>(null)
  const [deployedVersion, setDeployedVersion] = useState<number | null>(null)
  const [currentVersion, setCurrentVersion] = useState<number>(1)
  const [needsRedeploy, setNeedsRedeploy] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [deployError, setDeployError] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Exception state
  const [exceptions, setExceptions] = useState<RuleException[]>([])
  const [isLoadingExceptions, setIsLoadingExceptions] = useState(false)
  const [newExceptionField, setNewExceptionField] = useState('')
  const [newExceptionOperator, setNewExceptionOperator] = useState<ExceptionOperator>('equals')
  const [newExceptionValue, setNewExceptionValue] = useState('')
  const [newExceptionReason, setNewExceptionReason] = useState('')
  const [isAddingException, setIsAddingException] = useState(false)

  // Exception delete confirmation state
  const [exceptionToDelete, setExceptionToDelete] = useState<RuleException | null>(null)
  const [isDeleteExceptionDialogOpen, setIsDeleteExceptionDialogOpen] = useState(false)
  const [isDeletingException, setIsDeletingException] = useState(false)

  // Snooze state
  const [snoozeUntil, setSnoozeUntil] = useState<string | null>(null)
  const [isSnoozing, setIsSnoozing] = useState(false)

  // Activity panel state
  const [isActivityOpen, setIsActivityOpen] = useState(false)

  // Rule source state (for existing rules)
  const [ruleSource, setRuleSource] = useState<'user' | 'sigmahq'>('user')
  const [sigmahqPath, setSigmahqPath] = useState<string | null>(null)

  // Threshold alerting state
  const [thresholdEnabled, setThresholdEnabled] = useState(false)
  const [thresholdCount, setThresholdCount] = useState<number | null>(null)
  const [thresholdWindowMinutes, setThresholdWindowMinutes] = useState<number | null>(null)
  const [thresholdGroupBy, setThresholdGroupBy] = useState<string | null>(null)

  // Unmapped fields dialog state
  const [unmappedFieldsDialog, setUnmappedFieldsDialog] = useState<{
    open: boolean
    fields: string[]
    indexPatternId: string
  }>({ open: false, fields: [], indexPatternId: '' })

  useEffect(() => {
    loadIndexPatterns()
    if (!isNew) {
      loadRule()
      loadExceptions()
    }
  }, [id])

  // Load exceptions when rule ID is available
  const loadExceptions = async () => {
    if (!id || isNew) return
    setIsLoadingExceptions(true)
    try {
      const result = await rulesApi.listExceptions(id)
      setExceptions(result)
    } catch (err) {
      console.error('Failed to load exceptions:', err)
    } finally {
      setIsLoadingExceptions(false)
    }
  }

  // Debounced validation
  useEffect(() => {
    const timer = setTimeout(() => {
      if (yamlContent.trim()) {
        validateRule()
      }
    }, 500)
    return () => clearTimeout(timer)
  }, [yamlContent, indexPatternId])

  const loadIndexPatterns = async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
      if (patterns.length > 0 && !indexPatternId) {
        setIndexPatternId(patterns[0].id)
      }
    } catch (err) {
      console.error('Failed to load index patterns:', err)
    }
  }

  const loadRule = async () => {
    if (!id) return
    setIsLoading(true)
    try {
      const rule = await rulesApi.get(id)
      setTitle(rule.title)
      setYamlContent(rule.yaml_content)
      setSeverity(rule.severity)
      setIndexPatternId(rule.index_pattern_id)
      setDescription(rule.description || '')
      setDeployedAt(rule.deployed_at)
      setDeployedVersion(rule.deployed_version)
      setCurrentVersion(rule.current_version)
      setNeedsRedeploy(rule.needs_redeploy)
      setStatus(rule.status as 'deployed' | 'undeployed' | 'snoozed')
      setSnoozeIndefinite(rule.snooze_indefinite || false)
      setSnoozeUntil(rule.snooze_until)
      // Track rule source
      setRuleSource(rule.source as 'user' | 'sigmahq' || 'user')
      setSigmahqPath(rule.sigmahq_path || null)
      // Load threshold settings
      setThresholdEnabled(rule.threshold_enabled)
      setThresholdCount(rule.threshold_count)
      setThresholdWindowMinutes(rule.threshold_window_minutes)
      setThresholdGroupBy(rule.threshold_group_by)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rule')
    } finally {
      setIsLoading(false)
    }
  }

  const validateRule = async () => {
    setIsValidating(true)
    try {
      const result = await rulesApi.validate(
        yamlContent,
        indexPatternId || undefined
      )
      setValidationErrors(result.errors)
      setIsValid(result.valid)
      setGeneratedQuery(result.opensearch_query || null)
      setDetectedFields(result.fields || [])
    } catch (err) {
      setValidationErrors([
        { type: 'error', message: err instanceof Error ? err.message : 'Validation failed' },
      ])
      setIsValid(false)
      setDetectedFields([])
    } finally {
      setIsValidating(false)
    }
  }

  const handleTest = async () => {
    setIsTesting(true)
    setTestResults(null)
    try {
      // Parse sample log JSON
      let logs: Record<string, unknown>[]
      try {
        const parsed = JSON.parse(sampleLog)
        logs = Array.isArray(parsed) ? parsed : [parsed]
      } catch {
        setTestResults([])
        setError('Invalid JSON in sample log')
        setIsTesting(false)
        return
      }

      const result = await rulesApi.test(yamlContent, logs)
      if (result.errors.length > 0) {
        setValidationErrors(result.errors)
        setIsValid(false)
      } else {
        setTestResults(result.matches)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setIsTesting(false)
    }
  }

  // Extract title and level from YAML when it changes
  const syncFromYaml = (yamlStr: string) => {
    try {
      const parsed = yaml.load(yamlStr) as Record<string, unknown>
      if (parsed?.title && typeof parsed.title === 'string') {
        setTitle(parsed.title)
      }
      if (parsed?.level && typeof parsed.level === 'string') {
        const level = parsed.level.toLowerCase()
        if (['critical', 'high', 'medium', 'low', 'informational'].includes(level)) {
          setSeverity(level)
        }
      }
    } catch {
      // Invalid YAML, ignore
    }
  }

  const handleYamlChange = (newYaml: string) => {
    setYamlContent(newYaml)
    syncFromYaml(newYaml)
  }

  const handleTitleChange = (newTitle: string) => {
    setTitle(newTitle)
    // Update YAML
    const updatedYaml = yamlContent.replace(
      /^title:\s*.+$/m,
      `title: ${newTitle}`
    )
    if (updatedYaml !== yamlContent) {
      setYamlContent(updatedYaml)
    }
  }

  const handleSeverityChange = (newSeverity: string) => {
    setSeverity(newSeverity)
    // Update YAML level field
    const updatedYaml = yamlContent.replace(
      /^level:\s*.+$/m,
      `level: ${newSeverity}`
    )
    if (updatedYaml !== yamlContent) {
      setYamlContent(updatedYaml)
    }
  }

  const formatYaml = () => {
    try {
      const parsed = yaml.load(yamlContent)
      if (!parsed || typeof parsed !== 'object') {
        setError('Cannot format: invalid YAML structure')
        return
      }
      // Re-dump with consistent formatting
      const formatted = yaml.dump(parsed, {
        indent: 2,
        lineWidth: -1, // Don't wrap lines
        quotingType: "'",
        forceQuotes: false,
        noRefs: true,
      })
      setYamlContent(formatted)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? `Format failed: ${err.message}` : 'Format failed')
    }
  }

  const handleSave = async () => {
    if (!isValid) {
      setError('Please fix validation errors before saving')
      return
    }

    if (!title.trim()) {
      setError('Title is required')
      return
    }

    if (!indexPatternId) {
      setError('Index pattern is required')
      return
    }

    setIsSaving(true)
    setError('')
    setSaveSuccess(false)

    try {
      if (isNew) {
        const newRule = await rulesApi.create({
          title,
          description: description || undefined,
          yaml_content: yamlContent,
          severity,
          status,
          index_pattern_id: indexPatternId,
          threshold_enabled: thresholdEnabled,
          threshold_count: thresholdEnabled ? thresholdCount : null,
          threshold_window_minutes: thresholdEnabled ? thresholdWindowMinutes : null,
          threshold_group_by: thresholdEnabled ? thresholdGroupBy : null,
        })
        // Navigate to the edit page for the new rule
        navigate(`/rules/${newRule.id}`, { replace: true })
      } else {
        await rulesApi.update(id!, {
          title,
          description: description || undefined,
          yaml_content: yamlContent,
          severity,
          status,
          index_pattern_id: indexPatternId,
          threshold_enabled: thresholdEnabled,
          threshold_count: thresholdEnabled ? thresholdCount : null,
          threshold_window_minutes: thresholdEnabled ? thresholdWindowMinutes : null,
          threshold_group_by: thresholdEnabled ? thresholdGroupBy : null,
        })
        // Reload rule to get updated version
        await loadRule()
        setSaveSuccess(true)
        // Clear success message after 3 seconds
        setTimeout(() => setSaveSuccess(false), 3000)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDeploy = async () => {
    if (!id) return
    setIsDeploying(true)
    setDeployError('')
    try {
      const result = await rulesApi.deploy(id)
      setDeployedAt(result.deployed_at)
      setDeployedVersion(result.deployed_version)
      setNeedsRedeploy(false)
      // Update status to deployed (unless already snoozed)
      if (status !== 'snoozed') {
        setStatus('deployed')
      }
    } catch (err) {
      if (err instanceof DeploymentUnmappedFieldsError) {
        // Show unmapped fields dialog
        setUnmappedFieldsDialog({
          open: true,
          fields: err.unmapped_fields,
          indexPatternId: err.index_pattern_id,
        })
      } else {
        setDeployError(err instanceof Error ? err.message : 'Deploy failed')
      }
    } finally {
      setIsDeploying(false)
    }
  }

  const handleUndeploy = async () => {
    if (!id) return
    setIsDeploying(true)
    setDeployError('')
    try {
      await rulesApi.undeploy(id)
      setDeployedAt(null)
      setDeployedVersion(null)
      setStatus('undeployed')
      // Clear snooze state as well (backend does this too)
      setSnoozeUntil(null)
      setSnoozeIndefinite(false)
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Undeploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  // Exception handlers
  const handleAddException = async () => {
    if (!id || !newExceptionField.trim() || !newExceptionValue.trim()) {
      setError('Field and value are required for exceptions')
      return
    }

    setIsAddingException(true)
    try {
      const data: RuleExceptionCreate = {
        field: newExceptionField.trim(),
        operator: newExceptionOperator,
        value: newExceptionValue.trim(),
        reason: newExceptionReason.trim() || undefined,
      }
      const newException = await rulesApi.createException(id, data)
      setExceptions((prev) => [...prev, newException])
      // Reset form
      setNewExceptionField('')
      setNewExceptionOperator('equals')
      setNewExceptionValue('')
      setNewExceptionReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add exception')
    } finally {
      setIsAddingException(false)
    }
  }

  const handleToggleException = async (exceptionId: string, isActive: boolean) => {
    if (!id) return
    try {
      const updated = await rulesApi.updateException(id, exceptionId, { is_active: isActive })
      setExceptions((prev) =>
        prev.map((e) => (e.id === exceptionId ? updated : e))
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update exception')
    }
  }

  const openDeleteExceptionDialog = (exception: RuleException) => {
    setExceptionToDelete(exception)
    setIsDeleteExceptionDialogOpen(true)
  }

  const confirmDeleteException = async () => {
    if (!id || !exceptionToDelete) return
    setIsDeletingException(true)
    try {
      await rulesApi.deleteException(id, exceptionToDelete.id)
      setExceptions((prev) => prev.filter((e) => e.id !== exceptionToDelete.id))
      setIsDeleteExceptionDialogOpen(false)
      setExceptionToDelete(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete exception')
    } finally {
      setIsDeletingException(false)
    }
  }

  // Snooze handlers
  const handleSnooze = async (hours: number) => {
    if (!id) return
    setIsSnoozing(true)
    try {
      const result = await rulesApi.snooze(id, hours, false)
      setStatus('snoozed')
      setSnoozeUntil(result.snooze_until)
      setSnoozeIndefinite(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to snooze rule')
    } finally {
      setIsSnoozing(false)
    }
  }

  const handleSnoozeIndefinite = async () => {
    if (!id) return
    setIsSnoozing(true)
    try {
      const result = await rulesApi.snooze(id, undefined, true)
      setStatus('snoozed')
      setSnoozeUntil(null)
      setSnoozeIndefinite(result.snooze_indefinite)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to snooze rule')
    } finally {
      setIsSnoozing(false)
    }
  }

  const handleUnsnooze = async () => {
    if (!id) return
    setIsSnoozing(true)
    try {
      await rulesApi.unsnooze(id)
      setStatus('deployed')  // Unsnooze returns to deployed state
      setSnoozeUntil(null)
      setSnoozeIndefinite(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unsnooze rule')
    } finally {
      setIsSnoozing(false)
    }
  }

  // Restore version handler for activity panel
  const handleRestoreVersion = async (versionNumber: number) => {
    try {
      const version = await rulesApi.getVersion(id!, versionNumber)
      setYamlContent(version.yaml_content)
      setIsActivityOpen(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore version')
    }
  }

  const formatSnoozeExpiry = (iso: string) => {
    const date = new Date(iso)
    return date.toLocaleString()
  }

  const operatorLabels: Record<ExceptionOperator, string> = {
    equals: 'Equals',
    not_equals: 'Not equals',
    contains: 'Contains',
    not_contains: 'Not contains',
    starts_with: 'Starts with',
    ends_with: 'Ends with',
    regex: 'Regex',
    in_list: 'In list',
  }

  const editorErrors = validationErrors
    .filter((e) => e.line)
    .map((e) => ({ line: e.line!, message: e.message }))

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/rules')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold">
                {isNew ? 'Create Rule' : 'Edit Rule'}
                {!isNew && <span className="text-sm font-normal text-muted-foreground ml-2">v{currentVersion}</span>}
              </h1>
              {!isNew && ruleSource === 'sigmahq' && (
                <div className="flex items-center gap-1 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded text-xs" title={sigmahqPath ? `Imported from: ${sigmahqPath}` : 'Imported from SigmaHQ'}>
                  <FileCode className="h-3 w-3" />
                  SigmaHQ
                </div>
              )}
              {!isNew && ruleSource === 'user' && (
                <div className="flex items-center gap-1 px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded text-xs">
                  <FileText className="h-3 w-3" />
                  User-created
                </div>
              )}
            </div>
            {!isNew && deployedAt && (
              <p className={`text-xs ${deployedVersion === currentVersion ? 'text-green-600' : 'text-yellow-600'}`}>
                {deployedVersion === currentVersion
                  ? `Deployed v${deployedVersion}`
                  : `Deployed v${deployedVersion} (current is v${currentVersion} - redeploy needed)`
                }
              </p>
            )}
            {!isNew && !deployedAt && (
              <p className="text-xs text-muted-foreground">Not deployed</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!isNew && (
            <div className="flex items-center gap-2 mr-4">
              {status === 'snoozed' ? (
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm text-yellow-600">
                    {snoozeIndefinite ? 'Snoozed indefinitely' : snoozeUntil ? `Snoozed until ${formatSnoozeExpiry(snoozeUntil)}` : 'Snoozed'}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleUnsnooze}
                    disabled={isSnoozing}
                  >
                    {isSnoozing ? 'Unsnoozing...' : 'Unsnooze'}
                  </Button>
                </div>
              ) : status === 'undeployed' ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500 font-medium">Undeployed</span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled
                    title="Deploy the rule first to enable snooze"
                  >
                    <Clock className="h-4 w-4 mr-1" />
                    Snooze
                  </Button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-green-600 font-medium">Deployed</span>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" disabled={isSnoozing}>
                        <Clock className="h-4 w-4 mr-1" />
                        Snooze
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent className="z-50 bg-popover">
                      <DropdownMenuItem onClick={() => handleSnooze(1)}>1 hour</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleSnooze(4)}>4 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleSnooze(8)}>8 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleSnooze(24)}>24 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleSnooze(168)}>1 week</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleSnoozeIndefinite()}>Indefinitely</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              )}
            </div>
          )}
          {saveSuccess && (
            <span className="text-sm text-green-600 flex items-center gap-1">
              <Check className="h-4 w-4" />
              Saved
            </span>
          )}
          {!isNew && (
            <Button variant="outline" onClick={() => setIsActivityOpen(true)}>
              <History className="h-4 w-4 mr-2" />
              Activity
            </Button>
          )}
          {!isNew && (
            <Button
              variant="outline"
              onClick={async () => {
                try {
                  const token = localStorage.getItem('chad-token')
                  const response = await fetch(`/api/export/rules/${id}`, {
                    headers: token ? { Authorization: `Bearer ${token}` } : {},
                  })
                  if (!response.ok) throw new Error('Export failed')
                  const blob = await response.blob()
                  const url = window.URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `${title.replace(/[^a-z0-9-_]/gi, '_')}.yml`
                  document.body.appendChild(a)
                  a.click()
                  document.body.removeChild(a)
                  window.URL.revokeObjectURL(url)
                } catch (err) {
                  setError(err instanceof Error ? err.message : 'Export failed')
                }
              }}
            >
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          )}
          {!isNew && (
            deployedAt ? (
              <>
                {deployedVersion !== currentVersion && (
                  <Button
                    variant="outline"
                    onClick={handleDeploy}
                    disabled={isDeploying || !isValid}
                  >
                    <Rocket className="h-4 w-4 mr-2" />
                    {isDeploying ? 'Deploying...' : 'Redeploy'}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={handleUndeploy}
                  disabled={isDeploying}
                >
                  <RotateCcw className="h-4 w-4 mr-2" />
                  {isDeploying ? 'Undeploying...' : 'Undeploy'}
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                onClick={handleDeploy}
                disabled={isDeploying || !isValid}
              >
                <Rocket className="h-4 w-4 mr-2" />
                {isDeploying ? 'Deploying...' : 'Deploy'}
              </Button>
            )
          )}
          <Button onClick={handleSave} disabled={isSaving || !isValid}>
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {deployError && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          Deployment error: {deployError}
        </div>
      )}

      {needsRedeploy && (
        <div className="bg-orange-500/10 text-orange-600 text-sm p-3 rounded-md flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4" />
            This rule has been modified since deployment. Redeploy to apply changes.
          </div>
          <Button
            size="sm"
            onClick={handleDeploy}
            disabled={isDeploying}
          >
            {isDeploying ? 'Deploying...' : 'Redeploy Now'}
          </Button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editor - 2 columns */}
        <div className="lg:col-span-2 space-y-4">
          <div className="space-y-2">
            <Label htmlFor="title">Title</Label>
            <Input
              id="title"
              value={title}
              onChange={(e) => handleTitleChange(e.target.value)}
              placeholder="Detection rule title"
            />
          </div>

          <div className="border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between bg-muted/50 px-3 py-1.5 border-b">
              <span className="text-xs text-muted-foreground">Sigma YAML</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={formatYaml}
                className="h-6 text-xs"
              >
                <AlignLeft className="h-3 w-3 mr-1" />
                Format
              </Button>
            </div>
            <YamlEditor
              value={yamlContent}
              onChange={handleYamlChange}
              height="400px"
              errors={editorErrors}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Index Pattern</Label>
              <Select value={indexPatternId} onValueChange={setIndexPatternId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select index pattern" />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  {indexPatterns.map((pattern) => (
                    <SelectItem key={pattern.id} value={pattern.id}>
                      {pattern.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={handleSeverityChange}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  <SelectItem value="informational">Informational</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        {/* Side Panel - 1 column */}
        <div className="space-y-4">
          {/* Validation Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                Validation
                {isValidating && (
                  <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {isValid === null ? (
                <div className="text-sm text-muted-foreground">
                  Enter a rule to validate
                </div>
              ) : isValid ? (
                <div className="flex items-center gap-2 text-sm text-green-600">
                  <Check className="h-4 w-4" />
                  Rule is valid
                </div>
              ) : (
                <div className="space-y-2">
                  {validationErrors.map((error, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2 text-sm text-destructive"
                    >
                      <X className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>
                        {error.line && `Line ${error.line}: `}
                        {error.message}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {detectedFields.length > 0 && (
                <details className="mt-4" open>
                  <summary className="text-sm text-muted-foreground cursor-pointer">
                    Detected Fields ({detectedFields.length})
                  </summary>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {detectedFields.map((field) => (
                      <code
                        key={field}
                        className="px-1.5 py-0.5 bg-muted rounded text-xs font-mono"
                      >
                        {field}
                      </code>
                    ))}
                  </div>
                </details>
              )}

              {isValid !== null && detectedFields.length === 0 && (
                <div className="mt-2 text-xs text-muted-foreground">
                  No detection fields found in rule
                </div>
              )}

              {generatedQuery && (
                <details className="mt-4">
                  <summary className="text-sm text-muted-foreground cursor-pointer">
                    View OpenSearch Query
                  </summary>
                  <pre className="mt-2 p-2 bg-muted rounded text-xs overflow-auto max-h-40">
                    {JSON.stringify(generatedQuery, null, 2)}
                  </pre>
                </details>
              )}
            </CardContent>
          </Card>

          {/* Test Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium">Test Rule</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <Label className="text-xs">Sample Log (JSON)</Label>
                <textarea
                  value={sampleLog}
                  onChange={(e) => setSampleLog(e.target.value)}
                  className="w-full h-32 p-2 text-xs font-mono border rounded-md bg-background resize-none"
                  placeholder='{"field": "value"}'
                />
              </div>
              <Button
                size="sm"
                variant="secondary"
                onClick={handleTest}
                disabled={isTesting || !isValid}
                className="w-full"
              >
                <Play className="h-3 w-3 mr-2" />
                {isTesting ? 'Testing...' : 'Test'}
              </Button>

              {testResults && (
                <div className="space-y-1">
                  {testResults.map((result, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center gap-2 text-sm ${
                        result.matched ? 'text-green-600' : 'text-muted-foreground'
                      }`}
                    >
                      {result.matched ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <X className="h-4 w-4" />
                      )}
                      Log {result.log_index + 1}: {result.matched ? 'Matched' : 'No match'}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Threshold Alerting Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium">Threshold Alerting</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <Label htmlFor="threshold-enabled" className="text-sm">
                  Enable threshold alerting
                </Label>
                <Switch
                  id="threshold-enabled"
                  checked={thresholdEnabled}
                  onCheckedChange={setThresholdEnabled}
                />
              </div>
              {thresholdEnabled && (
                <div className="space-y-3 pt-2 border-t">
                  <div className="text-xs text-muted-foreground">
                    Only create an alert when the rule matches N times within the specified window.
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <Label className="text-xs">Count</Label>
                      <Input
                        type="number"
                        min={1}
                        value={thresholdCount ?? ''}
                        onChange={(e) => setThresholdCount(e.target.value ? parseInt(e.target.value) : null)}
                        placeholder="5"
                        className="h-8 text-sm"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Window (minutes)</Label>
                      <Input
                        type="number"
                        min={1}
                        value={thresholdWindowMinutes ?? ''}
                        onChange={(e) => setThresholdWindowMinutes(e.target.value ? parseInt(e.target.value) : null)}
                        placeholder="10"
                        className="h-8 text-sm"
                      />
                    </div>
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Group by field (optional)</Label>
                    <Input
                      value={thresholdGroupBy ?? ''}
                      onChange={(e) => setThresholdGroupBy(e.target.value || null)}
                      placeholder="user.name"
                      className="h-8 text-sm"
                    />
                    <div className="text-xs text-muted-foreground">
                      Count matches separately per unique value of this field
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Exceptions Card - Only show for existing rules */}
          {!isNew && (
            <Card>
              <CardHeader className="py-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  Exceptions
                  {isLoadingExceptions && (
                    <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Existing exceptions list */}
                {exceptions.length === 0 ? (
                  <div className="text-sm text-muted-foreground">
                    No exceptions defined
                  </div>
                ) : (
                  <div className="space-y-3">
                    {exceptions.map((exception) => (
                      <div
                        key={exception.id}
                        className={`p-2 border rounded-md space-y-1 ${
                          !exception.is_active ? 'opacity-50' : ''
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium truncate">
                              {exception.field}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {operatorLabels[exception.operator]}: {exception.value}
                            </div>
                            {exception.reason && (
                              <div className="text-xs text-muted-foreground mt-1 italic">
                                Reason: {exception.reason}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <Switch
                              checked={exception.is_active}
                              onCheckedChange={(checked) =>
                                handleToggleException(exception.id, checked)
                              }
                            />
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6"
                              onClick={() => openDeleteExceptionDialog(exception)}
                            >
                              <Trash2 className="h-3 w-3 text-destructive" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Add exception form */}
                <div className="border-t pt-4 space-y-3">
                  <Label className="text-xs font-medium">Add Exception</Label>
                  <div className="space-y-2">
                    <Input
                      placeholder="Field name"
                      value={newExceptionField}
                      onChange={(e) => setNewExceptionField(e.target.value)}
                      className="h-8 text-sm"
                    />
                    <Select
                      value={newExceptionOperator}
                      onValueChange={(value) =>
                        setNewExceptionOperator(value as ExceptionOperator)
                      }
                    >
                      <SelectTrigger className="h-8 text-sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="z-50 bg-popover">
                        <SelectItem value="equals">Equals</SelectItem>
                        <SelectItem value="not_equals">Not equals</SelectItem>
                        <SelectItem value="contains">Contains</SelectItem>
                        <SelectItem value="not_contains">Not contains</SelectItem>
                        <SelectItem value="starts_with">Starts with</SelectItem>
                        <SelectItem value="ends_with">Ends with</SelectItem>
                        <SelectItem value="regex">Regex</SelectItem>
                        <SelectItem value="in_list">In list</SelectItem>
                      </SelectContent>
                    </Select>
                    <textarea
                      placeholder="Value"
                      value={newExceptionValue}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setNewExceptionValue(e.target.value)}
                      className="w-full min-h-[60px] p-2 text-sm border rounded-md bg-background resize-none"
                    />
                    <Input
                      placeholder="Reason (optional)"
                      value={newExceptionReason}
                      onChange={(e) => setNewExceptionReason(e.target.value)}
                      className="h-8 text-sm"
                    />
                    <Button
                      size="sm"
                      onClick={handleAddException}
                      disabled={
                        isAddingException ||
                        !newExceptionField.trim() ||
                        !newExceptionValue.trim()
                      }
                      className="w-full"
                    >
                      <Plus className="h-3 w-3 mr-2" />
                      {isAddingException ? 'Adding...' : 'Add Exception'}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Exception Delete Confirmation Modal */}
      <DeleteConfirmModal
        open={isDeleteExceptionDialogOpen}
        onOpenChange={setIsDeleteExceptionDialogOpen}
        title="Delete Exception"
        description="Are you sure you want to delete this exception? This action cannot be undone."
        itemName={exceptionToDelete ? `${exceptionToDelete.field} ${operatorLabels[exceptionToDelete.operator]} ${exceptionToDelete.value}` : undefined}
        onConfirm={confirmDeleteException}
        isDeleting={isDeletingException}
      />

      {/* Activity Panel */}
      {!isNew && (
        <ActivityPanel
          ruleId={id!}
          currentYaml={yamlContent}
          currentVersion={currentVersion}
          isOpen={isActivityOpen}
          onClose={() => setIsActivityOpen(false)}
          onRestore={handleRestoreVersion}
        />
      )}

      {/* Unmapped Fields Dialog */}
      <Dialog
        open={unmappedFieldsDialog.open}
        onOpenChange={(open) =>
          setUnmappedFieldsDialog((prev) => ({ ...prev, open }))
        }
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertCircle className="h-5 w-5" />
              Unmapped Fields Detected
            </DialogTitle>
            <DialogDescription>
              The following Sigma fields are not found in the target index and
              have no field mappings configured. You need to create field
              mappings to deploy this rule.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="flex flex-wrap gap-2">
              {unmappedFieldsDialog.fields.map((field) => (
                <code
                  key={field}
                  className="px-2 py-1 bg-destructive/10 text-destructive rounded text-sm font-mono"
                >
                  {field}
                </code>
              ))}
            </div>
          </div>
          <DialogFooter className="flex gap-2">
            <Button
              variant="outline"
              onClick={() =>
                setUnmappedFieldsDialog((prev) => ({ ...prev, open: false }))
              }
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                // Navigate to field mappings page with the index pattern pre-selected
                navigate(
                  `/field-mappings?index_pattern_id=${unmappedFieldsDialog.indexPatternId}&fields=${unmappedFieldsDialog.fields.join(',')}`
                )
              }}
            >
              <Link2 className="h-4 w-4 mr-2" />
              Configure Field Mappings
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
