import { useEffect, useState } from 'react'
import { useNavigate, useParams, useLocation } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import {
  rulesApi,
  correlationRulesApi,
  indexPatternsApi,
  settingsApi,
  IndexPattern,
  ValidationError,
  LogMatchResult,
  RuleException,
  ExceptionOperator,
  RuleExceptionCreate,
  DeploymentUnmappedFieldsError,
  FieldMappingInfo,
  CorrelationRule,
} from '@/lib/api'
import { YamlEditor } from '@/components/YamlEditor'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import yaml from 'js-yaml'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ArrowLeft, Check, X, Play, AlertCircle, Rocket, RotateCcw, Loader2, Trash2, Plus, Clock, History, Download, AlignLeft, FileCode, FileText, ChevronDown, ChevronUp, Copy, Link } from 'lucide-react'
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
import { MapFieldsModal } from '@/components/MapFieldsModal'
import { HistoricalTestPanel } from '@/components/HistoricalTestPanel'

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

// Location state for cloning rules
interface LocationState {
  yamlContent?: string
  indexPatternId?: string
  title?: string
}

export default function RuleEditorPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const location = useLocation()
  const isNew = !id || id === 'new'

  // Get clone state from navigation (if cloning a rule)
  const cloneState = location.state as LocationState | null

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
  const [fieldMappings, setFieldMappings] = useState<FieldMappingInfo[]>([])

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

  // Rule versions state
  const [ruleVersions, setRuleVersions] = useState<any[] | null>(null)

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

  // Correlation rules state
  const [correlationRules, setCorrelationRules] = useState<CorrelationRule[]>([])
  const [isLoadingCorrelations, setIsLoadingCorrelations] = useState(false)

  // Snooze state
  const [snoozeUntil, setSnoozeUntil] = useState<string | null>(null)
  const [isSnoozing, setIsSnoozing] = useState(false)

  // Activity panel state
  const [isActivityOpen, setIsActivityOpen] = useState(false)

  // Delete rule confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [isDeletingRule, setIsDeletingRule] = useState(false)

  // Rule source state (for existing rules)
  const [ruleSource, setRuleSource] = useState<'user' | 'sigmahq'>('user')
  const [sigmahqPath, setSigmahqPath] = useState<string | null>(null)

  // Threshold alerting state
  const [thresholdEnabled, setThresholdEnabled] = useState(false)
  const [thresholdCount, setThresholdCount] = useState<number | null>(null)
  const [thresholdWindowMinutes, setThresholdWindowMinutes] = useState<number | null>(null)
  const [thresholdGroupBy, setThresholdGroupBy] = useState<string | null>(null)

  // Collapsible section state
  const [showThreshold, setShowThreshold] = useState(false)
  const [showExceptions, setShowExceptions] = useState(false)
  const [showCorrelation, setShowCorrelation] = useState(false)
  const [showHistoricalTest, setShowHistoricalTest] = useState(false)

  // Unmapped fields dialog state
  const [unmappedFieldsDialog, setUnmappedFieldsDialog] = useState<{
    open: boolean
    fields: string[]
    indexPatternId: string
  }>({ open: false, fields: [], indexPatternId: '' })

  // Map fields modal state
  const [mapFieldsModalOpen, setMapFieldsModalOpen] = useState(false)

  // Change reason modal state
  const [mandatoryComments, setMandatoryComments] = useState(true)
  const [showChangeReason, setShowChangeReason] = useState(false)
  const [changeReason, setChangeReason] = useState('')

  useEffect(() => {
    loadIndexPatterns()
    if (!isNew) {
      loadRule()
      loadExceptions()
      loadCorrelationRules()
    }
  }, [id])

  // Handle clone state from navigation
  useEffect(() => {
    if (isNew && cloneState) {
      if (cloneState.yamlContent) {
        setYamlContent(cloneState.yamlContent)
      }
      if (cloneState.title) {
        setTitle(cloneState.title)
        // Also update the title in YAML
        if (cloneState.yamlContent) {
          const updatedYaml = cloneState.yamlContent.replace(
            /^title:\s*.+$/m,
            `title: ${cloneState.title}`
          )
          setYamlContent(updatedYaml)
        }
      }
      if (cloneState.indexPatternId) {
        setIndexPatternId(cloneState.indexPatternId)
      }
    }
  }, [isNew, cloneState])

  // Load mandatory comments settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const settings = await settingsApi.getMandatoryCommentsSettings()
        setMandatoryComments(settings.mandatory_rule_comments)
      } catch (err) {
        console.error('Failed to load mandatory comments settings:', err)
        // Default to true on error to be safe
        setMandatoryComments(true)
      }
    }
    loadSettings()
  }, [])

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

  // Load correlation rules when rule ID is available
  const loadCorrelationRules = async () => {
    if (!id || isNew) return
    setIsLoadingCorrelations(true)
    try {
      const result = await correlationRulesApi.list(true)
      // Filter to only show correlation rules that use this rule
      const relatedRules = result.correlation_rules.filter(
        (rule) => rule.rule_a_id === id || rule.rule_b_id === id
      )
      setCorrelationRules(relatedRules)
    } catch (err) {
      console.error('Failed to load correlation rules:', err)
    } finally {
      setIsLoadingCorrelations(false)
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
      // Store rule versions for current version display
      setRuleVersions(rule.versions || null)
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
      setFieldMappings(result.field_mappings || [])
    } catch (err) {
      setValidationErrors([
        { type: 'error', message: err instanceof Error ? err.message : 'Validation failed' },
      ])
      setIsValid(false)
      setDetectedFields([])
      setFieldMappings([])
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

    // If mandatory comments enabled and no change_reason provided, show modal
    if (!isNew && mandatoryComments && !changeReason.trim()) {
      setShowChangeReason(true)
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
          change_reason: changeReason || 'Updated',
        })
        // Reload rule to get updated version
        await loadRule()
        setSaveSuccess(true)
        // Reset change reason
        setChangeReason('')
        setShowChangeReason(false)
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

  // Clone rule handler
  const handleClone = () => {
    // Navigate to new rule with current content
    navigate('/rules/new', {
      state: {
        yamlContent,
        indexPatternId,
        title: `${title} (Copy)`
      }
    })
  }

  // Export YAML handler
  const handleExportYaml = () => {
    const blob = new Blob([yamlContent], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${title.replace(/[^a-z0-9-_]/gi, '_')}.yml`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Delete rule handler
  const handleDeleteRule = async () => {
    if (!id) return
    setIsDeletingRule(true)
    try {
      await rulesApi.delete(id)
      navigate('/rules')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule')
      setIsDeletingRule(false)
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline">
                  More Actions <ChevronDown className="ml-2 h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="z-50 bg-popover">
                <DropdownMenuItem onClick={handleClone}>
                  <Copy className="mr-2 h-4 w-4" /> Clone Rule
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleExportYaml}>
                  <Download className="mr-2 h-4 w-4" /> Export YAML
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => setShowDeleteConfirm(true)}
                  className="text-destructive focus:text-destructive"
                >
                  <Trash2 className="mr-2 h-4 w-4" /> Delete Rule
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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

      {/* Current Version Info */}
      {!isNew && ruleVersions && ruleVersions.length > 0 && (
        <div className="mb-4 p-3 border rounded-lg bg-muted/50">
          <div className="flex items-center gap-2 text-sm">
            <Badge variant="outline">Current Version: v{currentVersion}</Badge>
            <span className="text-muted-foreground">
              Last updated {formatDistanceToNow(new Date(ruleVersions[0].created_at), { addSuffix: true })}
            </span>
          </div>
          {ruleVersions[0].change_reason && (
            <div className="mt-2 text-sm italic">
              <span className="font-medium">Last change reason:</span> "{ruleVersions[0].change_reason}"
            </div>
          )}
        </div>
      )}

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
              {(() => {
                // Separate field errors from other errors
                const fieldErrors = validationErrors.filter((e) => e.type === 'field')
                const otherErrors = validationErrors.filter((e) => e.type !== 'field')
                const unmappedFieldNames = new Set(fieldErrors.map((e) => e.field).filter(Boolean))
                const hasFieldErrors = fieldErrors.length > 0

                return (
                  <>
                    {isValid === null ? (
                      <div className="text-sm text-muted-foreground">
                        Enter a rule to validate
                      </div>
                    ) : isValid ? (
                      <div className="flex items-center gap-2 text-sm text-green-600">
                        <Check className="h-4 w-4" />
                        Rule is valid
                      </div>
                    ) : otherErrors.length > 0 ? (
                      <div className="space-y-2">
                        {otherErrors.map((error, idx) => (
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
                    ) : hasFieldErrors ? (
                      <div className="flex items-center gap-2 text-sm text-yellow-600">
                        <AlertCircle className="h-4 w-4" />
                        Fields need mapping
                      </div>
                    ) : null}

                    {/* Detected Fields with arrow notation for mappings */}
                    {(fieldMappings.length > 0 || detectedFields.length > 0) && (
                      <div className="mt-4">
                        <div className="text-sm text-muted-foreground mb-2">
                          Detected Fields ({fieldMappings.length || detectedFields.length})
                        </div>
                        <div className="space-y-1">
                          {fieldMappings.length > 0 ? (
                            fieldMappings.map((mapping) => (
                              <div key={mapping.sigma_field} className="flex items-center gap-2">
                                <code className="text-xs bg-muted px-1 rounded">{mapping.sigma_field}</code>
                                <span className="text-muted-foreground">→</span>
                                {mapping.target_field ? (
                                  <code className="text-xs bg-green-100 dark:bg-green-900 px-1 rounded">
                                    {mapping.target_field}
                                  </code>
                                ) : (
                                  <span className="text-xs text-destructive flex items-center gap-1">
                                    <AlertCircle className="h-3 w-3" /> Not mapped
                                  </span>
                                )}
                              </div>
                            ))
                          ) : (
                            // Fallback to simple field list if no mapping info available
                            <div className="flex flex-wrap gap-1">
                              {detectedFields.map((field) => {
                                const isUnmapped = unmappedFieldNames.has(field)
                                return (
                                  <code
                                    key={field}
                                    className={`px-1.5 py-0.5 rounded text-xs font-mono ${
                                      isUnmapped
                                        ? 'bg-destructive/10 text-destructive'
                                        : 'bg-green-500/10 text-green-600'
                                    }`}
                                  >
                                    {field}
                                  </code>
                                )
                              })}
                            </div>
                          )}
                        </div>
                        {/* Map Fields button below detected fields */}
                        {hasFieldErrors && indexPatternId && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="mt-3"
                            onClick={() => {
                              const unmappedFields = Array.from(unmappedFieldNames) as string[]
                              setUnmappedFieldsDialog({
                                open: false,
                                fields: unmappedFields.length > 0 ? unmappedFields : detectedFields,
                                indexPatternId,
                              })
                              setMapFieldsModalOpen(true)
                            }}
                          >
                            Map Fields
                          </Button>
                        )}
                      </div>
                    )}

                    {isValid !== null && detectedFields.length === 0 && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        No detection fields found in rule
                      </div>
                    )}
                  </>
                )
              })()}

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

          {/* Historical Dry-Run Test - Only show for existing rules with index pattern */}
          {!isNew && indexPatternId && (
            <Card>
              <CardHeader
                className="py-3 cursor-pointer"
                onClick={() => setShowHistoricalTest(!showHistoricalTest)}
              >
                <CardTitle className="text-sm font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <History className="h-4 w-4" />
                    Historical Dry-Run Test
                  </span>
                  {showHistoricalTest ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </CardTitle>
              </CardHeader>
              {showHistoricalTest && (
                <CardContent className="pt-0">
                  <HistoricalTestPanel ruleId={id!} />
                </CardContent>
              )}
            </Card>
          )}

          {/* Threshold Alerting Card */}
          <Card>
            <CardHeader
              className="py-3 cursor-pointer"
              onClick={() => setShowThreshold(!showThreshold)}
            >
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <span>Threshold Alerting</span>
                {showThreshold ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </CardTitle>
            </CardHeader>
            {showThreshold && (
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
            )}
          </Card>

          {/* Exceptions Card - Only show for existing rules */}
          {!isNew && (
            <Card>
              <CardHeader
                className="py-3 cursor-pointer"
                onClick={() => setShowExceptions(!showExceptions)}
              >
                <CardTitle className="text-sm font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    Exceptions
                    {isLoadingExceptions && (
                      <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                    )}
                    {exceptions.length > 0 && (
                      <span className="text-xs text-muted-foreground font-normal">
                        ({exceptions.length})
                      </span>
                    )}
                  </span>
                  {showExceptions ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </CardTitle>
              </CardHeader>
              {showExceptions && (
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
                      {detectedFields.length > 0 ? (
                        <Select
                          value={newExceptionField}
                          onValueChange={setNewExceptionField}
                        >
                          <SelectTrigger className="h-8 text-sm">
                            <SelectValue placeholder="Select field" />
                          </SelectTrigger>
                          <SelectContent className="z-50 bg-popover max-h-48">
                            {detectedFields.map((field) => (
                              <SelectItem key={field} value={field}>
                                {field}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <Input
                          placeholder="Field name"
                          value={newExceptionField}
                          onChange={(e) => setNewExceptionField(e.target.value)}
                          className="h-8 text-sm"
                        />
                      )}
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
              )}
            </Card>
          )}

          {/* Correlation Rules Card - Only show for existing rules */}
          {!isNew && (
            <Card>
              <CardHeader
                className="py-3 cursor-pointer"
                onClick={() => setShowCorrelation(!showCorrelation)}
              >
                <CardTitle className="text-sm font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    Correlation Rules
                    {isLoadingCorrelations && (
                      <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                    )}
                    {correlationRules.length > 0 && (
                      <span className="text-xs text-muted-foreground font-normal">
                        ({correlationRules.length})
                      </span>
                    )}
                  </span>
                  {showCorrelation ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </CardTitle>
              </CardHeader>
              {showCorrelation && (
                <CardContent className="space-y-4">
                  {correlationRules.length === 0 ? (
                    <div className="text-sm text-muted-foreground">
                      This rule is not used in any correlation rules.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {correlationRules.map((correlation) => (
                        <div
                          key={correlation.id}
                          className="p-3 border rounded-md space-y-2"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <div className="text-sm font-medium truncate">
                                  {correlation.name}
                                </div>
                                {!correlation.is_enabled && (
                                  <span className="text-xs text-muted-foreground">(Disabled)</span>
                                )}
                              </div>
                              <div className="text-xs text-muted-foreground mt-1">
                                <div>Correlates with:</div>
                                <div className="font-mono">
                                  {correlation.rule_a_id === id
                                    ? (correlation.rule_b_title || correlation.rule_b_id)
                                    : (correlation.rule_a_title || correlation.rule_a_id)}
                                </div>
                              </div>
                              <div className="text-xs text-muted-foreground mt-1">
                                <div>Entity: <span className="font-mono">{correlation.entity_field}</span></div>
                                <div>Window: {correlation.time_window_minutes} min</div>
                                <div>Severity: {correlation.severity}</div>
                              </div>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => navigate(`/correlation/${correlation.id}`)}
                              className="shrink-0"
                            >
                              <Link className="h-4 w-4 mr-1" />
                              View
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="pt-2 border-t">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate('/correlation/new')}
                      className="w-full"
                    >
                      <Plus className="h-3 w-3 mr-2" />
                      Create Correlation Rule
                    </Button>
                  </div>
                </CardContent>
              )}
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

      {/* Rule Delete Confirmation Modal */}
      <DeleteConfirmModal
        open={showDeleteConfirm}
        onOpenChange={setShowDeleteConfirm}
        title="Delete Rule"
        description="Are you sure you want to delete this rule? This action cannot be undone."
        itemName={title}
        onConfirm={handleDeleteRule}
        isDeleting={isDeletingRule}
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
              Deploy Failed
            </DialogTitle>
            <DialogDescription>
              The following Sigma fields have no mapping to your log fields:
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
          <DialogFooter className="justify-center">
            <Button
              onClick={() => {
                setUnmappedFieldsDialog((prev) => ({ ...prev, open: false }))
                setMapFieldsModalOpen(true)
              }}
            >
              Map Fields
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Reason Modal */}
      <Dialog open={showChangeReason} onOpenChange={setShowChangeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change Reason Required</DialogTitle>
            <DialogDescription>
              Please explain why you're updating this rule. This helps maintain an audit trail of rule changes.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="change-reason">Reason for Change *</Label>
              <Textarea
                id="change-reason"
                placeholder="Explain why you're making this change..."
                value={changeReason}
                onChange={(e) => setChangeReason(e.target.value)}
                rows={4}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowChangeReason(false)
                setChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={!changeReason.trim() || isSaving}
            >
              {isSaving ? 'Saving...' : 'Save with Reason'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Map Fields Modal */}
      <MapFieldsModal
        open={mapFieldsModalOpen}
        onOpenChange={setMapFieldsModalOpen}
        unmappedFields={unmappedFieldsDialog.fields}
        indexPatternId={unmappedFieldsDialog.indexPatternId}
        onMappingsSaved={() => {
          // Re-validate to update detected fields and try deploy again
          validateRule()
        }}
      />
    </div>
  )
}
