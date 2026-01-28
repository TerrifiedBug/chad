import { useEffect, useState, useMemo, useCallback } from 'react'
import { useNavigate, useParams, useLocation } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { useAuth } from '@/hooks/use-auth'
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
import type { RuleVersion } from '@/types/api'
import { YamlEditor } from '@/components/YamlEditor'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
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
import { ArrowLeft, Check, X, Play, AlertCircle, Rocket, RotateCcw, Loader2, Trash2, Plus, Clock, History, Download, AlignLeft, FileCode, FileText, ChevronDown, ChevronUp, Copy, Link, Beaker, TestTube, TrendingUp, ShieldAlert, GitCompare } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { TooltipProvider } from '@/components/ui/tooltip'
import { ActivityPanel } from '@/components/ActivityPanel'
import { MapFieldsModal } from '@/components/MapFieldsModal'
import { HistoricalTestPanel } from '@/components/HistoricalTestPanel'
import { SearchableFieldSelector } from '@/components/SearchableFieldSelector'

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
  const { hasPermission } = useAuth()
  const isNew = !id || id === 'new'
  const canManageRules = hasPermission('manage_rules')

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
  const [currentVersionNumber, setCurrentVersionNumber] = useState<number>(1)
  const [needsRedeploy, setNeedsRedeploy] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [deployError, setDeployError] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Rule versions state
  const [ruleVersions, setRuleVersions] = useState<RuleVersion[] | null>(null)

  // Compute the current (most recent) version using useMemo
  const currentVersion = useMemo(() => {
    if (!ruleVersions || ruleVersions.length === 0) return null

    // Find version with highest version_number
    const latest = ruleVersions.reduce((latest, version) =>
      version.version_number > latest.version_number ? version : latest
    )

    return latest
  }, [ruleVersions])

  // Users state for mapping UUID to email
  const [users, setUsers] = useState<Record<string, {email: string}>>({})

  // Track original YAML for dirty state
  const [originalYaml, setOriginalYaml] = useState('')

  // Exception state
  const [exceptions, setExceptions] = useState<RuleException[]>([])
  const [isLoadingExceptions, setIsLoadingExceptions] = useState(false)
  const [newExceptionField, setNewExceptionField] = useState('')
  const [newExceptionOperator, setNewExceptionOperator] = useState<ExceptionOperator>('equals')
  const [newExceptionValue, setNewExceptionValue] = useState('')
  const [newExceptionReason, setNewExceptionReason] = useState('')
  const [isAddingException, setIsAddingException] = useState(false)

  // Add state for available fields from OpenSearch
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(false)

  // Exception delete confirmation state
  const [exceptionToDelete, setExceptionToDelete] = useState<RuleException | null>(null)
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
  const [showDeleteReason, setShowDeleteReason] = useState(false)
  const [deleteReason, setDeleteReason] = useState('')
  const [isDeletingRule, setIsDeletingRule] = useState(false)

  // Rule source state (for existing rules)
  const [ruleSource, setRuleSource] = useState<'user' | 'sigmahq'>('user')
  const [sigmahqPath, setSigmahqPath] = useState<string | null>(null)

  // Threshold alerting state
  const [thresholdEnabled, setThresholdEnabled] = useState(false)
  const [thresholdCount, setThresholdCount] = useState<number | null>(null)
  const [thresholdWindowMinutes, setThresholdWindowMinutes] = useState<number | null>(null)
  const [thresholdGroupBy, setThresholdGroupBy] = useState<string | null>(null)

  // Available fields for group_by dropdown
  const [availableGroupByFields, setAvailableGroupByFields] = useState<string[]>([])
  const [isLoadingGroupByFields, setIsLoadingGroupByFields] = useState(false)

  // Collapsible section state
  const [showThreshold, setShowThreshold] = useState(false)
  const [showExceptions, setShowExceptions] = useState(false)
  const [showCorrelation, setShowCorrelation] = useState(false)
  const [showTest, setShowTest] = useState(false)
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

  // Deploy/Undeploy change reason dialog state
  const [showDeployReason, setShowDeployReason] = useState(false)
  const [showUndeployReason, setShowUndeployReason] = useState(false)
  const [deployReason, setDeployReason] = useState('')

  // Snooze/Unsnooze change reason dialog state
  const [showSnoozeReason, setShowSnoozeReason] = useState(false)
  const [showUnsnoozeReason, setShowUnsnoozeReason] = useState(false)
  const [snoozeReason, setSnoozeReason] = useState('')
  const [pendingSnoozeHours, setPendingSnoozeHours] = useState<number | undefined>(undefined)
  const [pendingSnoozeIndefinite, setPendingSnoozeIndefinite] = useState(false)

  // Exception change reason dialog state
  const [showExceptionCreateReason, setShowExceptionCreateReason] = useState(false)
  const [exceptionChangeReason, setExceptionChangeReason] = useState('')
  const [showExceptionToggleReason, setShowExceptionToggleReason] = useState(false)
  const [pendingExceptionToggle, setPendingExceptionToggle] = useState<{ id: string; isActive: boolean } | null>(null)
  const [showExceptionDeleteReason, setShowExceptionDeleteReason] = useState(false)

  // Threshold change reason state
  const [showThresholdReason, setShowThresholdReason] = useState(false)
  const [thresholdChangeReason, setThresholdChangeReason] = useState('')
  const [pendingThresholdEnabled, setPendingThresholdEnabled] = useState<boolean | null>(null)
  const [isUpdatingThreshold, setIsUpdatingThreshold] = useState(false)
  // Track original threshold field values to detect changes
  const [originalThresholdCount, setOriginalThresholdCount] = useState<number | null>(null)
  const [originalThresholdWindowMinutes, setOriginalThresholdWindowMinutes] = useState<number | null>(null)
  const [originalThresholdGroupBy, setOriginalThresholdGroupBy] = useState<string | null>(null)

  // Load functions - must be declared before useEffect that uses them
  const loadExceptions = useCallback(async () => {
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
  }, [id, isNew])

  // Load correlation rules when rule ID is available
  const loadCorrelationRules = useCallback(async () => {
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
  }, [id, isNew])

  const loadIndexPatterns = useCallback(async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
      if (patterns.length > 0 && !indexPatternId) {
        setIndexPatternId(patterns[0].id)
      }
    } catch (err) {
      console.error('Failed to load index patterns:', err)
    }
  }, [indexPatternId])

  const validateRule = useCallback(async () => {
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
  }, [yamlContent, indexPatternId])

  const loadRule = useCallback(async () => {
    if (!id) return
    setIsLoading(true)
    try {
      const rule = await rulesApi.get(id)
      setTitle(rule.title)
      setYamlContent(rule.yaml_content)
      setOriginalYaml(rule.yaml_content)
      setSeverity(rule.severity)
      setIndexPatternId(rule.index_pattern_id)
      setDescription(rule.description || '')
      setDeployedAt(rule.deployed_at)
      setDeployedVersion(rule.deployed_version)
      setCurrentVersionNumber(rule.current_version)
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
      setOriginalThresholdCount(rule.threshold_count)
      setThresholdWindowMinutes(rule.threshold_window_minutes)
      setOriginalThresholdWindowMinutes(rule.threshold_window_minutes)
      setThresholdGroupBy(rule.threshold_group_by)
      setOriginalThresholdGroupBy(rule.threshold_group_by)
      // Store rule versions for current version display
      setRuleVersions(rule.versions || null)

      // Fetch activity data to get user emails for version authors
      if (!isNew && rule.versions && rule.versions.length > 0) {
        try {
          const activityData = await rulesApi.getActivity(id)
          // Create map: user_id -> email from activity data
          const usersMap: Record<string, { email: string }> = {}
          activityData.forEach((activity: Record<string, unknown>) => {
            if (activity.type === 'version' && activity.data && activity.user_email) {
              // The version's changed_by should match an activity entry
              const data = activity.data as { version_number?: number }
              const versionNum = data.version_number
              if (versionNum) {
                const version = rule.versions.find((v: RuleVersion) => v.version_number === versionNum)
                if (version) {
                  usersMap[version.changed_by] = { email: activity.user_email as string }
                }
              }
            }
          })
          setUsers(usersMap)
        } catch (err) {
          console.error('Failed to load activity data for user emails:', err)
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rule')
    } finally {
      setIsLoading(false)
    }
  }, [id, isNew])

  const loadAvailableFields = async () => {
    if (!indexPatternId) return

    setIsLoadingFields(true)
    try {
      const data = await rulesApi.getIndexFields(indexPatternId)
      setAvailableFields(data.fields)
    } catch (err) {
      console.error('Failed to load fields', err)
    } finally {
      setIsLoadingFields(false)
    }
  }

  // Effects - must come after all useCallback declarations
  useEffect(() => {
    loadIndexPatterns()
    if (!isNew) {
      loadRule()
      loadExceptions()
      loadCorrelationRules()
    }
  }, [id, isNew, loadIndexPatterns, loadRule, loadExceptions, loadCorrelationRules])

  // Reset deployment state when rule ID changes (fixes clone showing as deployed)
  useEffect(() => {
    setDeployedAt(null)
    setDeployedVersion(null)
    setCurrentVersionNumber(1)
    setNeedsRedeploy(false)
    setStatus('undeployed')
    setSnoozeIndefinite(false)
    setSnoozeUntil(null)
  }, [id])

  // Load available fields for group_by dropdown when index pattern changes
  useEffect(() => {
    const loadGroupByFields = async () => {
      if (!indexPatternId) {
        setAvailableGroupByFields([])
        return
      }

      setIsLoadingGroupByFields(true)
      try {
        const data = await rulesApi.getIndexFields(indexPatternId)
        setAvailableGroupByFields(data.fields || [])
      } catch (err) {
        console.error('Failed to load index fields:', err)
        setAvailableGroupByFields([])
      } finally {
        setIsLoadingGroupByFields(false)
      }
    }

    loadGroupByFields()
  }, [indexPatternId])

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

  // Load available fields when index pattern changes
  useEffect(() => {
    loadAvailableFields()
  }, [indexPatternId])

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

  // Debounced validation
  useEffect(() => {
    const timer = setTimeout(() => {
      if (yamlContent.trim()) {
        validateRule()
      }
    }, 500)
    return () => clearTimeout(timer)
  }, [yamlContent, indexPatternId, validateRule])

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

  // Check if YAML has changes from original
  const hasChanges = () => {
    // Only consider YAML changes - threshold changes now apply immediately with change reason
    return yamlContent !== originalYaml
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
        // Threshold settings apply immediately via dedicated endpoint - don't include in general update
        await rulesApi.update(id!, {
          title,
          description: description || undefined,
          yaml_content: yamlContent,
          severity,
          status,
          index_pattern_id: indexPatternId,
          change_reason: changeReason || 'Updated',
        })
        // Reload rule to get updated version
        if (id) {
          await loadRule()
        }
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

  const handleDeploy = () => {
    if (!id) return
    setDeployReason('')
    setShowDeployReason(true)
  }

  const handleDeployConfirm = async () => {
    if (!id || !deployReason.trim()) return
    setShowDeployReason(false)
    setIsDeploying(true)
    setDeployError('')
    try {
      const result = await rulesApi.deploy(id, deployReason)
      setDeployedAt(result.deployed_at)
      setDeployedVersion(result.deployed_version)
      setNeedsRedeploy(false)
      // Update status to deployed (unless already snoozed)
      if (status !== 'snoozed') {
        setStatus('deployed')
      }
      setDeployReason('')
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

  const handleUndeploy = () => {
    if (!id) return
    setDeployReason('')
    setShowUndeployReason(true)
  }

  const handleUndeployConfirm = async () => {
    if (!id || !deployReason.trim()) return
    setShowUndeployReason(false)
    setIsDeploying(true)
    setDeployError('')
    try {
      await rulesApi.undeploy(id, deployReason)
      setDeployedAt(null)
      setDeployedVersion(null)
      setStatus('undeployed')
      // Clear snooze state as well (backend does this too)
      setSnoozeUntil(null)
      setSnoozeIndefinite(false)
      setDeployReason('')
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Undeploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  // Exception handlers
  const handleAddException = () => {
    if (!id || !newExceptionField.trim() || !newExceptionValue.trim()) {
      setError('Field and value are required for exceptions')
      return
    }
    // Show change reason dialog
    setExceptionChangeReason('')
    setShowExceptionCreateReason(true)
  }

  const handleAddExceptionConfirm = async () => {
    if (!id || !exceptionChangeReason.trim()) return
    setShowExceptionCreateReason(false)
    setIsAddingException(true)
    try {
      const data: RuleExceptionCreate = {
        field: newExceptionField.trim(),
        operator: newExceptionOperator,
        value: newExceptionValue.trim(),
        reason: newExceptionReason.trim() || undefined,
        change_reason: exceptionChangeReason.trim(),
      }
      const newException = await rulesApi.createException(id, data)
      setExceptions((prev) => [...prev, newException])
      // Reset form
      setNewExceptionField('')
      setNewExceptionOperator('equals')
      setNewExceptionValue('')
      setNewExceptionReason('')
      setExceptionChangeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add exception')
    } finally {
      setIsAddingException(false)
    }
  }

  const handleToggleException = (exceptionId: string, isActive: boolean) => {
    if (!id) return
    // Show change reason dialog
    setPendingExceptionToggle({ id: exceptionId, isActive })
    setExceptionChangeReason('')
    setShowExceptionToggleReason(true)
  }

  const handleToggleExceptionConfirm = async () => {
    if (!id || !pendingExceptionToggle || !exceptionChangeReason.trim()) return
    setShowExceptionToggleReason(false)
    try {
      const updated = await rulesApi.updateException(id, pendingExceptionToggle.id, {
        is_active: pendingExceptionToggle.isActive,
        change_reason: exceptionChangeReason.trim(),
      })
      setExceptions((prev) =>
        prev.map((e) => (e.id === pendingExceptionToggle.id ? updated : e))
      )
      setPendingExceptionToggle(null)
      setExceptionChangeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update exception')
    }
  }

  // Threshold toggle handler - shows change reason dialog
  const handleThresholdToggle = (enabled: boolean) => {
    if (!id || isNew) {
      // For new rules, just update state (will be saved with the rule)
      setThresholdEnabled(enabled)
      return
    }
    // For existing rules, show change reason dialog
    setPendingThresholdEnabled(enabled)
    setThresholdChangeReason('')
    setShowThresholdReason(true)
  }

  // Confirm threshold toggle with change reason
  const handleThresholdToggleConfirm = async () => {
    if (!id || pendingThresholdEnabled === null || !thresholdChangeReason.trim()) return
    setIsUpdatingThreshold(true)
    try {
      const result = await rulesApi.updateThreshold(
        id,
        pendingThresholdEnabled,
        thresholdChangeReason.trim(),
        pendingThresholdEnabled ? thresholdCount : null,
        pendingThresholdEnabled ? thresholdWindowMinutes : null,
        pendingThresholdEnabled ? thresholdGroupBy : null
      )
      // Update state with response
      setThresholdEnabled(result.threshold_enabled)
      setThresholdCount(result.threshold_count)
      setOriginalThresholdCount(result.threshold_count)
      setThresholdWindowMinutes(result.threshold_window_minutes)
      setOriginalThresholdWindowMinutes(result.threshold_window_minutes)
      setThresholdGroupBy(result.threshold_group_by)
      setOriginalThresholdGroupBy(result.threshold_group_by)
      // Close dialog
      setShowThresholdReason(false)
      setPendingThresholdEnabled(null)
      setThresholdChangeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update threshold settings')
    } finally {
      setIsUpdatingThreshold(false)
    }
  }

  // Check if threshold fields have changed from saved values
  const hasThresholdFieldChanges = useMemo(() => {
    if (!thresholdEnabled) return false // No changes if threshold is disabled
    return (
      thresholdCount !== originalThresholdCount ||
      thresholdWindowMinutes !== originalThresholdWindowMinutes ||
      thresholdGroupBy !== originalThresholdGroupBy
    )
  }, [thresholdEnabled, thresholdCount, originalThresholdCount, thresholdWindowMinutes, originalThresholdWindowMinutes, thresholdGroupBy, originalThresholdGroupBy])

  // Apply threshold field changes (count, window, group_by)
  const handleApplyThresholdFields = async () => {
    if (!id || isNew || !thresholdChangeReason.trim()) return
    setIsUpdatingThreshold(true)
    try {
      const result = await rulesApi.updateThreshold(
        id,
        thresholdEnabled,
        thresholdChangeReason.trim(),
        thresholdCount,
        thresholdWindowMinutes,
        thresholdGroupBy
      )
      // Update original values to match
      setOriginalThresholdCount(result.threshold_count)
      setOriginalThresholdWindowMinutes(result.threshold_window_minutes)
      setOriginalThresholdGroupBy(result.threshold_group_by)
      // Close dialog
      setShowThresholdReason(false)
      setThresholdChangeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update threshold settings')
    } finally {
      setIsUpdatingThreshold(false)
    }
  }

  // Show dialog for applying threshold field changes
  const handleApplyThresholdClick = () => {
    setThresholdChangeReason('')
    setPendingThresholdEnabled(null) // null indicates field changes, not toggle
    setShowThresholdReason(true)
  }

  const openDeleteExceptionDialog = (exception: RuleException) => {
    setExceptionToDelete(exception)
    setExceptionChangeReason('')
    setShowExceptionDeleteReason(true)
  }

  const confirmDeleteException = async () => {
    if (!id || !exceptionToDelete || !exceptionChangeReason.trim()) return
    setIsDeletingException(true)
    try {
      await rulesApi.deleteException(id, exceptionToDelete.id, exceptionChangeReason.trim())
      setExceptions((prev) => prev.filter((e) => e.id !== exceptionToDelete.id))
      setShowExceptionDeleteReason(false)
      setExceptionToDelete(null)
      setExceptionChangeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete exception')
    } finally {
      setIsDeletingException(false)
    }
  }

  // Snooze handlers
  const handleSnooze = (hours: number) => {
    if (!id || !canManageRules) return
    setPendingSnoozeHours(hours)
    setPendingSnoozeIndefinite(false)
    setSnoozeReason('')
    setShowSnoozeReason(true)
  }

  const handleSnoozeIndefinite = () => {
    if (!id || !canManageRules) return
    setPendingSnoozeHours(undefined)
    setPendingSnoozeIndefinite(true)
    setSnoozeReason('')
    setShowSnoozeReason(true)
  }

  const handleSnoozeConfirm = async () => {
    if (!id || !snoozeReason.trim()) return
    setShowSnoozeReason(false)
    setIsSnoozing(true)
    try {
      const result = await rulesApi.snooze(id, snoozeReason, pendingSnoozeHours, pendingSnoozeIndefinite)
      setStatus('snoozed')
      setSnoozeUntil(result.snooze_until)
      setSnoozeIndefinite(result.snooze_indefinite)
      setSnoozeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to snooze rule')
    } finally {
      setIsSnoozing(false)
    }
  }

  const handleUnsnooze = () => {
    if (!id) return
    setSnoozeReason('')
    setShowUnsnoozeReason(true)
  }

  const handleUnsnoozeConfirm = async () => {
    if (!id || !snoozeReason.trim()) return
    setShowUnsnoozeReason(false)
    setIsSnoozing(true)
    try {
      await rulesApi.unsnooze(id, snoozeReason)
      setStatus('deployed')  // Unsnooze returns to deployed state
      setSnoozeUntil(null)
      setSnoozeIndefinite(false)
      setSnoozeReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unsnooze rule')
    } finally {
      setIsSnoozing(false)
    }
  }

  // Restore version handler for activity panel
  const handleRestoreVersion = async (versionNumber: number, reason: string) => {
    try {
      await rulesApi.rollback(id!, versionNumber, reason)
      // Reload the rule to get the new version
      await loadRule()
      setIsActivityOpen(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore version')
    }
  }

  // Clone rule handler
  const handleClone = () => {
    if (!canManageRules) return
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

  // Delete rule handler - show reason dialog
  const handleDeleteRule = () => {
    if (!id || !canManageRules) return
    setDeleteReason('')
    setShowDeleteReason(true)
  }

  // Confirm delete rule with reason
  const handleDeleteRuleConfirm = async () => {
    if (!id || !deleteReason.trim()) return
    setShowDeleteReason(false)
    setIsDeletingRule(true)
    try {
      await rulesApi.delete(id, deleteReason.trim())
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
    <TooltipProvider>
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
              <p className={`text-xs ${deployedVersion === currentVersionNumber ? 'text-green-600' : 'text-yellow-600'}`}>
                {deployedVersion === currentVersionNumber
                  ? `Deployed v${deployedVersion}`
                  : `Deployed v${deployedVersion} (current is v${currentVersionNumber} - redeploy needed)`
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
            <div className="flex items-center gap-2">
              {status === 'snoozed' ? (
                <>
                  <Clock className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm text-yellow-600">
                    {snoozeIndefinite ? 'Snoozed indefinitely' : snoozeUntil ? `Snoozed until ${formatSnoozeExpiry(snoozeUntil)}` : 'Snoozed'}
                  </span>
                  <Button
                    variant="outline"
                    onClick={handleUnsnooze}
                    disabled={isSnoozing || !canManageRules}
                  >
                    {isSnoozing ? 'Unsnoozing...' : 'Unsnooze'}
                  </Button>
                </>
              ) : status === 'undeployed' ? (
                <>
                  <span className="text-sm text-gray-500 font-medium">Undeployed</span>
                  <Button
                    variant="outline"
                    disabled
                    title="Deploy the rule first to enable snooze"
                  >
                    <Clock className="h-4 w-4 mr-1" />
                    Snooze
                  </Button>
                </>
              ) : (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" disabled={isSnoozing || !canManageRules}>
                      <Clock className="h-4 w-4 mr-1" />
                      Snooze
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className="z-50 bg-popover">
                    <DropdownMenuItem onClick={() => handleSnooze(1)} disabled={!canManageRules}>1 hour</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleSnooze(4)} disabled={!canManageRules}>4 hours</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleSnooze(8)} disabled={!canManageRules}>8 hours</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleSnooze(24)} disabled={!canManageRules}>24 hours</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleSnooze(168)} disabled={!canManageRules}>1 week</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleSnoozeIndefinite()} disabled={!canManageRules}>Indefinitely</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
          )}
          {saveSuccess && (
            <span className="text-sm text-green-600 flex items-center gap-1 mr-2">
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
                <DropdownMenuItem onClick={handleClone} disabled={!canManageRules}>
                  <Copy className="mr-2 h-4 w-4" /> Clone Rule
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleExportYaml}>
                  <Download className="mr-2 h-4 w-4" /> Export YAML
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={handleDeleteRule}
                  className="text-destructive focus:text-destructive"
                  disabled={!canManageRules}
                >
                  <Trash2 className="mr-2 h-4 w-4" /> Delete Rule
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {!isNew && (
            deployedAt ? (
              <>
                {deployedVersion !== currentVersionNumber && (
                  <Button
                    variant="outline"
                    onClick={handleDeploy}
                    disabled={isDeploying || !isValid || !canManageRules}
                  >
                    <Rocket className="h-4 w-4 mr-2" />
                    {isDeploying ? 'Deploying...' : 'Redeploy'}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={handleUndeploy}
                  disabled={isDeploying || !canManageRules}
                >
                  <RotateCcw className="h-4 w-4 mr-2" />
                  {isDeploying ? 'Undeploying...' : 'Undeploy'}
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                onClick={handleDeploy}
                disabled={isDeploying || !isValid || !canManageRules}
              >
                <Rocket className="h-4 w-4 mr-2" />
                {isDeploying ? 'Deploying...' : 'Deploy'}
              </Button>
            )
          )}
          <Button onClick={handleSave} disabled={isSaving || !isValid || (!isNew && !hasChanges()) || !canManageRules}>
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
            disabled={isDeploying || !canManageRules}
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
              disabled={!canManageRules}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Index Pattern</Label>
              <Select value={indexPatternId} onValueChange={canManageRules ? setIndexPatternId : undefined} disabled={!canManageRules}>
                <SelectTrigger disabled={!canManageRules}>
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
              <Select value={severity} onValueChange={canManageRules ? handleSeverityChange : undefined} disabled={!canManageRules}>
                <SelectTrigger disabled={!canManageRules}>
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
                disabled={!canManageRules}
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
              readOnly={!canManageRules}
            />
          </div>
        </div>

        {/* Side Panel - 1 column */}
        <div className="space-y-4">
          {/* Validation Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <TestTube className="h-4 w-4 text-muted-foreground" />
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

          {/* Current Version Info Card - Only for existing rules */}
          {!isNew && currentVersion && (
            <Card>
              <CardHeader className="py-3">
                <CardTitle className="text-sm font-medium">Current Version</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="space-y-1 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Version:</span>
                    <span className="font-medium">v{currentVersion.version_number}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Last updated:</span>
                    <TimestampTooltip timestamp={currentVersion.created_at}>
                      <span className="text-muted-foreground">{formatDistanceToNow(new Date(currentVersion.created_at), { addSuffix: true })}</span>
                    </TimestampTooltip>
                  </div>
                  {currentVersion.changed_by && (
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Changed by:</span>
                      <span className="text-muted-foreground">
                        {users[currentVersion.changed_by]?.email || currentVersion.changed_by}
                      </span>
                    </div>
                  )}
                </div>
                {currentVersion.change_reason && (
                  <div className="mt-2 pt-2 border-t">
                    <div className="text-xs text-muted-foreground mb-1">Change reason:</div>
                    <p className="text-sm italic">"{currentVersion.change_reason}"</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Test Card */}
          <Card>
            <CardHeader
              className="py-3 cursor-pointer"
              onClick={() => setShowTest(!showTest)}
            >
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Beaker className="h-4 w-4 text-muted-foreground" />
                  <span>Test Rule</span>
                </div>
                {showTest ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </CardTitle>
            </CardHeader>
            {showTest && (
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
            )}
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
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                  <span>Threshold Alerting</span>
                </div>
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
                    onCheckedChange={canManageRules ? handleThresholdToggle : undefined}
                    disabled={!canManageRules}
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
                          disabled={!canManageRules}
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
                          disabled={!canManageRules}
                        />
                      </div>
                    </div>
                    <div className="space-y-1">
                      <SearchableFieldSelector
                        fields={availableGroupByFields}
                        value={thresholdGroupBy}
                        onChange={setThresholdGroupBy}
                        label="Group by field (optional)"
                        placeholder="Select field..."
                        description="Count matches separately per unique value of this field"
                        disabled={!canManageRules}
                        isLoading={isLoadingGroupByFields}
                        emptyMessage={indexPatternId ? 'No fields available for this index pattern' : 'Select an index pattern first'}
                      />
                    </div>
                    {/* Apply button - always show for existing rules, disabled when no changes */}
                    {!isNew && canManageRules && (
                      <div className="pt-2 border-t">
                        <Button
                          size="sm"
                          onClick={handleApplyThresholdClick}
                          disabled={isUpdatingThreshold || !hasThresholdFieldChanges}
                        >
                          {isUpdatingThreshold ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Applying...
                            </>
                          ) : (
                            'Apply Changes'
                          )}
                        </Button>
                      </div>
                    )}
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
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                    <span>Exceptions</span>
                    {isLoadingExceptions && (
                      <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                    )}
                    {exceptions.length > 0 && (
                      <span className="text-xs text-muted-foreground font-normal">
                        ({exceptions.length})
                      </span>
                    )}
                  </div>
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
                                onCheckedChange={canManageRules ? (checked) =>
                                  handleToggleException(exception.id, checked)
                                : undefined}
                                disabled={!canManageRules}
                              />
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                disabled={!canManageRules}
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
                      <SearchableFieldSelector
                        fields={availableFields}
                        value={newExceptionField}
                        onChange={canManageRules ? setNewExceptionField : undefined}
                        placeholder="Select a field..."
                        disabled={!canManageRules}
                        isLoading={isLoadingFields}
                        emptyMessage={indexPatternId ? 'No fields available for this index pattern' : 'Select an index pattern first'}
                      />
                      <Select
                        value={newExceptionOperator}
                        onValueChange={canManageRules ? (value) =>
                          setNewExceptionOperator(value as ExceptionOperator)
                        : undefined}
                        disabled={!canManageRules}
                      >
                        <SelectTrigger className="h-8 text-sm" disabled={!canManageRules}>
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
                        disabled={!canManageRules}
                      />
                      <Input
                        placeholder="Reason (optional)"
                        value={newExceptionReason}
                        onChange={(e) => setNewExceptionReason(e.target.value)}
                        className="h-8 text-sm"
                        disabled={!canManageRules}
                      />
                      <Button
                        size="sm"
                        onClick={handleAddException}
                        disabled={
                          isAddingException ||
                          !newExceptionField.trim() ||
                          !newExceptionValue.trim() ||
                          !canManageRules
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
                  <div className="flex items-center gap-2">
                    <GitCompare className="h-4 w-4 text-muted-foreground" />
                    <span>Correlation Rules</span>
                    {isLoadingCorrelations && (
                      <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                    )}
                    {correlationRules.length > 0 && (
                      <span className="text-xs text-muted-foreground font-normal">
                        ({correlationRules.length})
                      </span>
                    )}
                  </div>
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

      {/* Exception Create Reason Dialog */}
      <Dialog open={showExceptionCreateReason} onOpenChange={setShowExceptionCreateReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Exception</DialogTitle>
            <DialogDescription>
              Please explain why you're adding this exception. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="text-sm">
              <div className="font-medium">{newExceptionField}</div>
              <div className="text-muted-foreground">
                {operatorLabels[newExceptionOperator]}: {newExceptionValue}
              </div>
              {newExceptionReason && (
                <div className="text-muted-foreground mt-1 italic">
                  Reason: {newExceptionReason}
                </div>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="exception-create-reason">Change Reason *</Label>
              <Textarea
                id="exception-create-reason"
                placeholder="e.g., Adding exception for known false positive..."
                value={exceptionChangeReason}
                onChange={(e) => setExceptionChangeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowExceptionCreateReason(false)
                setExceptionChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddExceptionConfirm}
              disabled={!exceptionChangeReason.trim() || isAddingException}
            >
              {isAddingException ? 'Adding...' : 'Add Exception'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Exception Toggle Reason Dialog */}
      <Dialog open={showExceptionToggleReason} onOpenChange={setShowExceptionToggleReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pendingExceptionToggle?.isActive ? 'Enable' : 'Disable'} Exception
            </DialogTitle>
            <DialogDescription>
              Please explain why you're {pendingExceptionToggle?.isActive ? 'enabling' : 'disabling'} this exception.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {pendingExceptionToggle && (() => {
              const exception = exceptions.find(e => e.id === pendingExceptionToggle.id)
              return exception ? (
                <div className="text-sm">
                  <div className="font-medium">{exception.field}</div>
                  <div className="text-muted-foreground">
                    {operatorLabels[exception.operator]}: {exception.value}
                  </div>
                </div>
              ) : null
            })()}
            <div className="space-y-2">
              <Label htmlFor="exception-toggle-reason">Change Reason *</Label>
              <Textarea
                id="exception-toggle-reason"
                placeholder={pendingExceptionToggle?.isActive
                  ? "e.g., Re-enabling after investigation..."
                  : "e.g., Temporarily disabling for testing..."}
                value={exceptionChangeReason}
                onChange={(e) => setExceptionChangeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowExceptionToggleReason(false)
                setPendingExceptionToggle(null)
                setExceptionChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleToggleExceptionConfirm}
              disabled={!exceptionChangeReason.trim()}
            >
              {pendingExceptionToggle?.isActive ? 'Enable' : 'Disable'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Exception Delete Reason Dialog */}
      <Dialog open={showExceptionDeleteReason} onOpenChange={setShowExceptionDeleteReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Exception</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this exception? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {exceptionToDelete && (
              <div className="text-sm p-3 bg-muted rounded-md">
                <div className="font-medium">{exceptionToDelete.field}</div>
                <div className="text-muted-foreground">
                  {operatorLabels[exceptionToDelete.operator]}: {exceptionToDelete.value}
                </div>
                {exceptionToDelete.reason && (
                  <div className="text-muted-foreground mt-1 italic">
                    Reason: {exceptionToDelete.reason}
                  </div>
                )}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="exception-delete-reason">Change Reason *</Label>
              <Textarea
                id="exception-delete-reason"
                placeholder="e.g., Exception no longer needed, false positive resolved..."
                value={exceptionChangeReason}
                onChange={(e) => setExceptionChangeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowExceptionDeleteReason(false)
                setExceptionToDelete(null)
                setExceptionChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDeleteException}
              disabled={!exceptionChangeReason.trim() || isDeletingException}
            >
              {isDeletingException ? 'Deleting...' : 'Delete Exception'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Threshold Change Reason Dialog */}
      <Dialog open={showThresholdReason} onOpenChange={setShowThresholdReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pendingThresholdEnabled !== null
                ? (pendingThresholdEnabled ? 'Enable Threshold Alerting' : 'Disable Threshold Alerting')
                : 'Update Threshold Settings'
              }
            </DialogTitle>
            <DialogDescription>
              {pendingThresholdEnabled !== null
                ? `Please provide a reason for ${pendingThresholdEnabled ? 'enabling' : 'disabling'} threshold alerting.`
                : 'Please provide a reason for changing threshold settings.'
              }
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {pendingThresholdEnabled === null && (
              <div className="text-sm p-3 bg-muted rounded-md space-y-1">
                <div className="font-medium">Changes:</div>
                {thresholdCount !== originalThresholdCount && (
                  <div className="text-muted-foreground">
                    Count: {originalThresholdCount ?? 'not set'} → {thresholdCount ?? 'not set'}
                  </div>
                )}
                {thresholdWindowMinutes !== originalThresholdWindowMinutes && (
                  <div className="text-muted-foreground">
                    Window: {originalThresholdWindowMinutes ?? 'not set'} → {thresholdWindowMinutes ?? 'not set'} minutes
                  </div>
                )}
                {thresholdGroupBy !== originalThresholdGroupBy && (
                  <div className="text-muted-foreground">
                    Group by: {originalThresholdGroupBy || 'none'} → {thresholdGroupBy || 'none'}
                  </div>
                )}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="threshold-reason">Change Reason *</Label>
              <Textarea
                id="threshold-reason"
                placeholder="e.g., Adjusting threshold to reduce noise..."
                value={thresholdChangeReason}
                onChange={(e) => setThresholdChangeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowThresholdReason(false)
                setPendingThresholdEnabled(null)
                setThresholdChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={pendingThresholdEnabled !== null ? handleThresholdToggleConfirm : handleApplyThresholdFields}
              disabled={!thresholdChangeReason.trim() || isUpdatingThreshold}
            >
              {isUpdatingThreshold ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Applying...
                </>
              ) : (
                pendingThresholdEnabled !== null
                  ? (pendingThresholdEnabled ? 'Enable' : 'Disable')
                  : 'Apply Changes'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rule Delete Reason Dialog */}
      <Dialog open={showDeleteReason} onOpenChange={setShowDeleteReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Rule</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{title}"? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="delete-reason">Reason for Deletion *</Label>
              <Textarea
                id="delete-reason"
                placeholder="e.g., Rule is no longer needed, replaced by another rule..."
                value={deleteReason}
                onChange={(e) => setDeleteReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowDeleteReason(false)
                setDeleteReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteRuleConfirm}
              disabled={!deleteReason.trim() || isDeletingRule}
            >
              {isDeletingRule ? 'Deleting...' : 'Delete Rule'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Activity Panel */}
      {!isNew && (
        <ActivityPanel
          ruleId={id!}
          currentYaml={yamlContent}
          currentVersion={currentVersion?.version_number ?? 1}
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

      {/* Deploy Reason Modal */}
      <Dialog open={showDeployReason} onOpenChange={setShowDeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're deploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="deploy-reason">Reason for Deploy *</Label>
              <Textarea
                id="deploy-reason"
                placeholder="e.g., Ready for production, completed testing..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowDeployReason(false)
                setDeployReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleDeployConfirm}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Deploying...' : 'Deploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Undeploy Reason Modal */}
      <Dialog open={showUndeployReason} onOpenChange={setShowUndeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Undeploy Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're undeploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="undeploy-reason">Reason for Undeploy *</Label>
              <Textarea
                id="undeploy-reason"
                placeholder="e.g., False positives, needs revision, no longer needed..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowUndeployReason(false)
                setDeployReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleUndeployConfirm}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Undeploying...' : 'Undeploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Snooze Reason Modal */}
      <Dialog open={showSnoozeReason} onOpenChange={setShowSnoozeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Snooze Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're snoozing this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="text-sm text-muted-foreground">
              Snoozing for: {pendingSnoozeIndefinite ? 'Indefinitely' : `${pendingSnoozeHours} hour${pendingSnoozeHours !== 1 ? 's' : ''}`}
            </div>
            <div className="space-y-2">
              <Label htmlFor="snooze-reason">Reason for Snooze *</Label>
              <Textarea
                id="snooze-reason"
                placeholder="e.g., Investigating false positives, scheduled maintenance..."
                value={snoozeReason}
                onChange={(e) => setSnoozeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowSnoozeReason(false)
                setSnoozeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSnoozeConfirm}
              disabled={!snoozeReason.trim() || isSnoozing}
            >
              {isSnoozing ? 'Snoozing...' : 'Snooze'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Unsnooze Reason Modal */}
      <Dialog open={showUnsnoozeReason} onOpenChange={setShowUnsnoozeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unsnooze Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're unsnoozing this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="unsnooze-reason">Reason for Unsnooze *</Label>
              <Textarea
                id="unsnooze-reason"
                placeholder="e.g., Investigation complete, issue resolved..."
                value={snoozeReason}
                onChange={(e) => setSnoozeReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowUnsnoozeReason(false)
                setSnoozeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleUnsnoozeConfirm}
              disabled={!snoozeReason.trim() || isSnoozing}
            >
              {isSnoozing ? 'Unsnoozing...' : 'Unsnooze'}
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
    </TooltipProvider>
  )
}
