import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { alertsApi, alertCommentsApi, correlationRulesApi, rulesApi, Alert, AlertComment, AlertStatus, TIEnrichmentIndicator, CorrelationRule, ExceptionOperator } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { useAuth } from '@/hooks/use-auth'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { ArrowLeft, AlertTriangle, ChevronDown, Clock, User, FileText, Globe, ShieldAlert, Link as LinkIcon, Link2, Loader2, Trash2, Plus, X, ShieldX } from 'lucide-react'
import { TimestampTooltip } from '../components/timestamp-tooltip'
import { SearchableFieldSelector } from '@/components/SearchableFieldSelector'

// Type for exception conditions (for AND grouping)
type ExceptionCondition = {
  id: string
  field: string
  operator: ExceptionOperator
  value: string
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const statusColors: Record<AlertStatus, string> = {
  new: 'bg-blue-500 text-white',
  acknowledged: 'bg-yellow-500 text-black',
  resolved: 'bg-green-500 text-white',
  false_positive: 'bg-gray-500 text-white',
}

const statusLabels: Record<AlertStatus, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

// TI Risk level colors
const riskLevelColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  safe: 'bg-green-500 text-white',
  unknown: 'bg-gray-500 text-white',
}

// TI Indicator type icons/labels
const indicatorTypeLabels: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash_md5: 'MD5 Hash',
  hash_sha1: 'SHA1 Hash',
  hash_sha256: 'SHA256 Hash',
}

// TI Enrichment card component
function TIEnrichmentCard({ indicators }: { indicators: TIEnrichmentIndicator[] }) {
  const [expandedIndicator, setExpandedIndicator] = useState<string | null>(null)

  // Sort by risk level (critical first)
  const sortedIndicators = [...indicators].sort((a, b) => {
    const order = ['critical', 'high', 'medium', 'low', 'safe', 'unknown']
    return order.indexOf(a.overall_risk_level) - order.indexOf(b.overall_risk_level)
  })

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <ShieldAlert className="h-4 w-4" />
          Threat Intelligence
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {sortedIndicators.map((indicator) => (
          <Collapsible
            key={`${indicator.indicator_type}-${indicator.indicator}`}
            open={expandedIndicator === indicator.indicator}
            onOpenChange={(open) =>
              setExpandedIndicator(open ? indicator.indicator : null)
            }
          >
            <CollapsibleTrigger className="w-full">
              <div className="flex items-center justify-between text-sm hover:bg-muted/50 rounded p-2 -m-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge
                    className={`text-xs shrink-0 ${
                      riskLevelColors[indicator.overall_risk_level] || riskLevelColors.unknown
                    }`}
                  >
                    {capitalize(indicator.overall_risk_level)}
                  </Badge>
                  <span className="truncate font-mono text-xs">
                    {indicator.indicator}
                  </span>
                </div>
                <ChevronDown
                  className={`h-4 w-4 shrink-0 transition-transform ${
                    expandedIndicator === indicator.indicator ? 'rotate-180' : ''
                  }`}
                />
              </div>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="mt-2 pl-2 border-l-2 border-muted space-y-2 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-muted-foreground">Type:</span>
                    <span className="ml-1">
                      {indicatorTypeLabels[indicator.indicator_type] || indicator.indicator_type}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Risk Score:</span>
                    <span className="ml-1">{indicator.overall_risk_score?.toFixed(0) ?? 'N/A'}/100</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Sources:</span>
                    <span className="ml-1">
                      {indicator.sources_with_results}/{indicator.sources_queried}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Detections:</span>
                    <span className="ml-1">{indicator.sources_with_detections}</span>
                  </div>
                </div>
                {indicator.all_categories.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Categories:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {indicator.all_categories.map((cat) => (
                        <Badge key={cat} variant="outline" className="text-xs">
                          {cat}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {indicator.all_tags.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Tags:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {indicator.all_tags.slice(0, 10).map((tag) => (
                        <Badge key={tag} variant="secondary" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                      {indicator.all_tags.length > 10 && (
                        <Badge variant="secondary" className="text-xs">
                          +{indicator.all_tags.length - 10} more
                        </Badge>
                      )}
                    </div>
                  </div>
                )}
                {indicator.highest_risk_source && (
                  <div>
                    <span className="text-muted-foreground">Highest risk from:</span>
                    <span className="ml-1 capitalize">{indicator.highest_risk_source}</span>
                  </div>
                )}
              </div>
            </CollapsibleContent>
          </Collapsible>
        ))}
        {sortedIndicators.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No threat intelligence data available
          </p>
        )}
      </CardContent>
    </Card>
  )
}

// Correlation Alert Details card component
function CorrelationAlertDetails({ logDocument }: { logDocument: Record<string, unknown> }) {
  const correlationData = logDocument.correlation as {
    correlation_rule_id?: string
    correlation_name?: string
    source_alerts?: Array<{ alert_id: string; rule_title: string; timestamp: string }>
    entity_field?: string
    entity_value?: string
  }

  if (!correlationData) {
    return null
  }

  return (
    <Card className="border-purple-200 dark:border-purple-900">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Link2 className="h-4 w-4 text-purple-600 dark:text-purple-400" />
          <span className="text-purple-700 dark:text-purple-300">Correlation Alert</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-muted-foreground">Entity Field:</span>
            <div className="font-mono font-medium">{correlationData.entity_field || 'N/A'}</div>
          </div>
          <div>
            <span className="text-muted-foreground">Entity Value:</span>
            <div className="font-mono font-medium">{correlationData.entity_value || 'N/A'}</div>
          </div>
        </div>

        {correlationData.source_alerts && correlationData.source_alerts.length > 0 && (
          <div>
            <div className="text-muted-foreground mb-2">Source Alerts:</div>
            <div className="space-y-2">
              {correlationData.source_alerts.map((sourceAlert, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 bg-muted rounded text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-medium">{idx + 1}.</span>
                    <span className="truncate">{sourceAlert.rule_title}</span>
                  </div>
                  <Link
                    to={`/alerts/${sourceAlert.alert_id}`}
                    className="text-primary hover:underline text-xs shrink-0"
                  >
                    View
                  </Link>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="text-xs text-muted-foreground">
          This alert was triggered when multiple detection rules matched within the configured time window for the same entity value.
        </div>
      </CardContent>
    </Card>
  )
}

// Correlation Info card component
function CorrelationInfoCard({ correlations, ruleId }: { correlations: CorrelationRule[], ruleId: string }) {
  if (correlations.length === 0) {
    return null
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <LinkIcon className="h-4 w-4" />
          Correlation Rules ({correlations.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          This alert is part of {correlations.length} correlation rule(s) that detect patterns across multiple events.
        </p>
        {correlations.map((correlation) => (
          <div
            key={correlation.id}
            className="p-3 border rounded-md space-y-2 hover:bg-muted/50 transition-colors"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <div className="text-sm font-medium truncate">
                    {correlation.name}
                  </div>
                  {!correlation.deployed_at && (
                    <span className="text-xs text-muted-foreground">(Not Deployed)</span>
                  )}
                  <Badge
                    className={`text-xs ${
                      severityColors[correlation.severity] || 'bg-gray-500 text-white'
                    }`}
                  >
                    {correlation.severity}
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  <div>Correlates with:</div>
                  <div className="font-mono">
                    {correlation.rule_a_id === ruleId
                      ? (correlation.rule_b_title || correlation.rule_b_id)
                      : (correlation.rule_a_title || correlation.rule_a_id)}
                  </div>
                  <div className="mt-1">
                    Entity: <span className="font-mono">{correlation.entity_field}</span> • Window: {correlation.time_window_minutes} min
                  </div>
                </div>
              </div>
              <Link
                to={`/correlation/${correlation.id}`}
                className="shrink-0 text-xs text-primary hover:underline"
              >
                View Rule
              </Link>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

// GeoIP data extraction helper
interface GeoIPEntry {
  field: string
  ip: string
  country?: string
  city?: string
  coordinates?: { lat: number; lon: number }
}

function extractGeoIPData(doc: Record<string, unknown>): GeoIPEntry[] {
  const entries: GeoIPEntry[] = []

  // Helper to get nested value
  const getNestedValue = (obj: Record<string, unknown>, path: string): unknown => {
    return path.split('.').reduce((acc: unknown, key) => {
      if (acc && typeof acc === 'object' && key in (acc as Record<string, unknown>)) {
        return (acc as Record<string, unknown>)[key]
      }
      return undefined
    }, obj)
  }

  // Common patterns for GeoIP enriched fields
  const geoPatterns = [
    { ipField: 'source.ip', geoPrefix: 'source.geo' },
    { ipField: 'destination.ip', geoPrefix: 'destination.geo' },
    { ipField: 'client.ip', geoPrefix: 'client.geo' },
    { ipField: 'server.ip', geoPrefix: 'server.geo' },
    { ipField: 'host.ip', geoPrefix: 'host.geo' },
  ]

  for (const pattern of geoPatterns) {
    const ip = getNestedValue(doc, pattern.ipField)
    const country = getNestedValue(doc, `${pattern.geoPrefix}.country_name`) as string | undefined
    const city = getNestedValue(doc, `${pattern.geoPrefix}.city_name`) as string | undefined
    const location = getNestedValue(doc, `${pattern.geoPrefix}.location`) as { lat: number; lon: number } | undefined

    // Only include if we have geo data (not just an IP)
    if (ip && typeof ip === 'string' && (country || city || location)) {
      entries.push({
        field: pattern.ipField.replace('.ip', ''),
        ip,
        country,
        city,
        coordinates: location,
      })
    }
  }

  return entries
}

// Field extraction helper for exception creation
function extractFieldsFromLog(logDoc: Record<string, unknown>): string[] {
  const fields: string[] = []

  function extract(obj: Record<string, unknown>, prefix = '') {
    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = prefix ? `${prefix}.${key}` : key

      if (value !== null && typeof value === 'object') {
        // Nested object - recurse
        extract(value as Record<string, unknown>, fieldPath)
      } else {
        // Scalar value - this is a field
        fields.push(fieldPath)
      }
    }
  }

  extract(logDoc)
  return fields.sort()
}

// Helper to get field value from log document
function getFieldValue(logDoc: Record<string, unknown>, fieldPath: string): string {
  const MAX_DEPTH = 10
  const parts = fieldPath.split('.')

  if (parts.length > MAX_DEPTH) {
    return ''
  }

  let value: unknown = logDoc

  for (const part of parts) {
    if (value && typeof value === 'object' && part in (value as Record<string, unknown>)) {
      value = (value as Record<string, unknown>)[part]
    } else {
      return ''
    }
  }

  return String(value ?? '')
}

export default function AlertDetailPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const { hasPermission, user } = useAuth()
  const [alert, setAlert] = useState<Alert | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isUpdating, setIsUpdating] = useState(false)
  const [error, setError] = useState('')
  const [correlations, setCorrelations] = useState<CorrelationRule[]>([])

  // Exception dialog state
  const [showExceptionDialog, setShowExceptionDialog] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [exceptionFields, setExceptionFields] = useState<string[]>([])
  const [isExtractingFields, setIsExtractingFields] = useState(false)

  // Exception form state - now supports multiple AND conditions
  const [exceptionConditions, setExceptionConditions] = useState<ExceptionCondition[]>([])
  const [exceptionReason, setExceptionReason] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  // Comments state
  const [comments, setComments] = useState<AlertComment[]>([])
  const [newComment, setNewComment] = useState('')
  const [isSubmittingComment, setIsSubmittingComment] = useState(false)
  const { showToast } = useToast()

  // Ownership state
  const [isAssigning, setIsAssigning] = useState(false)

  // Helper to generate unique condition IDs
  const generateConditionId = () => `cond-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`

  // Add a new condition to the list
  const addCondition = () => {
    const preferredFields = ['process.executable', 'process.command_line', 'user.name', 'source.ip']
    const defaultField = exceptionFields.find(f =>
      preferredFields.includes(f) && !exceptionConditions.some(c => c.field === f)
    ) || exceptionFields[0] || ''

    const fieldValue = alert?.log_document ? getFieldValue(alert.log_document, defaultField) : ''

    setExceptionConditions([
      ...exceptionConditions,
      {
        id: generateConditionId(),
        field: defaultField,
        operator: 'equals',
        value: fieldValue,
      }
    ])
  }

  // Update a condition
  const updateCondition = (id: string, updates: Partial<ExceptionCondition>) => {
    setExceptionConditions(conditions =>
      conditions.map(c => c.id === id ? { ...c, ...updates } : c)
    )
  }

  // Remove a condition
  const removeCondition = (id: string) => {
    setExceptionConditions(conditions => conditions.filter(c => c.id !== id))
  }

  // Load alert function - must be declared before useEffect that uses it
  const loadAlert = useCallback(async () => {
    if (!id) return
    setIsLoading(true)
    setError('')
    try {
      const data = await alertsApi.get(id)
      setAlert(data)
      // Load correlation rules that involve this alert's rule
      if (data.rule_id) {
        loadCorrelations(data.rule_id)
      }
      // Load comments for this alert
      if (data.alert_id) {
        alertCommentsApi.list(data.alert_id).then(setComments).catch(console.error)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alert')
    } finally {
      setIsLoading(false)
    }
  }, [id])

  useEffect(() => {
    if (id) {
      loadAlert()
    }
  }, [id, loadAlert])

  const loadCorrelations = async (ruleId: string) => {
    try {
      const result = await correlationRulesApi.list(true)
      // Filter to only show correlation rules that use this rule
      const relatedRules = result.correlation_rules.filter(
        (rule) => rule.rule_a_id === ruleId || rule.rule_b_id === ruleId
      )
      setCorrelations(relatedRules)
    } catch (err) {
      console.error('Failed to load correlation rules:', err)
    }
  }

  const handleAddComment = async () => {
    if (!newComment.trim() || !alert?.alert_id) return
    setIsSubmittingComment(true)
    try {
      const comment = await alertCommentsApi.create(alert.alert_id, newComment)
      setComments([...comments, comment])
      setNewComment('')
    } catch (err) {
      showToast('Failed to add comment', 'error')
    } finally {
      setIsSubmittingComment(false)
    }
  }

  const handleToggleOwnership = async () => {
    if (!id || !alert) return
    setIsAssigning(true)
    try {
      const isOwner = alert.owner_id === user?.id
      if (isOwner) {
        await alertsApi.unassign(id)
        setAlert({ ...alert, owner_id: undefined, owner_username: undefined, owned_at: undefined })
      } else {
        const result = await alertsApi.assign(id)
        setAlert({ ...alert, owner_id: user?.id, owner_username: result.owner, owned_at: new Date().toISOString() })
      }
    } catch (err) {
      showToast('Failed to update ownership', 'error')
    } finally {
      setIsAssigning(false)
    }
  }

  const handleStatusChange = async (status: AlertStatus) => {
    if (!id || !alert) return
    setIsUpdating(true)
    try {
      await alertsApi.updateStatus(id, status)
      setAlert({ ...alert, status })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status')
    } finally {
      setIsUpdating(false)
    }
  }

  const handleDelete = () => {
    setShowDeleteConfirm(true)
  }

  const confirmDelete = async () => {
    if (!id) return
    setIsUpdating(true)
    setShowDeleteConfirm(false)
    try {
      await alertsApi.delete(id)
      navigate('/alerts')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete alert')
      setIsUpdating(false)
    }
  }

  const handleOpenExceptionDialog = async () => {
    if (!alert || !alert.log_document) {
      setError('Alert has no log document')
      return
    }

    setIsExtractingFields(true)
    setShowExceptionDialog(true)

    try {
      const fields = extractFieldsFromLog(alert.log_document)
      setExceptionFields(fields)

      // Auto-select preferred field for first condition
      const preferredFields = ['process.executable', 'process.command_line', 'user.name', 'source.ip']
      const selectedField = fields.find(f => preferredFields.includes(f)) || fields[0] || ''

      // Auto-fill value and detect operator
      let operator: ExceptionOperator = 'equals'
      let fieldValue = ''
      if (selectedField) {
        fieldValue = getFieldValue(alert.log_document, selectedField)
        // Auto-detect operator based on value characteristics
        if (fieldValue.includes('\\') || fieldValue.includes('/')) {
          operator = 'contains'
        }
      }

      // Initialize with one condition
      setExceptionConditions([{
        id: generateConditionId(),
        field: selectedField,
        operator,
        value: fieldValue,
      }])

      setExceptionReason(`False positive from alert ${alert.alert_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to extract fields from log')
    } finally {
      setIsExtractingFields(false)
    }
  }

  const handleCreateException = async (e: React.FormEvent) => {
    e.preventDefault()

    // Null check for alert
    if (!alert?.rule_id) {
      setError('Alert data not available')
      return
    }

    if (exceptionConditions.length === 0) {
      setError('Please add at least one condition')
      return
    }

    // Validate all conditions have field and value
    for (const cond of exceptionConditions) {
      if (!cond.field || !cond.value) {
        setError('All conditions must have field and value')
        return
      }
    }

    if (!exceptionReason) {
      setError('Please provide a reason')
      return
    }

    // Validate input lengths to prevent abuse
    const MAX_REASON_LENGTH = 1000
    const MAX_VALUE_LENGTH = 500

    if (exceptionReason.length > MAX_REASON_LENGTH) {
      setError(`Reason must be less than ${MAX_REASON_LENGTH} characters`)
      return
    }

    for (const cond of exceptionConditions) {
      if (cond.value.length > MAX_VALUE_LENGTH) {
        setError(`Value must be less than ${MAX_VALUE_LENGTH} characters`)
        return
      }
    }

    setIsCreating(true)
    setError('')

    try {
      // Generate a shared group_id for all conditions (AND logic)
      const groupId = crypto.randomUUID()

      // Create first exception (creates the group)
      // Pass alert_id to auto-mark alert as false_positive
      const firstCond = exceptionConditions[0]
      await rulesApi.createException(alert.rule_id, {
        field: firstCond.field,
        operator: firstCond.operator,
        value: firstCond.value,
        reason: exceptionReason,
        change_reason: exceptionReason,
        group_id: groupId,
        alert_id: alert.alert_id,
      })

      // Create additional conditions in the same group
      // Don't pass alert_id for subsequent conditions as alert is already updated
      for (let i = 1; i < exceptionConditions.length; i++) {
        const cond = exceptionConditions[i]
        await rulesApi.createException(alert.rule_id, {
          field: cond.field,
          operator: cond.operator,
          value: cond.value,
          reason: exceptionReason,
          change_reason: exceptionReason,
          group_id: groupId,
        })
      }

      setShowExceptionDialog(false)

      // Reset form
      setExceptionConditions([])
      setExceptionReason('')

      // Reload alert to show updated status and exception badge
      await loadAlert()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create exception')
    } finally {
      setIsCreating(false)
    }
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (error || !alert) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/alerts')}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error || 'Alert not found'}
        </div>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/alerts')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold">{alert.rule_title}</h1>
              {alert.tags.includes('correlation') && (
                <div className="flex items-center gap-1 px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs font-medium">
                  <Link2 className="h-3 w-3" />
                  <span>Correlation</span>
                </div>
              )}
            </div>
            <p className="text-sm text-muted-foreground">
              Alert ID: {alert.alert_id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span
            className={`px-3 py-1 rounded text-sm font-medium ${
              severityColors[alert.severity] || 'bg-gray-500 text-white'
            }`}
          >
            {capitalize(alert.severity)}
          </span>
          {alert.exception_created && (
            <Tooltip>
              <TooltipTrigger>
                <Badge variant="outline" className="gap-1">
                  <ShieldX className="h-3 w-3" />
                  Exception
                </Badge>
              </TooltipTrigger>
              <TooltipContent>
                <p className="font-medium">Exception created</p>
                <p className="text-sm text-muted-foreground">
                  {alert.exception_created.field} = {alert.exception_created.value}
                </p>
                <p className="text-xs text-muted-foreground">
                  {new Date(alert.exception_created.created_at).toLocaleString()}
                </p>
              </TooltipContent>
            </Tooltip>
          )}
          {alert.owner_username && (
            <Badge variant="secondary">
              Owner: {alert.owner_username}
            </Badge>
          )}
          <Button
            variant={alert.owner_id === user?.id ? 'destructive' : 'outline'}
            size="sm"
            onClick={handleToggleOwnership}
            disabled={isAssigning}
          >
            {isAssigning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : alert.owner_id === user?.id ? (
              'Release'
            ) : (
              'Take Ownership'
            )}
          </Button>
          <Select
            value={alert.status}
            onValueChange={(v) => handleStatusChange(v as AlertStatus)}
            disabled={isUpdating || !hasPermission('manage_rules')}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="z-50 bg-popover">
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="acknowledged">Acknowledged</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
          {hasPermission('manage_rules') && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleOpenExceptionDialog()}
            >
              <ShieldAlert className="h-4 w-4 mr-1" />
              Create Exception
            </Button>
          )}
          <Button
            variant="destructive"
            size="sm"
            onClick={handleDelete}
            disabled={isUpdating || !hasPermission('manage_alerts')}
          >
            <Trash2 className="h-4 w-4 mr-1" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Info Cards */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <span
                className={`px-2 py-1 rounded text-xs font-medium ${statusColors[alert.status]}`}
              >
                {statusLabels[alert.status]}
              </span>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Timeline
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">Created:</span>
                <div>
                  <TimestampTooltip timestamp={alert.created_at}>
                    <span>{formatDate(alert.created_at)}</span>
                  </TimestampTooltip>
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Updated:</span>
                <div>
                  <TimestampTooltip timestamp={alert.updated_at}>
                    <span>{formatDate(alert.updated_at)}</span>
                  </TimestampTooltip>
                </div>
              </div>
              {alert.acknowledged_at && (
                <div>
                  <span className="text-muted-foreground">Acknowledged:</span>
                  <div>
                    <TimestampTooltip timestamp={alert.acknowledged_at}>
                      <span>{formatDate(alert.acknowledged_at)}</span>
                    </TimestampTooltip>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {alert.acknowledged_by && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Acknowledged By
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm">
                {alert.acknowledged_by}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Rule
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Link
                to={`/rules/${alert.rule_id}`}
                className="text-sm text-primary hover:underline"
              >
                View Rule
              </Link>
              {alert.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap mt-2">
                  {alert.tags.map((tag, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.5 bg-muted rounded text-xs"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* GeoIP Data - shown if enrichment data exists */}
          {(() => {
            const geoData = extractGeoIPData(alert.log_document as Record<string, unknown>)
            if (geoData.length === 0) return null
            return (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Globe className="h-4 w-4" />
                    Geographic Information
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {geoData.map((entry, i) => (
                    <div key={i} className="text-sm">
                      <div className="font-medium capitalize">{entry.field}</div>
                      <div className="text-muted-foreground text-xs space-y-0.5 mt-1">
                        <div>IP: {entry.ip}</div>
                        {entry.country && <div>Country: {entry.country}</div>}
                        {entry.city && <div>City: {entry.city}</div>}
                        {entry.coordinates && (
                          <div>
                            Coordinates: {entry.coordinates.lat.toFixed(4)}, {entry.coordinates.lon.toFixed(4)}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )
          })()}

          {/* Threat Intelligence Enrichment - shown if TI data exists */}
          {alert.ti_enrichment && alert.ti_enrichment.indicators.length > 0 && (
            <TIEnrichmentCard indicators={alert.ti_enrichment.indicators} />
          )}

          {/* Correlation Alert Details - shown if this is a correlation alert */}
          <CorrelationAlertDetails logDocument={alert.log_document as Record<string, unknown>} />

          {/* Correlation Rules - shown if any correlation rules involve this alert's rule */}
          <CorrelationInfoCard correlations={correlations} ruleId={alert.rule_id} />
        </div>

        {/* Log Document */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-medium">
              Triggering Log Document
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="p-4 bg-muted rounded-lg overflow-auto max-h-[600px] text-xs font-mono">
              {JSON.stringify(alert.log_document, null, 2)}
            </pre>
          </CardContent>
        </Card>
      </div>

      {/* Comments Section */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <User className="h-4 w-4" />
            Investigation Notes
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {comments.map((comment) => (
              <div key={comment.id} className="border-b pb-3 last:border-0">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{comment.username}</span>
                  <span className="text-xs text-muted-foreground">
                    {new Date(comment.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-sm mt-1 whitespace-pre-wrap">{comment.content}</p>
              </div>
            ))}
            {comments.length === 0 && (
              <p className="text-sm text-muted-foreground">No comments yet. Add investigation notes to track your analysis.</p>
            )}
          </div>
          <div className="mt-4 flex gap-2">
            <Textarea
              placeholder="Add investigation notes..."
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              className="min-h-[80px]"
            />
            <Button
              onClick={handleAddComment}
              disabled={isSubmittingComment || !newComment.trim()}
              className="self-end"
            >
              {isSubmittingComment ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  Adding...
                </>
              ) : (
                'Add'
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Create Exception Dialog */}
      <Dialog open={showExceptionDialog} onOpenChange={setShowExceptionDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Rule Exception</DialogTitle>
            <DialogDescription>
              Create an exception for rule: <strong>{alert?.rule_title}</strong>
            </DialogDescription>
          </DialogHeader>

          {isExtractingFields ? (
            <div className="py-8 flex items-center justify-center">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span className="ml-2">Extracting fields from alert...</span>
            </div>
          ) : (
            <form onSubmit={handleCreateException} className="space-y-4">
              {/* Conditions - grouped with AND logic */}
              <div className="space-y-3">
                <Label>Conditions {exceptionConditions.length > 1 && <span className="text-muted-foreground text-xs ml-1">(all must match)</span>}</Label>

                {exceptionConditions.map((condition, index) => (
                  <div key={condition.id} className="p-3 border rounded-lg bg-muted/30 space-y-3">
                    {index > 0 && (
                      <div className="flex items-center justify-center mb-2">
                        <span className="text-xs font-medium bg-primary/10 text-primary px-2 py-0.5 rounded">AND</span>
                      </div>
                    )}
                    <div className="flex items-start gap-2">
                      <div className="flex-1 space-y-2">
                        {/* Field */}
                        <SearchableFieldSelector
                          fields={exceptionFields}
                          value={condition.field}
                          onChange={(field) => updateCondition(condition.id, { field })}
                          onSelect={(field) => {
                            if (alert?.log_document) {
                              const fieldValue = getFieldValue(alert.log_document, field)
                              updateCondition(condition.id, { field, value: fieldValue })
                            }
                          }}
                          label=""
                          placeholder="Select field"
                          emptyMessage="No fields available"
                        />

                        <div className="grid grid-cols-2 gap-2">
                          {/* Operator */}
                          <Select
                            value={condition.operator}
                            onValueChange={(v) => updateCondition(condition.id, { operator: v as ExceptionOperator })}
                          >
                            <SelectTrigger>
                              <SelectValue placeholder="Operator" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="equals">Equals</SelectItem>
                              <SelectItem value="not_equals">Not Equals</SelectItem>
                              <SelectItem value="contains">Contains</SelectItem>
                              <SelectItem value="not_contains">Not Contains</SelectItem>
                              <SelectItem value="starts_with">Starts With</SelectItem>
                              <SelectItem value="ends_with">Ends With</SelectItem>
                              <SelectItem value="regex">Regex</SelectItem>
                            </SelectContent>
                          </Select>

                          {/* Value */}
                          <Input
                            value={condition.value}
                            onChange={(e) => updateCondition(condition.id, { value: e.target.value })}
                            placeholder="Value"
                          />
                        </div>
                      </div>

                      {/* Remove button (only if more than one condition) */}
                      {exceptionConditions.length > 1 && (
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => removeCondition(condition.id)}
                          className="mt-1 text-muted-foreground hover:text-destructive"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}

                {/* Add AND condition button */}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={addCondition}
                  className="w-full"
                >
                  <Plus className="h-4 w-4 mr-1" />
                  Add AND Condition
                </Button>
              </div>

              {/* Preview */}
              {exceptionConditions.length > 0 && (
                <div className="p-3 bg-muted rounded-lg">
                  <Label className="text-xs text-muted-foreground">Preview:</Label>
                  <p className="text-sm font-mono mt-1">
                    {exceptionConditions.map((c, i) => (
                      <span key={c.id}>
                        {i > 0 && <span className="text-primary font-bold"> AND </span>}
                        <span className="text-blue-600">{c.field || '?'}</span>
                        <span className="text-muted-foreground"> {c.operator.replace('_', ' ')} </span>
                        <span className="text-green-600">"{c.value || '?'}"</span>
                      </span>
                    ))}
                  </p>
                </div>
              )}

              {/* Reason */}
              <div className="space-y-2">
                <Label htmlFor="exception-reason">Reason</Label>
                <Textarea
                  id="exception-reason"
                  value={exceptionReason}
                  onChange={(e) => setExceptionReason(e.target.value)}
                  placeholder="Explain why this exception is needed..."
                  rows={3}
                  required
                />
              </div>

              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowExceptionDialog(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={isCreating}>
                  {isCreating ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    'Create Exception'
                  )}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Alert</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this alert? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteConfirm(false)}
              disabled={isUpdating}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
              disabled={isUpdating}
            >
              {isUpdating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </TooltipProvider>
  )
}
