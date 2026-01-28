import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { alertsApi, correlationRulesApi, rulesApi, Alert, AlertStatus, TIEnrichmentIndicator, CorrelationRule } from '@/lib/api'
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
import { TooltipProvider } from '@/components/ui/tooltip'
import { ArrowLeft, AlertTriangle, ChevronDown, Clock, User, FileText, Globe, ShieldAlert, Link as LinkIcon, Link2, Loader2, Trash2 } from 'lucide-react'
import { TimestampTooltip } from '../components/timestamp-tooltip'
import { SearchableFieldSelector } from '@/components/SearchableFieldSelector'

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
  const { hasPermission } = useAuth()
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

  // Exception form state
  const [exceptionField, setExceptionField] = useState('')
  const [exceptionOperator, setExceptionOperator] = useState<'equals' | 'not_equals' | 'contains' | 'not_contains' | 'starts_with' | 'ends_with' | 'regex'>('equals')
  const [exceptionValue, setExceptionValue] = useState('')
  const [exceptionReason, setExceptionReason] = useState('')
  const [isCreating, setIsCreating] = useState(false)

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

      // Auto-select preferred field
      const preferredFields = ['process.executable', 'process.command_line', 'user.name', 'source.ip']
      const selectedField = fields.find(f => preferredFields.includes(f)) || fields[0] || ''
      setExceptionField(selectedField)

      // Auto-fill value and detect operator
      if (selectedField) {
        const fieldValue = getFieldValue(alert.log_document, selectedField)
        setExceptionValue(fieldValue)

        // Auto-detect operator based on value characteristics
        if (fieldValue.includes('\\') || fieldValue.includes('/')) {
          setExceptionOperator('contains')
        } else {
          setExceptionOperator('equals')
        }
      }

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

    if (!exceptionField || !exceptionValue || !exceptionReason) {
      setError('Please fill in all fields')
      return
    }

    // Validate input lengths to prevent abuse
    const MAX_REASON_LENGTH = 1000
    const MAX_VALUE_LENGTH = 500

    if (exceptionReason.length > MAX_REASON_LENGTH) {
      setError(`Reason must be less than ${MAX_REASON_LENGTH} characters`)
      return
    }

    if (exceptionValue.length > MAX_VALUE_LENGTH) {
      setError(`Value must be less than ${MAX_VALUE_LENGTH} characters`)
      return
    }

    setIsCreating(true)
    setError('')

    try {
      await rulesApi.createException(alert.rule_id, {
        field: exceptionField,
        operator: exceptionOperator,
        value: exceptionValue,
        reason: exceptionReason,
        change_reason: exceptionReason  // Use same reason for audit trail
      })

      setShowExceptionDialog(false)

      // Reset form
      setExceptionField('')
      setExceptionOperator('equals')
      setExceptionValue('')
      setExceptionReason('')
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
              {/* Field Selection */}
              <div className="space-y-2">
                <SearchableFieldSelector
                  fields={exceptionFields}
                  value={exceptionField}
                  onChange={setExceptionField}
                  onSelect={(field) => {
                    // Auto-fill the value with the field's value from the alert document
                    if (alert?.log_document) {
                      const fieldValue = getFieldValue(alert.log_document, field)
                      setExceptionValue(fieldValue)
                    }
                  }}
                  label="Field"
                  placeholder="Select a field from the alert"
                  emptyMessage="No fields available in this alert"
                />
              </div>

              {/* Operator Selection */}
              <div className="space-y-2">
                <Label htmlFor="exception-operator">Operator</Label>
                <Select value={exceptionOperator} onValueChange={(v: any) => setExceptionOperator(v)}>
                  <SelectTrigger id="exception-operator">
                    <SelectValue placeholder="Select operator" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="equals">Equals</SelectItem>
                    <SelectItem value="not_equals">Not Equals</SelectItem>
                    <SelectItem value="contains">Contains</SelectItem>
                    <SelectItem value="not_contains">Does Not Contain</SelectItem>
                    <SelectItem value="starts_with">Starts With</SelectItem>
                    <SelectItem value="ends_with">Ends With</SelectItem>
                    <SelectItem value="regex">Regex</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Value Input */}
              <div className="space-y-2">
                <Label htmlFor="exception-value">Value</Label>
                <Input
                  id="exception-value"
                  value={exceptionValue}
                  onChange={(e) => setExceptionValue(e.target.value)}
                  placeholder="Auto-filled from alert or enter value to match"
                  required
                />
              </div>

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
