import { useEffect, useState, useCallback } from 'react'
import {
  indexPatternsApi,
  IndexPattern,
  IndexPatternValidateResponse,
  IndexPatternMode,
  TIConfig,
  TI_SOURCE_INFO,
  TI_INDICATOR_TYPE_INFO,
  TI_SOURCE_SUPPORTED_TYPES,
  TISourceType,
  TIIndicatorType,
  TISourceConfigForPattern,
  tiApi,
  healthApi,
  HealthStatus,
} from '@/lib/api'
import { useMode } from '@/hooks/useMode'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Plus, Pencil, Trash2, Check, X, Loader2, Copy, Eye, EyeOff, RefreshCw, Key, ChevronDown, ChevronUp, Globe, Shield, HeartPulse, CheckCircle2, AlertTriangle, AlertCircle, Database } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'

const HealthStatusIcon = ({ status }: { status: HealthStatus }) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle2 className="h-4 w-4 text-green-600" />
    case 'warning':
      return <AlertTriangle className="h-4 w-4 text-yellow-600" />
    case 'critical':
      return <AlertCircle className="h-4 w-4 text-red-600" />
  }
}

export default function IndexPatternsPage() {
  const { isPullOnly, supportsPush } = useMode()
  const [patterns, setPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [healthData, setHealthData] = useState<Record<string, HealthStatus>>({})

  // Dialog state
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingPattern, setEditingPattern] = useState<IndexPattern | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  // Detection mode state
  const [detectionMode, setDetectionMode] = useState<IndexPatternMode>('push')
  const [pollIntervalMinutes, setPollIntervalMinutes] = useState<number>(5)
  const [timestampField, setTimestampField] = useState<string>('@timestamp')
  const [availableTimeFields, setAvailableTimeFields] = useState<string[]>([])
  const [isLoadingTimeFields, setIsLoadingTimeFields] = useState(false)

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    percolator_index: '',
    description: '',
  })

  // Health alerting form state
  const [healthAlerting, setHealthAlerting] = useState({
    enabled: true,
    noDataMinutes: null as number | null,
    errorRatePercent: null as number | null,
    latencyMs: null as number | null,
  })

  // Health monitoring overrides state
  const [enableHealthAlerting, setEnableHealthAlerting] = useState(true)
  const [healthOverrides, setHealthOverrides] = useState({
    detection_latency_warning_seconds: '',
    detection_latency_critical_seconds: '',
    error_rate_percent: '',
    no_data_minutes: '',
    queue_warning: '',
    queue_critical: '',
  })
  const [globalDefaults, setGlobalDefaults] = useState({
    detection_latency_warning: 2,
    detection_latency_critical: 10,
    error_rate_percent: 5,
    no_data_minutes: 15,
    queue_warning: 10000,
    queue_critical: 100000,
  })

  // GeoIP enrichment state
  const [geoipFields, setGeoipFields] = useState<string[]>([])

  // TI enrichment state
  const [tiConfig, setTiConfig] = useState<TIConfig>({})
  const [tiFieldInputs, setTiFieldInputs] = useState<Record<string, { field: string; type: TIIndicatorType }>>({})
  const [availableTiSources, setAvailableTiSources] = useState<TISourceType[]>([])

  // Toggle for health settings section
  const [showHealthSettings, setShowHealthSettings] = useState(false)
  const [showGeoipSettings, setShowGeoipSettings] = useState(false)
  const [showTiSettings, setShowTiSettings] = useState(false)
  const [showSecuritySettings, setShowSecuritySettings] = useState(false)

  // IP Allowlist state
  const [allowedIps, setAllowedIps] = useState<string[]>([])
  const [newIpEntry, setNewIpEntry] = useState('')
  const [ipError, setIpError] = useState('')

  // Rate limiting state
  const [rateLimitEnabled, setRateLimitEnabled] = useState(false)
  const [rateLimitRequests, setRateLimitRequests] = useState<number | null>(100)
  const [rateLimitEvents, setRateLimitEvents] = useState<number | null>(50000)

  // Validation state
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] =
    useState<IndexPatternValidateResponse | null>(null)

  // Delete confirmation
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')

  // Token visibility state
  const [visibleTokens, setVisibleTokens] = useState<Set<string>>(new Set())
  const [copiedToken, setCopiedToken] = useState<string | null>(null)

  // Token regeneration state
  const [regenerateId, setRegenerateId] = useState<string | null>(null)
  const [isRegenerating, setIsRegenerating] = useState(false)

  // Token details dialog
  const [tokenDetailsPattern, setTokenDetailsPattern] = useState<IndexPattern | null>(null)

  // Track if user has manually edited percolator_index
  const [percolatorIndexManuallyEdited, setPercolatorIndexManuallyEdited] = useState(false)

  // Load functions - must be declared before useEffect that uses them
  const loadTiSources = useCallback(async () => {
    try {
      const status = await tiApi.listSources()
      // Get sources that have API keys configured (sources is an array)
      const configuredSources = status.sources
        .filter(s => s.has_api_key)
        .map(s => s.source_type as TISourceType)
      setAvailableTiSources(configuredSources)
    } catch {
      // If TI sources fail to load, continue without them
      setAvailableTiSources([])
    }
  }, [])

  const loadPatterns = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const data = await indexPatternsApi.list()
      setPatterns(data)
      loadHealthData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load patterns')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadPatterns()
    loadTiSources()
    loadGlobalDefaults()
  }, [loadPatterns, loadTiSources])

  // Load global health defaults
  const loadGlobalDefaults = async () => {
    try {
      const settings = await healthApi.getSettings()
      setGlobalDefaults({
        detection_latency_warning: settings.detection_latency_warning_ms / 1000, // Convert ms to seconds
        detection_latency_critical: settings.detection_latency_critical_ms / 1000,
        error_rate_percent: settings.error_rate_percent,
        no_data_minutes: settings.no_data_minutes,
        queue_warning: settings.queue_warning,
        queue_critical: settings.queue_critical,
      })
    } catch (err) {
      console.error('Failed to load global health defaults:', err)
      // Continue with hardcoded defaults
    }
  }

  const loadTimeFields = async (patternId: string) => {
    setIsLoadingTimeFields(true)
    try {
      const fields = await indexPatternsApi.getTimeFields(patternId)
      setAvailableTimeFields(fields)
    } catch (err) {
      console.error('Failed to load time fields:', err)
      setAvailableTimeFields([])
    } finally {
      setIsLoadingTimeFields(false)
    }
  }

  const loadHealthData = async () => {
    try {
      const health = await healthApi.listIndices()
      const healthMap: Record<string, HealthStatus> = {}
      for (const h of health) {
        healthMap[h.index_pattern_id] = h.status
      }
      setHealthData(healthMap)
    } catch {
      // Health data is optional, continue without it
    }
  }

  const openCreateDialog = () => {
    setEditingPattern(null)
    setFormData({
      name: '',
      pattern: '',
      percolator_index: '',
      description: '',
    })
    setHealthAlerting({
      enabled: true,
      noDataMinutes: null,
      errorRatePercent: null,
      latencyMs: null,
    })
    setEnableHealthAlerting(true)
    setHealthOverrides({
      detection_latency_warning_seconds: '',
      detection_latency_critical_seconds: '',
      error_rate_percent: '',
      no_data_minutes: '',
      queue_warning: '',
      queue_critical: '',
    })
    setGeoipFields([])
    setTiConfig({})
    setTiFieldInputs({})
    setShowHealthSettings(false)
    setShowGeoipSettings(false)
    setShowTiSettings(false)
    setShowSecuritySettings(false)
    setAllowedIps([])
    setNewIpEntry('')
    setIpError('')
    setRateLimitEnabled(false)
    setRateLimitRequests(100)
    setRateLimitEvents(50000)
    // Detection mode - default to pull in pull-only deployment
    setDetectionMode(isPullOnly ? 'pull' : 'push')
    setPollIntervalMinutes(5)
    setTimestampField('@timestamp')
    setAvailableTimeFields([])
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(false)
    setSaveError('')
    setIsDialogOpen(true)
  }

  const openEditDialog = async (pattern: IndexPattern) => {
    setEditingPattern(pattern)
    setFormData({
      name: pattern.name,
      pattern: pattern.pattern,
      percolator_index: pattern.percolator_index,
      description: pattern.description || '',
    })
    setHealthAlerting({
      enabled: pattern.health_alerting_enabled,
      noDataMinutes: pattern.health_no_data_minutes,
      errorRatePercent: pattern.health_error_rate_percent,
      latencyMs: pattern.health_latency_ms,
    })
    setEnableHealthAlerting(pattern.health_alerting_enabled || false)
    // TODO: Load health_overrides from pattern when backend integration is ready
    setHealthOverrides({
      detection_latency_warning_seconds: '',
      detection_latency_critical_seconds: '',
      error_rate_percent: '',
      no_data_minutes: '',
      queue_warning: '',
      queue_critical: '',
    })
    setGeoipFields(pattern.geoip_fields || [])
    // Load TI config from pattern
    const patternTiConfig: TIConfig = {}
    if (pattern.ti_config) {
      for (const [source, config] of Object.entries(pattern.ti_config)) {
        patternTiConfig[source] = {
          enabled: config.enabled ?? false,
          fields: config.fields ?? [],
        }
      }
    }
    setTiConfig(patternTiConfig)
    setTiFieldInputs({})
    setShowHealthSettings(false)
    setShowGeoipSettings(pattern.geoip_fields && pattern.geoip_fields.length > 0)
    // Show TI settings if any source is enabled
    const hasTiEnabled = Object.values(patternTiConfig).some(c => c.enabled)
    setShowTiSettings(hasTiEnabled)
    // Security settings (IP allowlist and rate limiting)
    setAllowedIps(pattern.allowed_ips || [])
    setNewIpEntry('')
    setIpError('')
    setRateLimitEnabled(pattern.rate_limit_enabled || false)
    setRateLimitRequests(pattern.rate_limit_requests_per_minute || 100)
    setRateLimitEvents(pattern.rate_limit_events_per_minute || 50000)
    // Show security settings if any are configured
    const hasSecuritySettings = (pattern.allowed_ips && pattern.allowed_ips.length > 0) || pattern.rate_limit_enabled
    setShowSecuritySettings(hasSecuritySettings || false)
    // Detection mode
    setDetectionMode(pattern.mode || 'push')
    setPollIntervalMinutes(pattern.poll_interval_minutes || 5)
    setTimestampField(pattern.timestamp_field || '@timestamp')
    setAvailableTimeFields([])
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(true) // Don't auto-generate for existing patterns
    setSaveError('')
    setIsDialogOpen(true)

    // Auto-validate to load available fields for enrichment configuration
    if (pattern.pattern) {
      setIsValidating(true)
      try {
        const result = await indexPatternsApi.validate(pattern.pattern)
        setValidationResult(result)
      } catch {
        // Silently fail - user can manually validate if needed
      } finally {
        setIsValidating(false)
      }
    }

    // Load time fields for pull mode timestamp configuration
    if (pattern.mode === 'pull') {
      loadTimeFields(pattern.id)
    }
  }

  const handleValidate = async () => {
    if (!formData.pattern) return

    setIsValidating(true)
    try {
      const result = await indexPatternsApi.validate(formData.pattern)
      setValidationResult(result)
    } catch (err) {
      setValidationResult({
        valid: false,
        indices: [],
        total_docs: 0,
        sample_fields: [],
        error: err instanceof Error ? err.message : 'Validation failed',
      })
    } finally {
      setIsValidating(false)
    }
  }

  const handleSave = async () => {
    // For push mode, percolator_index is required; for pull mode, auto-generate if empty
    if (!formData.name || !formData.pattern) {
      return
    }
    if (detectionMode === 'push' && !formData.percolator_index) {
      return
    }

    // For pull mode, auto-generate percolator index if not set (still needed in DB but not used)
    const percolatorIndex = formData.percolator_index ||
      `chad-percolator-${formData.pattern.replace(/\*/g, '').replace(/-$/, '')}`

    setIsSaving(true)
    setSaveError('')
    try {
      const healthData = {
        health_alerting_enabled: enableHealthAlerting,
        health_no_data_minutes: healthAlerting.noDataMinutes,
        health_error_rate_percent: healthAlerting.errorRatePercent,
        health_latency_ms: healthAlerting.latencyMs,
      }

      // Build TI config - only include sources with fields configured
      const tiConfigToSave: TIConfig = {}
      for (const [source, config] of Object.entries(tiConfig)) {
        if (config.enabled || config.fields.length > 0) {
          tiConfigToSave[source] = config
        }
      }

      // Security settings
      const securityData = {
        allowed_ips: allowedIps.length > 0 ? allowedIps : null,
        rate_limit_enabled: rateLimitEnabled,
        rate_limit_requests_per_minute: rateLimitEnabled ? rateLimitRequests : null,
        rate_limit_events_per_minute: rateLimitEnabled ? rateLimitEvents : null,
      }

      // Detection mode settings
      const modeData = {
        mode: detectionMode,
        poll_interval_minutes: detectionMode === 'pull' ? pollIntervalMinutes : 5,
        timestamp_field: detectionMode === 'pull' ? timestampField : '@timestamp',
      }

      if (editingPattern) {
        await indexPatternsApi.update(editingPattern.id, {
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: percolatorIndex,
          description: formData.description || undefined,
          ...healthData,
          geoip_fields: geoipFields,
          ti_config: Object.keys(tiConfigToSave).length > 0 ? tiConfigToSave : null,
          ...securityData,
          ...modeData,
        })
      } else {
        await indexPatternsApi.create({
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: percolatorIndex,
          description: formData.description || undefined,
          ...healthData,
          geoip_fields: geoipFields,
          ti_config: Object.keys(tiConfigToSave).length > 0 ? tiConfigToSave : null,
          ...securityData,
          ...modeData,
        })
      }
      setIsDialogOpen(false)
      loadPatterns()
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return

    setIsDeleting(true)
    setDeleteError('')
    try {
      await indexPatternsApi.delete(deleteId)
      setDeleteId(null)
      loadPatterns()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setIsDeleting(false)
    }
  }

  const openDeleteDialog = (patternId: string) => {
    setDeleteId(patternId)
    setDeleteError('')
  }

  const handleRegenerateToken = async () => {
    if (!regenerateId) return

    setIsRegenerating(true)
    try {
      const result = await indexPatternsApi.regenerateToken(regenerateId)
      // Update the pattern in state with the new token
      setPatterns(prev =>
        prev.map(p =>
          p.id === regenerateId ? { ...p, auth_token: result.auth_token } : p
        )
      )
      // Also update token details dialog if open
      if (tokenDetailsPattern?.id === regenerateId) {
        setTokenDetailsPattern(prev =>
          prev ? { ...prev, auth_token: result.auth_token } : null
        )
      }
      setRegenerateId(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to regenerate token')
    } finally {
      setIsRegenerating(false)
    }
  }

  const toggleTokenVisibility = (patternId: string) => {
    setVisibleTokens(prev => {
      const newSet = new Set(prev)
      if (newSet.has(patternId)) {
        newSet.delete(patternId)
      } else {
        newSet.add(patternId)
      }
      return newSet
    })
  }

  const copyToClipboard = async (text: string, patternId: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedToken(patternId)
      setTimeout(() => setCopiedToken(null), 2000)
    } catch {
      setError('Failed to copy to clipboard')
    }
  }

  // Auto-generate percolator index name from pattern
  const handlePatternChange = (value: string) => {
    setFormData((prev) => ({
      ...prev,
      pattern: value,
      // Only auto-generate if user hasn't manually edited percolator_index
      percolator_index: percolatorIndexManuallyEdited
        ? prev.percolator_index
        : `chad-percolator-${value.replace(/\*/g, '').replace(/-$/, '')}`,
    }))
    setValidationResult(null)
  }

  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Index Patterns</h1>
        <Button onClick={openCreateDialog}>
          <Plus className="h-4 w-4 mr-2" />
          Create Pattern
        </Button>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <LoadingState message="Loading index patterns..." />
      ) : patterns.length === 0 ? (
        <EmptyState
          icon={<Database className="h-12 w-12" />}
          title="No index patterns"
          description="Create your first index pattern to start matching rules against your OpenSearch indices."
          action={
            <Button onClick={openCreateDialog}>
              <Plus className="h-4 w-4 mr-2" />
              Create Pattern
            </Button>
          }
        />
      ) : (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Pattern</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead className="w-32">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {patterns.map((pattern) => (
                <TableRow key={pattern.id}>
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      {healthData[pattern.id] && (
                        <HealthStatusIcon status={healthData[pattern.id]} />
                      )}
                      {pattern.name}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {pattern.pattern}
                  </TableCell>
                  <TableCell>
                    <Badge variant={pattern.mode === 'push' ? 'default' : 'secondary'}>
                      {pattern.mode === 'push' ? 'Push' : `Pull (${pattern.poll_interval_minutes}m)`}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        title="View token & endpoint"
                        onClick={() => setTokenDetailsPattern(pattern)}
                      >
                        <Key className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Edit pattern"
                        onClick={() => openEditDialog(pattern)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Delete pattern"
                        onClick={() => openDeleteDialog(pattern.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Token Details Dialog */}
      <Dialog open={!!tokenDetailsPattern} onOpenChange={() => setTokenDetailsPattern(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>
              {tokenDetailsPattern?.mode === 'pull' ? 'Pull Mode Configuration' : 'Log Shipping Configuration'}
            </DialogTitle>
            <DialogDescription>
              {tokenDetailsPattern?.mode === 'pull'
                ? `This pattern polls OpenSearch every ${tokenDetailsPattern?.poll_interval_minutes} minutes for new logs.`
                : `Use this token to authenticate log shipping requests for "${tokenDetailsPattern?.name}"`}
            </DialogDescription>
          </DialogHeader>

          {tokenDetailsPattern && tokenDetailsPattern.mode === 'pull' && (
            <div className="space-y-4 py-4">
              <div className="p-3 bg-muted rounded-md space-y-2">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  <span className="font-medium text-sm">Pull Mode Active</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  CHAD automatically queries OpenSearch for logs matching the pattern "{tokenDetailsPattern.pattern}"
                  every {tokenDetailsPattern.poll_interval_minutes} minutes. No log shipping configuration is needed.
                </p>
              </div>
              <p className="text-xs text-muted-foreground">
                To change to push mode, edit this index pattern and select "Push" as the detection mode.
              </p>
            </div>
          )}

          {tokenDetailsPattern && tokenDetailsPattern.mode !== 'pull' && (
            <div className="space-y-4 py-4">
              {/* Endpoint URL */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Endpoint URL</Label>
                <div className="flex gap-2">
                  <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                    POST {window.location.origin}/api/logs/{getIndexSuffix(tokenDetailsPattern.percolator_index)}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(
                      `${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}`,
                      `${tokenDetailsPattern.id}-url`
                    )}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-url` ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Auth Token */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Auth Token</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 text-xs"
                    onClick={() => setRegenerateId(tokenDetailsPattern.id)}
                  >
                    <RefreshCw className="h-3 w-3 mr-1" />
                    Regenerate
                  </Button>
                </div>
                <div className="flex gap-2">
                  <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                    {visibleTokens.has(tokenDetailsPattern.id)
                      ? tokenDetailsPattern.auth_token
                      : `${'*'.repeat(20)}...${tokenDetailsPattern.auth_token.slice(-4)}`
                    }
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => toggleTokenVisibility(tokenDetailsPattern.id)}
                  >
                    {visibleTokens.has(tokenDetailsPattern.id) ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(tokenDetailsPattern.auth_token, `${tokenDetailsPattern.id}-token`)}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-token` ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Example curl command */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Example Request</Label>
                <div className="relative">
                  <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap">
{`curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\
  -H "Authorization: Bearer ${visibleTokens.has(tokenDetailsPattern.id) ? tokenDetailsPattern.auth_token : '<your-token>'}" \\
  -H "Content-Type: application/json" \\
  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`}
                  </pre>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-2 right-2 h-6 w-6"
                    onClick={() => copyToClipboard(
                      `curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\\n  -H "Authorization: Bearer ${tokenDetailsPattern.auth_token}" \\\n  -H "Content-Type: application/json" \\\n  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`,
                      `${tokenDetailsPattern.id}-curl`
                    )}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-curl` ? (
                      <Check className="h-3 w-3 text-green-500" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </Button>
                </div>
              </div>

              <p className="text-xs text-muted-foreground">
                Send a JSON array of log documents to this endpoint. Each log will be matched against deployed rules and alerts will be generated for matches.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setTokenDetailsPattern(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create/Edit Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>
              {editingPattern ? 'Edit Index Pattern' : 'Create Index Pattern'}
            </DialogTitle>
            <DialogDescription>
              Index patterns define which OpenSearch indices rules will match against.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4 overflow-y-auto flex-1">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Windows Sysmon Logs"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pattern">Index Pattern</Label>
              <div className="flex gap-2">
                <Input
                  id="pattern"
                  value={formData.pattern}
                  onChange={(e) => handlePatternChange(e.target.value)}
                  placeholder="logs-windows-*"
                  className="font-mono"
                />
                <Button
                  type="button"
                  variant="secondary"
                  onClick={handleValidate}
                  disabled={isValidating || !formData.pattern}
                >
                  {isValidating ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    'Validate'
                  )}
                </Button>
              </div>
              {validationResult && (
                <div
                  className={`text-sm p-2 rounded ${
                    validationResult.valid
                      ? 'bg-green-500/10 text-green-600'
                      : 'bg-destructive/10 text-destructive'
                  }`}
                >
                  {validationResult.valid ? (
                    <div className="flex items-center gap-2">
                      <Check className="h-4 w-4" />
                      Found {validationResult.indices.length} indices,{' '}
                      {validationResult.total_docs.toLocaleString()} documents
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <X className="h-4 w-4" />
                      {validationResult.error || 'No matching indices found'}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Percolator Index - only shown for push mode */}
            {detectionMode === 'push' && (
              <div className="space-y-2">
                <Label htmlFor="percolator">Percolator Index</Label>
                <Input
                  id="percolator"
                  value={formData.percolator_index}
                  onChange={(e) => {
                    setFormData({ ...formData, percolator_index: e.target.value })
                    setPercolatorIndexManuallyEdited(true)
                  }}
                  placeholder="chad-percolator-windows"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Where deployed rules will be stored in OpenSearch. Must start with "chad-percolator-".
                </p>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="description">Description (optional)</Label>
              <Input
                id="description"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
                placeholder="Windows event logs from Sysmon"
              />
            </div>

            {/* Detection Mode Selector */}
            <div className="space-y-3 p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4" />
                <Label className="font-medium">Detection Mode</Label>
              </div>
              <div className="space-y-2">
                <Select
                  value={detectionMode}
                  onValueChange={(value) => setDetectionMode(value as IndexPatternMode)}
                  disabled={isPullOnly}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {supportsPush && (
                      <SelectItem value="push">
                        Push (Real-time via /logs endpoint)
                      </SelectItem>
                    )}
                    <SelectItem value="pull">
                      Pull (Scheduled OpenSearch queries)
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {detectionMode === 'push'
                    ? 'Logs are pushed to CHAD via the /logs endpoint for real-time detection.'
                    : 'CHAD periodically queries OpenSearch for new logs matching deployed rules. Detection is delayed by the poll interval.'}
                </p>
                {isPullOnly && (
                  <p className="text-xs text-amber-600">
                    This deployment only supports pull mode.
                  </p>
                )}
                {!isPullOnly && detectionMode === 'pull' && (
                  <p className="text-xs text-blue-600">
                    Pull mode has delayed detection compared to push mode. Use push mode for time-sensitive security detections.
                  </p>
                )}
              </div>

              {/* Poll Interval for Pull Mode */}
              {detectionMode === 'pull' && (
                <div className="space-y-4 pt-2 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="poll-interval">Poll Interval (minutes)</Label>
                    <Input
                      id="poll-interval"
                      type="number"
                      min="1"
                      max="1440"
                      value={pollIntervalMinutes}
                      onChange={(e) => setPollIntervalMinutes(Math.min(1440, Math.max(1, parseInt(e.target.value) || 5)))}
                      className="w-24"
                    />
                    <p className="text-xs text-muted-foreground">
                      How often to query OpenSearch for new logs (1-1440 minutes / 24 hours max).
                    </p>
                    {pollIntervalMinutes > 15 && (
                      <p className="text-xs text-amber-600">
                        ⚠️ Longer polling intervals mean delayed detection. For time-sensitive detections, consider shorter intervals.
                      </p>
                    )}
                  </div>

                  {/* Timestamp Field for Pull Mode */}
                  <div className="space-y-2">
                    <Label htmlFor="timestamp-field">Timestamp Field</Label>
                    <Select
                      value={timestampField}
                      onValueChange={setTimestampField}
                    >
                      <SelectTrigger className="w-full font-mono text-sm">
                        <SelectValue placeholder="Select timestamp field" />
                      </SelectTrigger>
                      <SelectContent>
                        {isLoadingTimeFields ? (
                          <div className="p-2 text-xs text-muted-foreground flex items-center gap-2">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            Loading time fields...
                          </div>
                        ) : availableTimeFields.length > 0 ? (
                          availableTimeFields.map((field) => (
                            <SelectItem key={field} value={field} className="font-mono">
                              {field}
                            </SelectItem>
                          ))
                        ) : (
                          <>
                            <SelectItem value="@timestamp" className="font-mono">@timestamp</SelectItem>
                            <SelectItem value="timestamp" className="font-mono">timestamp</SelectItem>
                            <SelectItem value="event.created" className="font-mono">event.created</SelectItem>
                          </>
                        )}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      The field used to track which logs have been processed.
                      {!editingPattern && ' Validate the pattern to see available time fields.'}
                    </p>
                    {editingPattern && availableTimeFields.length === 0 && !isLoadingTimeFields && (
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto p-0 text-xs"
                        onClick={() => loadTimeFields(editingPattern.id)}
                      >
                        Load available time fields
                      </Button>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Dynamic Log Shipper Endpoint Info - only show for push mode */}
            {detectionMode === 'push' && formData.percolator_index && formData.percolator_index.startsWith('chad-percolator-') && (
              <div className="space-y-2 p-3 bg-muted rounded-md">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Log Shipper Endpoint</Label>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6"
                    onClick={() => {
                      const suffix = getIndexSuffix(formData.percolator_index)
                      navigator.clipboard.writeText(`${window.location.origin}/api/logs/${suffix}`)
                    }}
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                </div>
                <code className="block text-xs bg-background p-2 rounded font-mono break-all">
                  POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}
                </code>
                <p className="text-xs text-muted-foreground">
                  {editingPattern
                    ? 'Use the auth token to authenticate requests to this endpoint.'
                    : 'An auth token will be generated when you save this pattern.'}
                </p>
              </div>
            )}

            {/* Health Alerting Section */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowHealthSettings(!showHealthSettings)}
              >
                <div className="flex items-center gap-2">
                  <HeartPulse className="h-4 w-4" />
                  <span className="font-medium text-sm">Health Alerting</span>
                </div>
                {showHealthSettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showHealthSettings && (
                <div className="p-3 pt-0 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="health-enabled" className="font-normal">Enable Health Alerting</Label>
                      <p className="text-xs text-muted-foreground">Send alerts when thresholds are exceeded</p>
                    </div>
                    <Switch
                      id="health-enabled"
                      checked={enableHealthAlerting}
                      onCheckedChange={setEnableHealthAlerting}
                    />
                  </div>

                  {enableHealthAlerting && (
                    <div className="space-y-6 pt-4 border-t">
                      <p className="text-xs text-muted-foreground">
                        Leave empty to use global defaults from the Health page.
                      </p>

                      {/* Detection Latency */}
                      <div>
                        <h4 className="text-sm font-medium mb-3">Detection Latency</h4>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="detection-warning">Warning (seconds)</Label>
                            <Input
                              id="detection-warning"
                              type="number"
                              min="1"
                              step="0.1"
                              placeholder={`Global: ${globalDefaults.detection_latency_warning}`}
                              value={healthOverrides.detection_latency_warning_seconds}
                              onChange={(e) => setHealthOverrides({...healthOverrides, detection_latency_warning_seconds: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.detection_latency_warning} seconds</p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="detection-critical">Critical (seconds)</Label>
                            <Input
                              id="detection-critical"
                              type="number"
                              min="1"
                              step="0.1"
                              placeholder={`Global: ${globalDefaults.detection_latency_critical}`}
                              value={healthOverrides.detection_latency_critical_seconds}
                              onChange={(e) => setHealthOverrides({...healthOverrides, detection_latency_critical_seconds: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.detection_latency_critical} seconds</p>
                          </div>
                        </div>
                      </div>

                      {/* Other Thresholds */}
                      <div>
                        <h4 className="text-sm font-medium mb-3">Other Thresholds</h4>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="error-rate">Error Rate (%)</Label>
                            <Input
                              id="error-rate"
                              type="number"
                              min="0"
                              step="0.1"
                              placeholder={`Global: ${globalDefaults.error_rate_percent}`}
                              value={healthOverrides.error_rate_percent}
                              onChange={(e) => setHealthOverrides({...healthOverrides, error_rate_percent: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.error_rate_percent}%</p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="no-data">No Data (minutes)</Label>
                            <Input
                              id="no-data"
                              type="number"
                              min="1"
                              placeholder={`Global: ${globalDefaults.no_data_minutes}`}
                              value={healthOverrides.no_data_minutes}
                              onChange={(e) => setHealthOverrides({...healthOverrides, no_data_minutes: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.no_data_minutes} min</p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="queue-warning">Queue Warning</Label>
                            <Input
                              id="queue-warning"
                              type="number"
                              min="1"
                              placeholder={`Global: ${globalDefaults.queue_warning}`}
                              value={healthOverrides.queue_warning}
                              onChange={(e) => setHealthOverrides({...healthOverrides, queue_warning: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.queue_warning}</p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="queue-critical">Queue Critical</Label>
                            <Input
                              id="queue-critical"
                              type="number"
                              min="1"
                              placeholder={`Global: ${globalDefaults.queue_critical}`}
                              value={healthOverrides.queue_critical}
                              onChange={(e) => setHealthOverrides({...healthOverrides, queue_critical: e.target.value})}
                            />
                            <p className="text-xs text-muted-foreground">Global: {globalDefaults.queue_critical}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* GeoIP Enrichment Section */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowGeoipSettings(!showGeoipSettings)}
              >
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  <span className="font-medium text-sm">GeoIP Enrichment</span>
                  {geoipFields.length > 0 && (
                    <Badge variant="secondary" className="text-xs">
                      {geoipFields.length} field{geoipFields.length > 1 ? 's' : ''}
                    </Badge>
                  )}
                </div>
                {showGeoipSettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showGeoipSettings && (
                <div className="p-3 pt-0 space-y-4">
                  <p className="text-xs text-muted-foreground">
                    Select IP address fields to enrich with geographic data. Click a field to add it.
                  </p>

                  <Select
                    value=""
                    onValueChange={(value) => {
                      if (value && !geoipFields.includes(value)) {
                        setGeoipFields([...geoipFields, value])
                      }
                    }}
                  >
                    <SelectTrigger className="h-8 text-sm">
                      <SelectValue placeholder="Click to add IP fields..." />
                    </SelectTrigger>
                    <SelectContent>
                      {validationResult?.sample_fields && validationResult.sample_fields.length > 0 ? (
                        validationResult.sample_fields
                          .filter(f => !geoipFields.includes(f))
                          .map(field => (
                            <SelectItem key={field} value={field}>
                              {field}
                            </SelectItem>
                          ))
                      ) : (
                        <div className="p-2 text-xs text-muted-foreground">
                          Validate pattern to see available fields
                        </div>
                      )}
                    </SelectContent>
                  </Select>

                  {!validationResult?.sample_fields?.length && (
                    <p className="text-xs text-amber-600">
                      Validate the index pattern above to see available fields
                    </p>
                  )}

                  {geoipFields.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {geoipFields.map((field) => (
                        <Badge
                          key={field}
                          variant="outline"
                          className="flex items-center gap-1 pr-1"
                        >
                          {field}
                          <button
                            type="button"
                            onClick={() => setGeoipFields(geoipFields.filter(f => f !== field))}
                            className="ml-1 hover:bg-muted rounded-full p-0.5"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  )}

                  <p className="text-xs text-muted-foreground">
                    Common fields: source.ip, destination.ip, client.ip, server.ip
                  </p>
                </div>
              )}
            </div>

            {/* TI Enrichment Section */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowTiSettings(!showTiSettings)}
              >
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  <span className="font-medium text-sm">Threat Intelligence Enrichment</span>
                  {Object.values(tiConfig).filter(c => c.enabled).length > 0 && (
                    <Badge variant="secondary" className="text-xs">
                      {Object.values(tiConfig).filter(c => c.enabled).length} source{Object.values(tiConfig).filter(c => c.enabled).length > 1 ? 's' : ''}
                    </Badge>
                  )}
                </div>
                {showTiSettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showTiSettings && (
                <div className="p-3 pt-0 space-y-4">
                  <p className="text-xs text-muted-foreground">
                    Enable TI sources for this index pattern and specify which fields to enrich.
                    TI sources must first be configured in Settings &gt; Integrations.
                  </p>

                  {availableTiSources.length === 0 ? (
                    <div className="text-sm text-muted-foreground p-3 bg-muted/50 rounded">
                      No TI sources configured. Configure API keys in Settings &gt; Integrations &gt; Threat Intelligence.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {availableTiSources.map((source) => {
                        const sourceInfo = TI_SOURCE_INFO[source]
                        const config: TISourceConfigForPattern = tiConfig[source] || { enabled: false, fields: [] }
                        const supportedTypes = TI_SOURCE_SUPPORTED_TYPES[source] || ['ip']
                        const defaultType = supportedTypes[0]
                        const fieldInput = tiFieldInputs[source] || { field: '', type: defaultType }

                        return (
                          <div key={source} className="border rounded p-3 space-y-3">
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-medium text-sm">{sourceInfo.name}</div>
                                <p className="text-xs text-muted-foreground">{sourceInfo.description}</p>
                              </div>
                              <Switch
                                checked={config.enabled}
                                onCheckedChange={(checked) => {
                                  setTiConfig({
                                    ...tiConfig,
                                    [source]: { ...config, enabled: checked },
                                  })
                                }}
                              />
                            </div>

                            {config.enabled && (
                              <div className="space-y-2">
                                <div className="flex items-center gap-2">
                                  <Label className="text-xs">Add as:</Label>
                                  {/* Type selector - sets the type for next added field */}
                                  <Select
                                    value={fieldInput.type}
                                    onValueChange={(value) => setTiFieldInputs({
                                      ...tiFieldInputs,
                                      [source]: { ...fieldInput, type: value as TIIndicatorType },
                                    })}
                                  >
                                    <SelectTrigger className="w-32 h-7 text-xs">
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      {(TI_SOURCE_SUPPORTED_TYPES[source] || []).map(type => (
                                        <SelectItem key={type} value={type}>
                                          {TI_INDICATOR_TYPE_INFO[type].label}
                                        </SelectItem>
                                      ))}
                                    </SelectContent>
                                  </Select>
                                </div>

                                {/* Field selector - clicking adds immediately with selected type */}
                                <Select
                                  value=""
                                  onValueChange={(value) => {
                                    if (value && !config.fields.some(f => f.field === value)) {
                                      setTiConfig({
                                        ...tiConfig,
                                        [source]: {
                                          ...config,
                                          fields: [...config.fields, { field: value, type: fieldInput.type }],
                                        },
                                      })
                                    }
                                  }}
                                >
                                  <SelectTrigger className="h-8 text-sm">
                                    <SelectValue placeholder="Click to add fields..." />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {validationResult?.sample_fields && validationResult.sample_fields.length > 0 ? (
                                      validationResult.sample_fields
                                        .filter(f => !config.fields.some(fc => fc.field === f))
                                        .map(field => (
                                          <SelectItem key={field} value={field}>
                                            {field}
                                          </SelectItem>
                                        ))
                                    ) : (
                                      <div className="p-2 text-xs text-muted-foreground">
                                        Validate pattern to see available fields
                                      </div>
                                    )}
                                  </SelectContent>
                                </Select>

                                {config.fields.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {config.fields.map((fieldConfig, idx) => (
                                      <Badge
                                        key={`${fieldConfig.field}-${idx}`}
                                        variant="outline"
                                        className="flex items-center gap-1 pr-1 text-xs"
                                      >
                                        <span className="font-mono">{fieldConfig.field}</span>
                                        <span className="text-muted-foreground">
                                          ({TI_INDICATOR_TYPE_INFO[fieldConfig.type]?.label || fieldConfig.type})
                                        </span>
                                        <button
                                          type="button"
                                          onClick={() => setTiConfig({
                                            ...tiConfig,
                                            [source]: {
                                              ...config,
                                              fields: config.fields.filter((_, i) => i !== idx),
                                            },
                                          })}
                                          className="ml-1 hover:bg-muted rounded-full p-0.5"
                                        >
                                          <X className="h-2.5 w-2.5" />
                                        </button>
                                      </Badge>
                                    ))}
                                  </div>
                                )}

                                {!validationResult?.sample_fields?.length && (
                                  <p className="text-xs text-amber-600">
                                    Validate the index pattern above to see available fields
                                  </p>
                                )}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}

                  <p className="text-xs text-muted-foreground">
                    Common fields: source.ip, destination.ip, file.hash.md5, file.hash.sha256, url.domain
                  </p>
                </div>
              )}
            </div>

            {/* Security Settings Section (IP Allowlist & Rate Limiting) */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowSecuritySettings(!showSecuritySettings)}
              >
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  <span className="font-medium text-sm">Security Settings</span>
                  {(allowedIps.length > 0 || rateLimitEnabled) && (
                    <Badge variant="secondary" className="text-xs">
                      {allowedIps.length > 0 && `${allowedIps.length} IP${allowedIps.length > 1 ? 's' : ''}`}
                      {allowedIps.length > 0 && rateLimitEnabled && ' + '}
                      {rateLimitEnabled && 'Rate limit'}
                    </Badge>
                  )}
                </div>
                {showSecuritySettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showSecuritySettings && (
                <div className="p-3 pt-0 space-y-6">
                  {/* IP Allowlist Section */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-medium">IP Allowlist</h4>
                    <p className="text-xs text-muted-foreground">
                      Restrict which IP addresses can ship logs to this index. Leave empty to allow all IPs.
                    </p>

                    <div className="flex gap-2">
                      <Input
                        placeholder="IP or CIDR (e.g., 10.10.40.1 or 10.10.40.0/24)"
                        value={newIpEntry}
                        onChange={(e) => {
                          setNewIpEntry(e.target.value)
                          setIpError('')
                        }}
                        className="font-mono text-sm"
                      />
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => {
                          const entry = newIpEntry.trim()
                          if (!entry) return

                          // Basic validation for IP or CIDR
                          const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
                          if (!ipPattern.test(entry)) {
                            setIpError('Invalid IP or CIDR format')
                            return
                          }

                          if (allowedIps.includes(entry)) {
                            setIpError('IP already in list')
                            return
                          }

                          setAllowedIps([...allowedIps, entry])
                          setNewIpEntry('')
                          setIpError('')
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>

                    {ipError && (
                      <p className="text-xs text-destructive">{ipError}</p>
                    )}

                    {allowedIps.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {allowedIps.map((ip) => (
                          <Badge
                            key={ip}
                            variant="outline"
                            className="flex items-center gap-1 pr-1 font-mono"
                          >
                            {ip}
                            <button
                              type="button"
                              onClick={() => setAllowedIps(allowedIps.filter(i => i !== ip))}
                              className="ml-1 hover:bg-muted rounded-full p-0.5"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Rate Limiting Section */}
                  <div className="space-y-3 pt-3 border-t">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-sm font-medium">Rate Limiting</h4>
                        <p className="text-xs text-muted-foreground">
                          Limit log shipping requests to prevent abuse
                        </p>
                      </div>
                      <Switch
                        checked={rateLimitEnabled}
                        onCheckedChange={setRateLimitEnabled}
                      />
                    </div>

                    {rateLimitEnabled && (
                      <div className="grid grid-cols-2 gap-4 pt-2">
                        <div className="space-y-2">
                          <Label htmlFor="rate-requests">Requests per minute</Label>
                          <Input
                            id="rate-requests"
                            type="number"
                            min="1"
                            value={rateLimitRequests || ''}
                            onChange={(e) => setRateLimitRequests(e.target.value ? parseInt(e.target.value) : null)}
                            placeholder="100"
                          />
                          <p className="text-xs text-muted-foreground">Max API calls/min</p>
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="rate-events">Events per minute</Label>
                          <Input
                            id="rate-events"
                            type="number"
                            min="1"
                            value={rateLimitEvents || ''}
                            onChange={(e) => setRateLimitEvents(e.target.value ? parseInt(e.target.value) : null)}
                            placeholder="50000"
                          />
                          <p className="text-xs text-muted-foreground">Max log events/min</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {saveError && (
              <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
                {saveError}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={
                isSaving ||
                !formData.name ||
                !formData.pattern ||
                (detectionMode === 'push' && !formData.percolator_index)
              }
            >
              {isSaving ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Index Pattern</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this index pattern? This action
              cannot be undone. Rules using this pattern will need to be
              reassigned.
            </DialogDescription>
          </DialogHeader>
          {deleteError && (
            <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
              {deleteError}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Regenerate Token Confirmation Dialog */}
      <Dialog open={!!regenerateId} onOpenChange={() => setRegenerateId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate Auth Token</DialogTitle>
            <DialogDescription>
              Are you sure you want to regenerate the auth token? This will
              immediately invalidate the existing token. Any log shippers using
              the old token will stop working until updated with the new token.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegenerateId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRegenerateToken}
              disabled={isRegenerating}
            >
              {isRegenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Regenerating...
                </>
              ) : (
                'Regenerate Token'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
