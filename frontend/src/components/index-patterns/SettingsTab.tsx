import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  IndexPattern,
  IndexPatternMode,
  IndexPatternValidateResponse,
  indexPatternsApi,
  healthApi,
} from '@/lib/api'
import { useMode } from '@/hooks/useMode'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Check,
  X,
  Loader2,
  Database,
  ChevronDown,
  ChevronUp,
  Globe,
  Shield,
  HeartPulse,
  Lock,
} from 'lucide-react'

interface SettingsTabProps {
  pattern: IndexPattern | null
  isNew: boolean
  onSave: (data: Partial<IndexPattern>) => Promise<void>
  isSaving?: boolean
  onDirtyChange?: (isDirty: boolean) => void
}

interface FormData {
  name: string
  pattern: string
  percolator_index: string
  description: string
}

interface HealthOverrides {
  detection_latency_warning_seconds: string
  detection_latency_critical_seconds: string
  error_rate_percent: string
  no_data_minutes: string
  queue_warning: string
  queue_critical: string
}

interface GlobalDefaults {
  detection_latency_warning: number
  detection_latency_critical: number
  error_rate_percent: number
  no_data_minutes: number
  queue_warning: number
  queue_critical: number
}

export function SettingsTab({ pattern, isNew, onSave, isSaving = false, onDirtyChange }: SettingsTabProps) {
  const { isPullOnly, supportsPush } = useMode()

  // Form state
  const [formData, setFormData] = useState<FormData>({
    name: '',
    pattern: '',
    percolator_index: '',
    description: '',
  })

  // Detection mode state
  const [detectionMode, setDetectionMode] = useState<IndexPatternMode>('push')
  const [pollIntervalMinutes, setPollIntervalMinutes] = useState(5)
  const [timestampField, setTimestampField] = useState('@timestamp')
  const [availableTimeFields, setAvailableTimeFields] = useState<string[]>([])
  const [isLoadingTimeFields, setIsLoadingTimeFields] = useState(false)

  // Validation state
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<IndexPatternValidateResponse | null>(null)
  const [percolatorIndexManuallyEdited, setPercolatorIndexManuallyEdited] = useState(false)

  // Health alerting state
  const [enableHealthAlerting, setEnableHealthAlerting] = useState(true)
  const [showHealthSettings, setShowHealthSettings] = useState(false)
  const [healthOverrides, setHealthOverrides] = useState<HealthOverrides>({
    detection_latency_warning_seconds: '',
    detection_latency_critical_seconds: '',
    error_rate_percent: '',
    no_data_minutes: '',
    queue_warning: '',
    queue_critical: '',
  })
  const [globalDefaults, setGlobalDefaults] = useState<GlobalDefaults>({
    detection_latency_warning: 2,
    detection_latency_critical: 10,
    error_rate_percent: 5,
    no_data_minutes: 15,
    queue_warning: 10000,
    queue_critical: 100000,
  })

  // GeoIP enrichment state
  const [geoipFields, setGeoipFields] = useState<string[]>([])
  const [showGeoipSettings, setShowGeoipSettings] = useState(false)

  // Security settings state (push mode only)
  const [showSecuritySettings, setShowSecuritySettings] = useState(false)
  const [allowedIps, setAllowedIps] = useState<string[]>([])
  const [newIpEntry, setNewIpEntry] = useState('')
  const [ipError, setIpError] = useState('')
  const [rateLimitEnabled, setRateLimitEnabled] = useState(false)
  const [rateLimitRequests, setRateLimitRequests] = useState<number | null>(100)
  const [rateLimitEvents, setRateLimitEvents] = useState<number | null>(50000)

  // Error state
  const [saveError, setSaveError] = useState('')

  // Initialize form from pattern
  useEffect(() => {
    if (pattern) {
      setFormData({
        name: pattern.name,
        pattern: pattern.pattern,
        percolator_index: pattern.percolator_index,
        description: pattern.description || '',
      })
      setDetectionMode(pattern.mode)
      setPollIntervalMinutes(pattern.poll_interval_minutes || 5)
      setTimestampField(pattern.timestamp_field || '@timestamp')
      setEnableHealthAlerting(pattern.health_alerting_enabled ?? true)
      setGeoipFields(pattern.geoip_fields || [])
      setAllowedIps(pattern.allowed_ips || [])
      setRateLimitEnabled(pattern.rate_limit_enabled || false)
      setRateLimitRequests(pattern.rate_limit_requests_per_minute || 100)
      setRateLimitEvents(pattern.rate_limit_events_per_minute || 50000)

      // Set health overrides from pattern
      const overrides = pattern.health_overrides || {}
      setHealthOverrides({
        detection_latency_warning_seconds: overrides.detection_latency_warning_ms
          ? String(overrides.detection_latency_warning_ms / 1000) : '',
        detection_latency_critical_seconds: overrides.detection_latency_critical_ms
          ? String(overrides.detection_latency_critical_ms / 1000) : '',
        error_rate_percent: overrides.error_rate_percent ? String(overrides.error_rate_percent) : '',
        no_data_minutes: overrides.no_data_minutes ? String(overrides.no_data_minutes) : '',
        queue_warning: overrides.queue_warning ? String(overrides.queue_warning) : '',
        queue_critical: overrides.queue_critical ? String(overrides.queue_critical) : '',
      })
    } else {
      // Create mode - reset to defaults
      setFormData({
        name: '',
        pattern: '',
        percolator_index: '',
        description: '',
      })
      setDetectionMode(isPullOnly ? 'pull' : 'push')
      setPollIntervalMinutes(5)
      setTimestampField('@timestamp')
      setEnableHealthAlerting(true)
      setGeoipFields([])
      setAllowedIps([])
      setRateLimitEnabled(false)
      setRateLimitRequests(100)
      setRateLimitEvents(50000)
      setHealthOverrides({
        detection_latency_warning_seconds: '',
        detection_latency_critical_seconds: '',
        error_rate_percent: '',
        no_data_minutes: '',
        queue_warning: '',
        queue_critical: '',
      })
    }
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(false)
    setSaveError('')
  }, [pattern, isPullOnly])

  // Track dirty state
  const isDirty = useMemo(() => {
    if (isNew) {
      // For new patterns, dirty if any required field has content
      return formData.name.trim() !== '' || formData.pattern.trim() !== ''
    }
    if (!pattern) return false

    // Compare current form state to saved pattern
    const overrides = pattern.health_overrides || {}
    return (
      formData.name !== pattern.name ||
      formData.pattern !== pattern.pattern ||
      formData.percolator_index !== pattern.percolator_index ||
      formData.description !== (pattern.description || '') ||
      detectionMode !== pattern.mode ||
      (detectionMode === 'pull' && pollIntervalMinutes !== (pattern.poll_interval_minutes || 5)) ||
      (detectionMode === 'pull' && timestampField !== (pattern.timestamp_field || '@timestamp')) ||
      enableHealthAlerting !== (pattern.health_alerting_enabled ?? true) ||
      JSON.stringify(geoipFields) !== JSON.stringify(pattern.geoip_fields || []) ||
      JSON.stringify(allowedIps) !== JSON.stringify(pattern.allowed_ips || []) ||
      rateLimitEnabled !== (pattern.rate_limit_enabled || false) ||
      (rateLimitEnabled && rateLimitRequests !== (pattern.rate_limit_requests_per_minute || 100)) ||
      (rateLimitEnabled && rateLimitEvents !== (pattern.rate_limit_events_per_minute || 50000)) ||
      healthOverrides.detection_latency_warning_seconds !== (overrides.detection_latency_warning_ms ? String(overrides.detection_latency_warning_ms / 1000) : '') ||
      healthOverrides.detection_latency_critical_seconds !== (overrides.detection_latency_critical_ms ? String(overrides.detection_latency_critical_ms / 1000) : '') ||
      healthOverrides.error_rate_percent !== (overrides.error_rate_percent ? String(overrides.error_rate_percent) : '') ||
      healthOverrides.no_data_minutes !== (overrides.no_data_minutes ? String(overrides.no_data_minutes) : '') ||
      healthOverrides.queue_warning !== (overrides.queue_warning ? String(overrides.queue_warning) : '') ||
      healthOverrides.queue_critical !== (overrides.queue_critical ? String(overrides.queue_critical) : '')
    )
  }, [
    isNew, pattern, formData, detectionMode, pollIntervalMinutes, timestampField,
    enableHealthAlerting, geoipFields, allowedIps, rateLimitEnabled,
    rateLimitRequests, rateLimitEvents, healthOverrides
  ])

  // Notify parent of dirty state changes
  useEffect(() => {
    onDirtyChange?.(isDirty)
  }, [isDirty, onDirtyChange])

  // Load global defaults
  useEffect(() => {
    const loadGlobalDefaults = async () => {
      try {
        const settings = await healthApi.getSettings()
        setGlobalDefaults({
          detection_latency_warning: settings.detection_latency_warning_ms / 1000,
          detection_latency_critical: settings.detection_latency_critical_ms / 1000,
          error_rate_percent: settings.error_rate_percent,
          no_data_minutes: settings.no_data_minutes,
          queue_warning: settings.queue_warning,
          queue_critical: settings.queue_critical,
        })
      } catch {
        // Continue with hardcoded defaults
      }
    }
    loadGlobalDefaults()
  }, [])

  // Load time fields for existing pattern
  const loadTimeFields = useCallback(async (patternId: string) => {
    setIsLoadingTimeFields(true)
    try {
      const fields = await indexPatternsApi.getTimeFields(patternId)
      setAvailableTimeFields(fields)
    } catch {
      setAvailableTimeFields([])
    } finally {
      setIsLoadingTimeFields(false)
    }
  }, [])

  // Auto-generate percolator index
  const handlePatternChange = (value: string) => {
    setFormData({ ...formData, pattern: value })
    setValidationResult(null)

    // Auto-generate percolator index if not manually edited
    if (!percolatorIndexManuallyEdited && value) {
      const baseName = value
        .replace(/[*?]/g, '')
        .replace(/-+$/, '')
        .replace(/^-+/, '')
        .split('-')
        .filter(Boolean)
        .slice(0, 2)
        .join('-')
      if (baseName) {
        setFormData((prev) => ({
          ...prev,
          pattern: value,
          percolator_index: `chad-percolator-${baseName}`,
        }))
      }
    }
  }

  // Validate pattern
  const handleValidate = async () => {
    if (!formData.pattern) return
    setIsValidating(true)
    try {
      const result = await indexPatternsApi.validate({ pattern: formData.pattern })
      setValidationResult(result)
    } catch (err) {
      setValidationResult({
        valid: false,
        indices: [],
        total_docs: 0,
        error: err instanceof Error ? err.message : 'Validation failed',
      })
    } finally {
      setIsValidating(false)
    }
  }

  // Get index suffix for endpoints
  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
  }

  // Validate IP address
  const validateIp = (ip: string): boolean => {
    // Basic IP address or CIDR validation
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip)
  }

  // Add IP to allowlist
  const handleAddIp = () => {
    const ip = newIpEntry.trim()
    if (!ip) return

    if (!validateIp(ip)) {
      setIpError('Invalid IP address or CIDR notation')
      return
    }

    if (allowedIps.includes(ip)) {
      setIpError('IP already in list')
      return
    }

    setAllowedIps([...allowedIps, ip])
    setNewIpEntry('')
    setIpError('')
  }

  // Handle save
  const handleSave = async () => {
    setSaveError('')

    // Build health overrides object
    const healthOverridesData: Record<string, number> = {}
    if (healthOverrides.detection_latency_warning_seconds) {
      healthOverridesData.detection_latency_warning_ms = parseFloat(healthOverrides.detection_latency_warning_seconds) * 1000
    }
    if (healthOverrides.detection_latency_critical_seconds) {
      healthOverridesData.detection_latency_critical_ms = parseFloat(healthOverrides.detection_latency_critical_seconds) * 1000
    }
    if (healthOverrides.error_rate_percent) {
      healthOverridesData.error_rate_percent = parseFloat(healthOverrides.error_rate_percent)
    }
    if (healthOverrides.no_data_minutes) {
      healthOverridesData.no_data_minutes = parseInt(healthOverrides.no_data_minutes)
    }
    if (healthOverrides.queue_warning) {
      healthOverridesData.queue_warning = parseInt(healthOverrides.queue_warning)
    }
    if (healthOverrides.queue_critical) {
      healthOverridesData.queue_critical = parseInt(healthOverrides.queue_critical)
    }

    const data: Partial<IndexPattern> = {
      name: formData.name,
      pattern: formData.pattern,
      percolator_index: detectionMode === 'push' ? formData.percolator_index : `chad-percolator-${formData.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
      description: formData.description || undefined,
      mode: detectionMode,
      poll_interval_minutes: detectionMode === 'pull' ? pollIntervalMinutes : undefined,
      timestamp_field: detectionMode === 'pull' ? timestampField : undefined,
      health_alerting_enabled: enableHealthAlerting,
      health_overrides: Object.keys(healthOverridesData).length > 0 ? healthOverridesData : undefined,
      geoip_fields: geoipFields.length > 0 ? geoipFields : undefined,
      allowed_ips: allowedIps.length > 0 ? allowedIps : undefined,
      rate_limit_enabled: rateLimitEnabled,
      rate_limit_requests_per_minute: rateLimitEnabled ? rateLimitRequests || undefined : undefined,
      rate_limit_events_per_minute: rateLimitEnabled ? rateLimitEvents || undefined : undefined,
    }

    try {
      await onSave(data)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save')
    }
  }

  return (
    <div className="space-y-6">
      {saveError && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {saveError}
        </div>
      )}

      {/* Basic Settings */}
      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="name">Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
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
              {isValidating ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Validate'}
            </Button>
          </div>
          {validationResult && (
            <div
              className={`text-sm p-2 rounded ${
                validationResult.valid
                  ? 'bg-green-500/10 text-green-600 dark:text-green-400'
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
              Where deployed rules will be stored. Must start with "chad-percolator-".
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="description">Description (optional)</Label>
          <Input
            id="description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Windows event logs from Sysmon"
          />
        </div>
      </div>

      {/* Detection Mode */}
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
                <SelectItem value="push">Push (Real-time via /logs endpoint)</SelectItem>
              )}
              <SelectItem value="pull">Pull (Scheduled OpenSearch queries)</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {detectionMode === 'push'
              ? 'Logs are pushed to CHAD via the /logs endpoint for real-time detection.'
              : 'CHAD periodically queries OpenSearch for new logs matching deployed rules.'}
          </p>
          {isPullOnly && (
            <p className="text-xs text-amber-600">This deployment only supports pull mode.</p>
          )}
        </div>

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
                How often to query OpenSearch (1-1440 minutes).
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="timestamp-field">Timestamp Field</Label>
              <Select value={timestampField} onValueChange={setTimestampField}>
                <SelectTrigger className="font-mono text-sm">
                  <SelectValue placeholder="Select timestamp field" />
                </SelectTrigger>
                <SelectContent>
                  {isLoadingTimeFields ? (
                    <div className="p-2 text-xs text-muted-foreground flex items-center gap-2">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      Loading...
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
                Field used to track processed logs.
              </p>
              {pattern && availableTimeFields.length === 0 && !isLoadingTimeFields && (
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="h-auto p-0 text-xs"
                  onClick={() => loadTimeFields(pattern.id)}
                >
                  Load available time fields
                </Button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Endpoint Preview for Push Mode */}
      {detectionMode === 'push' && formData.percolator_index?.startsWith('chad-percolator-') && (
        <div className="space-y-3 p-3 bg-muted rounded-md">
          <Label className="text-sm font-medium">Log Shipper Endpoints (Preview)</Label>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-background p-2 rounded font-mono break-all">
                POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}
              </code>
              <span className="text-xs text-muted-foreground">sync</span>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-background p-2 rounded font-mono break-all">
                POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}/queue
              </code>
              <span className="text-xs text-green-600 dark:text-green-400 font-medium">recommended</span>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            {pattern ? 'Use the auth token to authenticate requests.' : 'An auth token will be generated when you save.'}
          </p>
        </div>
      )}

      {/* Health Alerting (Collapsible) */}
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
          {showHealthSettings ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
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
              <div className="space-y-4 pt-4 border-t">
                <p className="text-xs text-muted-foreground">
                  Leave empty to use global defaults from the Health page.
                </p>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="detection-warning">Latency Warning (s)</Label>
                    <Input
                      id="detection-warning"
                      type="number"
                      min="1"
                      step="0.1"
                      placeholder={`Global: ${globalDefaults.detection_latency_warning}`}
                      value={healthOverrides.detection_latency_warning_seconds}
                      onChange={(e) => setHealthOverrides({ ...healthOverrides, detection_latency_warning_seconds: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="detection-critical">Latency Critical (s)</Label>
                    <Input
                      id="detection-critical"
                      type="number"
                      min="1"
                      step="0.1"
                      placeholder={`Global: ${globalDefaults.detection_latency_critical}`}
                      value={healthOverrides.detection_latency_critical_seconds}
                      onChange={(e) => setHealthOverrides({ ...healthOverrides, detection_latency_critical_seconds: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="error-rate">Error Rate (%)</Label>
                    <Input
                      id="error-rate"
                      type="number"
                      min="0"
                      step="0.1"
                      placeholder={`Global: ${globalDefaults.error_rate_percent}`}
                      value={healthOverrides.error_rate_percent}
                      onChange={(e) => setHealthOverrides({ ...healthOverrides, error_rate_percent: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="no-data">No Data (min)</Label>
                    <Input
                      id="no-data"
                      type="number"
                      min="1"
                      placeholder={`Global: ${globalDefaults.no_data_minutes}`}
                      value={healthOverrides.no_data_minutes}
                      onChange={(e) => setHealthOverrides({ ...healthOverrides, no_data_minutes: e.target.value })}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* GeoIP Enrichment (Collapsible) */}
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
          {showGeoipSettings ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>

        {showGeoipSettings && (
          <div className="p-3 pt-0 space-y-4">
            <p className="text-xs text-muted-foreground">
              Select IP address fields to enrich with geographic data.
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
                <SelectValue placeholder="Add IP fields..." />
              </SelectTrigger>
              <SelectContent>
                {validationResult?.sample_fields?.length ? (
                  validationResult.sample_fields
                    .filter((f) => !geoipFields.includes(f))
                    .map((field) => (
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

            {geoipFields.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {geoipFields.map((field) => (
                  <Badge key={field} variant="outline" className="flex items-center gap-1 pr-1">
                    {field}
                    <button
                      type="button"
                      onClick={() => setGeoipFields(geoipFields.filter((f) => f !== field))}
                      className="ml-1 hover:bg-muted rounded-full p-0.5"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}

            <p className="text-xs text-muted-foreground">
              Common fields: source.ip, destination.ip, client.ip
            </p>
          </div>
        )}
      </div>

      {/* TI Enrichment placeholder */}
      <div className="border rounded-lg">
        <button
          type="button"
          className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors opacity-50 cursor-not-allowed"
          disabled
        >
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            <span className="font-medium text-sm">Threat Intelligence Enrichment</span>
            <Badge variant="outline" className="text-xs">Use edit dialog</Badge>
          </div>
          <ChevronDown className="h-4 w-4" />
        </button>
      </div>

      {/* Security Settings (Push mode only) */}
      {detectionMode === 'push' && (
        <div className="border rounded-lg">
          <button
            type="button"
            className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
            onClick={() => setShowSecuritySettings(!showSecuritySettings)}
          >
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              <span className="font-medium text-sm">Security Settings</span>
            </div>
            {showSecuritySettings ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>

          {showSecuritySettings && (
            <div className="p-3 pt-0 space-y-4">
              {/* IP Allowlist */}
              <div className="space-y-2">
                <Label>IP Allowlist (optional)</Label>
                <p className="text-xs text-muted-foreground">
                  Restrict log submissions to specific IP addresses or CIDR ranges.
                </p>
                <div className="flex gap-2">
                  <Input
                    value={newIpEntry}
                    onChange={(e) => {
                      setNewIpEntry(e.target.value)
                      setIpError('')
                    }}
                    placeholder="192.168.1.0/24"
                    className="font-mono text-sm"
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddIp())}
                  />
                  <Button type="button" variant="secondary" size="sm" onClick={handleAddIp}>
                    Add
                  </Button>
                </div>
                {ipError && <p className="text-xs text-destructive">{ipError}</p>}
                {allowedIps.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {allowedIps.map((ip) => (
                      <Badge key={ip} variant="outline" className="flex items-center gap-1 pr-1 font-mono">
                        {ip}
                        <button
                          type="button"
                          onClick={() => setAllowedIps(allowedIps.filter((i) => i !== ip))}
                          className="ml-1 hover:bg-muted rounded-full p-0.5"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              {/* Rate Limiting */}
              <div className="space-y-2 pt-4 border-t">
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="rate-limit" className="font-normal">Rate Limiting</Label>
                    <p className="text-xs text-muted-foreground">Limit requests and events per minute</p>
                  </div>
                  <Switch
                    id="rate-limit"
                    checked={rateLimitEnabled}
                    onCheckedChange={setRateLimitEnabled}
                  />
                </div>

                {rateLimitEnabled && (
                  <div className="grid grid-cols-2 gap-4 pt-2">
                    <div className="space-y-2">
                      <Label htmlFor="rate-requests">Requests/min</Label>
                      <Input
                        id="rate-requests"
                        type="number"
                        min="1"
                        value={rateLimitRequests || ''}
                        onChange={(e) => setRateLimitRequests(parseInt(e.target.value) || null)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="rate-events">Events/min</Label>
                      <Input
                        id="rate-events"
                        type="number"
                        min="1"
                        value={rateLimitEvents || ''}
                        onChange={(e) => setRateLimitEvents(parseInt(e.target.value) || null)}
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Save Button */}
      <div className="flex justify-end pt-4 border-t">
        <Button onClick={handleSave} disabled={isSaving || !formData.name || !formData.pattern}>
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : isNew ? (
            'Create Pattern'
          ) : (
            'Save Changes'
          )}
        </Button>
      </div>
    </div>
  )
}
