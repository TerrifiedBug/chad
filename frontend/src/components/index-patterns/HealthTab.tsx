import { useState, useEffect } from 'react'
import { IndexPattern, indexPatternsApi, healthApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Loader2, Save, Info } from 'lucide-react'

interface HealthTabProps {
  pattern: IndexPattern
  onPatternUpdated: (pattern: IndexPattern) => void
}

interface HealthOverrides {
  detection_latency_warning_seconds: string
  detection_latency_critical_seconds: string
  error_rate_percent: string
  no_data_minutes: string
  queue_warning: string
  queue_critical: string
}

export function HealthTab({ pattern, onPatternUpdated }: HealthTabProps) {
  const { showToast } = useToast()
  const [enableHealthAlerting, setEnableHealthAlerting] = useState(pattern.health_alerting_enabled ?? true)
  const [healthOverrides, setHealthOverrides] = useState<HealthOverrides>({
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
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)

  // Load global defaults
  useEffect(() => {
    const loadGlobalDefaults = async () => {
      setIsLoading(true)
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
      } finally {
        setIsLoading(false)
      }
    }
    loadGlobalDefaults()
  }, [])

  // Initialize overrides from pattern
  useEffect(() => {
    setEnableHealthAlerting(pattern.health_alerting_enabled ?? true)
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
  }, [pattern])

  const handleSave = async () => {
    setIsSaving(true)
    try {
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

      const updated = await indexPatternsApi.update(pattern.id, {
        health_alerting_enabled: enableHealthAlerting,
        health_overrides: Object.keys(healthOverridesData).length > 0 ? healthOverridesData : undefined,
      })
      onPatternUpdated(updated)
      showToast('Health settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Health Alerting</h3>
        <p className="text-sm text-muted-foreground">
          Configure health monitoring thresholds for this index pattern. Leave fields empty to use global defaults.
        </p>
      </div>

      {/* Enable/Disable Health Alerting */}
      <div className="flex items-center justify-between p-4 border rounded-lg">
        <div>
          <Label className="text-base">Enable Health Alerting</Label>
          <p className="text-sm text-muted-foreground">
            Send alerts when health thresholds are exceeded for this pattern.
          </p>
        </div>
        <Switch
          checked={enableHealthAlerting}
          onCheckedChange={setEnableHealthAlerting}
        />
      </div>

      {enableHealthAlerting && (
        <div className="space-y-6">
          {/* Info banner */}
          <div className="flex items-start gap-3 p-4 bg-muted/50 rounded-lg">
            <Info className="h-5 w-5 text-blue-600 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium">Using Global Defaults</p>
              <p className="text-muted-foreground">
                Empty fields will use the global defaults from Settings → Health Monitoring.
                Enter a value to override for this pattern only.
              </p>
            </div>
          </div>

          {/* Detection Latency */}
          <div className="space-y-4">
            <Label className="text-base">Detection Latency Thresholds</Label>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="latency-warning">Warning (seconds)</Label>
                <Input
                  id="latency-warning"
                  type="number"
                  min="0.1"
                  step="0.1"
                  placeholder={`Global: ${globalDefaults.detection_latency_warning}s`}
                  value={healthOverrides.detection_latency_warning_seconds}
                  onChange={(e) => setHealthOverrides({ ...healthOverrides, detection_latency_warning_seconds: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="latency-critical">Critical (seconds)</Label>
                <Input
                  id="latency-critical"
                  type="number"
                  min="0.1"
                  step="0.1"
                  placeholder={`Global: ${globalDefaults.detection_latency_critical}s`}
                  value={healthOverrides.detection_latency_critical_seconds}
                  onChange={(e) => setHealthOverrides({ ...healthOverrides, detection_latency_critical_seconds: e.target.value })}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Alert when average time from log ingestion to alert generation exceeds these thresholds.
            </p>
          </div>

          {/* Error Rate */}
          <div className="space-y-4">
            <Label className="text-base">Error Rate Threshold</Label>
            <div className="max-w-xs">
              <div className="space-y-2">
                <Label htmlFor="error-rate">Error Rate (%)</Label>
                <Input
                  id="error-rate"
                  type="number"
                  min="0"
                  max="100"
                  step="0.1"
                  placeholder={`Global: ${globalDefaults.error_rate_percent}%`}
                  value={healthOverrides.error_rate_percent}
                  onChange={(e) => setHealthOverrides({ ...healthOverrides, error_rate_percent: e.target.value })}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Alert when the percentage of failed log processing exceeds this threshold.
            </p>
          </div>

          {/* No Data */}
          <div className="space-y-4">
            <Label className="text-base">No Data Threshold</Label>
            <div className="max-w-xs">
              <div className="space-y-2">
                <Label htmlFor="no-data">No Data (minutes)</Label>
                <Input
                  id="no-data"
                  type="number"
                  min="1"
                  placeholder={`Global: ${globalDefaults.no_data_minutes} min`}
                  value={healthOverrides.no_data_minutes}
                  onChange={(e) => setHealthOverrides({ ...healthOverrides, no_data_minutes: e.target.value })}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Alert when no logs have been received for this many minutes.
            </p>
          </div>

          {/* Queue Depth (Push mode only) */}
          {pattern.mode === 'push' && (
            <div className="space-y-4">
              <Label className="text-base">Queue Depth Thresholds</Label>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="queue-warning">Warning</Label>
                  <Input
                    id="queue-warning"
                    type="number"
                    min="1"
                    placeholder={`Global: ${globalDefaults.queue_warning.toLocaleString()}`}
                    value={healthOverrides.queue_warning}
                    onChange={(e) => setHealthOverrides({ ...healthOverrides, queue_warning: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="queue-critical">Critical</Label>
                  <Input
                    id="queue-critical"
                    type="number"
                    min="1"
                    placeholder={`Global: ${globalDefaults.queue_critical.toLocaleString()}`}
                    value={healthOverrides.queue_critical}
                    onChange={(e) => setHealthOverrides({ ...healthOverrides, queue_critical: e.target.value })}
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Alert when the processing queue depth exceeds these thresholds.
              </p>
            </div>
          )}
        </div>
      )}

      <div className="flex justify-end pt-4 border-t">
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              Save Changes
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
