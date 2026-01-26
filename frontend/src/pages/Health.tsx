import { useEffect, useState } from 'react'
import { healthApi, IndexHealth, HealthStatus, HealthSettings } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AlertCircle, CheckCircle2, AlertTriangle, Activity, Clock, Zap, Bell, Settings, ChevronDown, ChevronUp, Save, Loader2, RefreshCw, Server, ChevronRight } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import { HealthCheckSettings } from '@/components/HealthCheckSettings'

interface ServiceHealth {
  service_type: string
  service_name: string
  status: string
  last_check: string
}

interface HealthCheckLog {
  service_type: string
  service_name: string
  status: string
  error_message: string | null
  checked_at: string
}

interface ServiceHealthResponse {
  services: ServiceHealth[]
  recent_checks: HealthCheckLog[]
}

const statusColors: Record<HealthStatus, string> = {
  healthy: 'text-green-600',
  warning: 'text-yellow-600',
  critical: 'text-red-600',
}

const statusBgColors: Record<HealthStatus, string> = {
  healthy: 'bg-green-50 dark:bg-green-900/20',
  warning: 'bg-yellow-50 dark:bg-yellow-900/20',
  critical: 'bg-red-50 dark:bg-red-900/20',
}

const StatusIcon = ({ status }: { status: HealthStatus | string }) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle2 className="h-5 w-5 text-green-600" />
    case 'warning':
      return <AlertTriangle className="h-5 w-5 text-yellow-600" />
    case 'critical':
    case 'unhealthy':
      return <AlertCircle className="h-5 w-5 text-red-600" />
    default:
      return <AlertCircle className="h-5 w-5 text-muted-foreground" />
  }
}

const formatDateTime = (dateStr: string) => {
  const date = new Date(dateStr)
  return date.toLocaleString()
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return n.toString()
}

export default function HealthPage() {
  const { hasPermission } = useAuth()
  const [health, setHealth] = useState<IndexHealth[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Service health state
  const [serviceHealth, setServiceHealth] = useState<ServiceHealthResponse | null>(null)
  const [serviceHealthLoading, setServiceHealthLoading] = useState(true)

  // Status popover state
  const [statusPopoverOpen, setStatusPopoverOpen] = useState(false)

  // Settings state
  const [showSettings, setShowSettings] = useState(false)
  const [settings, setSettings] = useState<HealthSettings | null>(null)
  const [settingsForm, setSettingsForm] = useState<HealthSettings | null>(null)
  const [isSavingSettings, setIsSavingSettings] = useState(false)
  const [settingsError, setSettingsError] = useState('')

  useEffect(() => {
    loadHealth()
    loadServiceHealth()
    loadSettings()
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadHealth()
      loadServiceHealth()
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadHealth = async () => {
    try {
      const data = await healthApi.listIndices()
      setHealth(data)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load health data')
    } finally {
      setIsLoading(false)
    }
  }

  const loadServiceHealth = async () => {
    setServiceHealthLoading(true)
    try {
      const data = await api.get<ServiceHealthResponse>('/health/status')
      setServiceHealth(data)
    } catch (err) {
      console.error('Failed to load service health:', err)
    } finally {
      setServiceHealthLoading(false)
    }
  }

  const loadSettings = async () => {
    try {
      const data = await healthApi.getSettings()
      setSettings(data)
      setSettingsForm(data)
    } catch {
      // Settings may require admin - silently ignore
    }
  }

  const handleSaveSettings = async () => {
    if (!settingsForm) return

    setIsSavingSettings(true)
    setSettingsError('')
    try {
      const updated = await healthApi.updateSettings(settingsForm)
      setSettings(updated)
      setSettingsForm(updated)
    } catch (err) {
      setSettingsError(err instanceof Error ? err.message : 'Failed to save settings')
    } finally {
      setIsSavingSettings(false)
    }
  }

  const hasSettingsChanged = settings && settingsForm && (
    settings.no_data_minutes !== settingsForm.no_data_minutes ||
    settings.error_rate_percent !== settingsForm.error_rate_percent ||
    settings.latency_ms !== settingsForm.latency_ms ||
    settings.queue_warning !== settingsForm.queue_warning ||
    settings.queue_critical !== settingsForm.queue_critical
  )

  // Calculate overall status
  const overallStatus: HealthStatus = health.reduce((worst, h) => {
    if (h.status === 'critical') return 'critical'
    if (h.status === 'warning' && worst !== 'critical') return 'warning'
    return worst
  }, 'healthy' as HealthStatus)

  // Get problematic index patterns for the popover
  const problematicPatterns = health.filter(h => h.status === 'warning' || h.status === 'critical')

  // Get problematic external services for the popover
  const problematicServices = serviceHealth?.services.filter(s => s.status === 'warning' || s.status === 'unhealthy') || []

  // Aggregate totals
  const totals = health.reduce(
    (acc, h) => ({
      logs: acc.logs + h.totals_24h.logs_received,
      errors: acc.errors + h.totals_24h.logs_errored,
      alerts: acc.alerts + h.totals_24h.alerts_generated,
    }),
    { logs: 0, errors: 0, alerts: 0 }
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading health data...</div>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">System Health</h1>
          <p className="text-muted-foreground">Monitor index pattern health and performance</p>
        </div>
        <Popover open={statusPopoverOpen} onOpenChange={setStatusPopoverOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              className={`flex items-center gap-2 px-4 py-2 rounded-lg ${statusBgColors[overallStatus]} hover:${statusBgColors[overallStatus]}`}
            >
              <StatusIcon status={overallStatus} />
              <span className={`font-medium capitalize ${statusColors[overallStatus]}`}>
                {overallStatus === 'healthy' ? 'All Systems Healthy' : `System ${overallStatus}`}
              </span>
              {(problematicPatterns.length > 0 || problematicServices.length > 0) && (
                <ChevronDown className={`h-4 w-4 transition-transform ${statusPopoverOpen ? 'rotate-180' : ''}`} />
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-80" align="end">
            {(problematicPatterns.length === 0 && problematicServices.length === 0) ? (
              <div className="text-sm text-muted-foreground">All systems operating normally</div>
            ) : (
              <div className="space-y-3">
                {problematicPatterns.length > 0 && (
                  <div>
                    <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-600" />
                      Index Patterns
                    </h4>
                    <div className="space-y-1">
                      {problematicPatterns.map((pattern, index) => (
                        <div key={`${pattern.index_pattern_id}-${index}`} className="flex items-center justify-between text-sm p-2 rounded bg-muted/50">
                          <div className="flex items-center gap-2 flex-1 min-w-0">
                            <StatusIcon status={pattern.status} />
                            <span className="truncate font-medium">{pattern.index_pattern_name}</span>
                          </div>
                          <span className={`text-xs capitalize ${statusColors[pattern.status as HealthStatus]}`}>
                            {pattern.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {problematicServices.length > 0 && (
                  <div>
                    <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                      <Server className="h-4 w-4 text-red-600" />
                      External Services
                    </h4>
                    <div className="space-y-1">
                      {problematicServices.map((service, index) => (
                        <div key={`${service.service_type}-${index}`} className="flex items-center justify-between text-sm p-2 rounded bg-muted/50">
                          <div className="flex items-center gap-2 flex-1 min-w-0">
                            <StatusIcon status={service.status} />
                            <span className="truncate font-medium">{service.service_name}</span>
                          </div>
                          <span className="text-xs text-muted-foreground capitalize">
                            {service.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <Button
                  variant="link"
                  size="sm"
                  className="w-full"
                  onClick={() => setStatusPopoverOpen(false)}
                >
                  View details in dashboard below
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            )}
          </PopoverContent>
        </Popover>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {/* Global Settings Panel - Merged */}
      {hasPermission('manage_settings') && (
        <Card>
          <button
            type="button"
            className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
            onClick={() => setShowSettings(!showSettings)}
          >
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span className="font-medium">Global Settings</span>
            </div>
            {showSettings ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>

          {showSettings && (
            <CardContent className="pt-0 border-t space-y-6">
              {/* Alerting Thresholds Section */}
              <div>
                <h4 className="text-sm font-medium mb-2">Alerting Thresholds</h4>
                <p className="text-xs text-muted-foreground mb-4">
                  These thresholds are used by default for all index patterns unless overridden.
                </p>

                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="no-data-minutes" className="text-xs">No Data (min)</Label>
                    <Input
                      id="no-data-minutes"
                      type="number"
                      min="1"
                      value={settingsForm!.no_data_minutes}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm!,
                          no_data_minutes: parseInt(e.target.value) || 0,
                        })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="error-rate" className="text-xs">Error Rate (%)</Label>
                    <Input
                      id="error-rate"
                      type="number"
                      min="0"
                      step="0.1"
                      value={settingsForm!.error_rate_percent}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm!,
                          error_rate_percent: parseFloat(e.target.value) || 0,
                        })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="latency-ms" className="text-xs">Latency (ms)</Label>
                    <Input
                      id="latency-ms"
                      type="number"
                      min="1"
                      value={settingsForm!.latency_ms}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm!,
                          latency_ms: parseInt(e.target.value) || 0,
                        })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="queue-warning" className="text-xs">Queue Warning</Label>
                    <Input
                      id="queue-warning"
                      type="number"
                      min="1"
                      value={settingsForm!.queue_warning}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm!,
                          queue_warning: parseInt(e.target.value) || 0,
                        })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="queue-critical" className="text-xs">Queue Critical</Label>
                    <Input
                      id="queue-critical"
                      type="number"
                      min="1"
                      value={settingsForm!.queue_critical}
                      onChange={(e) =>
                        setSettingsForm({
                          ...settingsForm!,
                          queue_critical: parseInt(e.target.value) || 0,
                        })
                      }
                    />
                  </div>
                </div>
              </div>

              {/* Health Check Intervals Section */}
              <div className="border-t pt-4">
                <h4 className="text-sm font-medium mb-2">Health Check Intervals</h4>
                <p className="text-xs text-muted-foreground mb-4">
                  Configure how frequently the system checks health status of external services.
                </p>
                <HealthCheckSettings />
              </div>

              {settingsError && (
                <div className="text-sm text-destructive">{settingsError}</div>
              )}

              <div className="flex justify-end pt-2 border-t">
                <Button
                  onClick={handleSaveSettings}
                  disabled={!hasSettingsChanged || isSavingSettings}
                >
                  {isSavingSettings ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="h-4 w-4 mr-2" />
                      Save Settings
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                <Activity className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Logs (24h)</p>
                <p className="text-2xl font-bold">{formatNumber(totals.logs)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
                <AlertCircle className="h-5 w-5 text-red-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Errors (24h)</p>
                <p className="text-2xl font-bold">{formatNumber(totals.errors)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
                <Bell className="h-5 w-5 text-yellow-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Alerts (24h)</p>
                <p className="text-2xl font-bold">{formatNumber(totals.alerts)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                <Zap className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Index Patterns</p>
                <p className="text-2xl font-bold">{health.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* External Services Health */}
      {hasPermission('manage_settings') && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <Server className="h-5 w-5" />
                External Services
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={loadServiceHealth}
                disabled={serviceHealthLoading}
              >
                <RefreshCw className={`h-4 w-4 ${serviceHealthLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {serviceHealthLoading ? (
              <div className="text-center py-4 text-muted-foreground">Loading service health...</div>
            ) : !serviceHealth || serviceHealth.services.length === 0 ? (
              <div className="text-center py-4 text-muted-foreground">No external services configured</div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {serviceHealth.services.map((service) => (
                  <Card
                    key={service.service_type}
                    className={
                      service.status === 'unhealthy'
                        ? 'bg-red-50 dark:bg-red-900/20'
                        : service.status === 'warning'
                        ? 'bg-yellow-50 dark:bg-yellow-900/20'
                        : 'bg-green-50 dark:bg-green-900/20'
                    }
                  >
                    <CardContent className="pt-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-medium">{service.service_name}</h4>
                          <p className="text-xs text-muted-foreground mt-1">
                            Last check: {service.last_check ? (
                              <TimestampTooltip timestamp={service.last_check}>
                                <span>{formatDateTime(service.last_check)}</span>
                              </TimestampTooltip>
                            ) : 'Never'}
                          </p>
                        </div>
                        <StatusIcon status={service.status} />
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Index Pattern Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {health.length === 0 ? (
          <div className="col-span-full text-center py-12 text-muted-foreground">
            No index patterns configured. Add index patterns to see health data.
          </div>
        ) : (
          health.map((h) => (
            <Card key={h.index_pattern_id} className={statusBgColors[h.status]}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{h.index_pattern_name}</CardTitle>
                  <StatusIcon status={h.status} />
                </div>
                <p className="text-sm text-muted-foreground font-mono">{h.pattern}</p>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Issues */}
                {h.issues.length > 0 && (
                  <div className="space-y-1">
                    {h.issues.map((issue, i) => (
                      <p key={i} className="text-sm text-destructive flex items-center gap-1">
                        <AlertCircle className="h-3 w-3" />
                        {issue}
                      </p>
                    ))}
                  </div>
                )}

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-muted-foreground">Logs/min</p>
                      <p className="font-medium">{formatNumber(h.latest.logs_per_minute)}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-muted-foreground">Latency</p>
                      <p className="font-medium">{h.latest.avg_latency_ms}ms</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Bell className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-muted-foreground">Alerts/hr</p>
                      <p className="font-medium">{formatNumber(h.latest.alerts_per_hour)}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-muted-foreground">Queue</p>
                      <p className="font-medium">{formatNumber(h.latest.queue_depth)}</p>
                    </div>
                  </div>
                </div>

                {/* 24h Totals */}
                <div className="pt-2 border-t text-xs text-muted-foreground">
                  <span>24h: </span>
                  <span>{formatNumber(h.totals_24h.logs_received)} logs</span>
                  <span className="mx-1">|</span>
                  <span>{formatNumber(h.totals_24h.logs_errored)} errors</span>
                  <span className="mx-1">|</span>
                  <span>{formatNumber(h.totals_24h.alerts_generated)} alerts</span>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
    </TooltipProvider>
  )
}
