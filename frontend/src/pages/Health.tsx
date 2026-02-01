import { useEffect, useState } from 'react'
import { healthApi, IndexHealth, HealthStatus, queueApi, QueueStatsResponse, DeadLetterMessage, PullModeHealth } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { AlertCircle, CheckCircle2, AlertTriangle, Activity, Clock, Zap, Bell, ChevronDown, RefreshCw, Server, ChevronRight, Database, Layers, XCircle, Loader2, ChevronUp } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { useToast } from '@/components/ui/toast-provider'
import { LoadingState } from '@/components/ui/loading-state'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { TimestampTooltip } from '@/components/timestamp-tooltip'

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
  overall_status?: 'healthy' | 'warning' | 'degraded' | 'critical'
  unhealthy_ti_sources?: number
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
  const { showToast } = useToast()
  const [health, setHealth] = useState<IndexHealth[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshingIndexes, setIsRefreshingIndexes] = useState(false)
  const [error, setError] = useState('')

  // Service health state
  const [serviceHealth, setServiceHealth] = useState<ServiceHealthResponse | null>(null)
  const [serviceHealthLoading, setServiceHealthLoading] = useState(true)

  // Queue health state
  const [queueStats, setQueueStats] = useState<QueueStatsResponse | null>(null)
  const [isLoadingQueueStats, setIsLoadingQueueStats] = useState(false)

  // Dead letter state
  const [deadLetterMessages, setDeadLetterMessages] = useState<DeadLetterMessage[]>([])
  const [deadLetterCount, setDeadLetterCount] = useState(0)
  const [isClearingDeadLetter, setIsClearingDeadLetter] = useState(false)

  // Pull mode health state
  const [pullModeHealth, setPullModeHealth] = useState<PullModeHealth | null>(null)
  const [isLoadingPullMode, setIsLoadingPullMode] = useState(false)
  const [pullModeOpen, setPullModeOpen] = useState(false)

  // Collapsible sections state
  const [externalServicesOpen, setExternalServicesOpen] = useState(false)
  const [pushModeOpen, setPushModeOpen] = useState(false)
  const [queueDetailsOpen, setQueueDetailsOpen] = useState(false)
  const [deadLetterOpen, setDeadLetterOpen] = useState(false)
  const [indexesOpen, setIndexesOpen] = useState(false)

  // Status popover state
  const [statusPopoverOpen, setStatusPopoverOpen] = useState(false)

  useEffect(() => {
    loadHealth()
    loadServiceHealth()
    loadQueueStats()
    loadPullModeHealth()
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadHealth()
      loadServiceHealth()
      loadQueueStats()
      loadPullModeHealth()
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadHealth = async (isRefresh = false) => {
    if (isRefresh) {
      setIsRefreshingIndexes(true)
    } else {
      setIsLoading(true)
    }
    try {
      const data = await healthApi.listIndices()
      setHealth(data)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load health data')
    } finally {
      setIsLoading(false)
      setIsRefreshingIndexes(false)
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

  const loadQueueStats = async () => {
    setIsLoadingQueueStats(true)
    try {
      const [stats, deadLetter] = await Promise.all([
        queueApi.getStats(),
        queueApi.getDeadLetter(50),
      ])
      setQueueStats(stats)
      setDeadLetterMessages(deadLetter.messages)
      setDeadLetterCount(deadLetter.count)
    } catch (err) {
      // Queue stats may not be available if Redis isn't configured
      console.error('Failed to load queue stats:', err)
    } finally {
      setIsLoadingQueueStats(false)
    }
  }

  const loadPullModeHealth = async () => {
    setIsLoadingPullMode(true)
    try {
      const data = await healthApi.getPullModeHealth()
      setPullModeHealth(data)
      // Auto-expand if there are pull mode patterns
      if (data.patterns.length > 0 && pullModeHealth === null) {
        setPullModeOpen(true)
      }
    } catch (err) {
      // Pull mode health may not be available
      console.error('Failed to load pull mode health:', err)
    } finally {
      setIsLoadingPullMode(false)
    }
  }

  const clearDeadLetterQueue = async () => {
    if (!confirm('Are you sure you want to permanently delete all messages in the dead letter queue? This action cannot be undone.')) {
      return
    }
    setIsClearingDeadLetter(true)
    try {
      await queueApi.clearDeadLetter()
      setDeadLetterMessages([])
      setDeadLetterCount(0)
      if (queueStats) {
        setQueueStats({ ...queueStats, dead_letter_count: 0 })
      }
      showToast('Dead letter queue cleared')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to clear dead letter queue', 'error')
    } finally {
      setIsClearingDeadLetter(false)
    }
  }

  // Calculate overall status (includes pull mode health when patterns exist)
  const overallStatus: HealthStatus = (() => {
    // Start with index pattern health
    let worst: HealthStatus = health.reduce((acc, h) => {
      if (h.status === 'critical') return 'critical'
      if (h.status === 'warning' && acc !== 'critical') return 'warning'
      return acc
    }, 'healthy' as HealthStatus)

    // Include pull mode health if there are pull patterns
    if (pullModeHealth && pullModeHealth.patterns.length > 0) {
      if (pullModeHealth.overall_status === 'critical') worst = 'critical'
      else if (pullModeHealth.overall_status === 'warning' && worst !== 'critical') worst = 'warning'
    }

    return worst
  })()

  // Get problematic index patterns for the popover
  const problematicPatterns = health.filter(h => h.status === 'warning' || h.status === 'critical')

  // Get problematic pull mode patterns for the popover
  const problematicPullPatterns = pullModeHealth?.patterns.filter(p => p.status === 'warning' || p.status === 'critical') || []

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
    return <LoadingState message="Loading health data..." />
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
              {(problematicPatterns.length > 0 || problematicPullPatterns.length > 0 || problematicServices.length > 0) && (
                <ChevronDown className={`h-4 w-4 transition-transform ${statusPopoverOpen ? 'rotate-180' : ''}`} />
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-80" align="end">
            {(problematicPatterns.length === 0 && problematicPullPatterns.length === 0 && problematicServices.length === 0) ? (
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

                {problematicPullPatterns.length > 0 && (
                  <div>
                    <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                      <Clock className="h-4 w-4 text-yellow-600" />
                      Pull Mode Detection
                    </h4>
                    <div className="space-y-1">
                      {problematicPullPatterns.map((pattern, index) => (
                        <div key={`pull-${pattern.index_pattern_id}-${index}`} className="flex items-center justify-between text-sm p-2 rounded bg-muted/50">
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

      {/* Degraded status warning banner */}
      {serviceHealth?.overall_status === 'degraded' && (
        <div className="bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200 text-sm p-3 rounded-md flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          <span>
            Some services are degraded.
            {serviceHealth.unhealthy_ti_sources && serviceHealth.unhealthy_ti_sources > 0 && (
              <> {serviceHealth.unhealthy_ti_sources} TI source(s) unhealthy.</>
            )}
          </span>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
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

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                <Layers className="h-5 w-5 text-purple-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Queue Depth</p>
                <p className="text-2xl font-bold">{queueStats ? formatNumber(queueStats.total_depth) : '-'}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className={`p-2 rounded-lg ${queueStats && queueStats.dead_letter_count > 0 ? 'bg-orange-100 dark:bg-orange-900/30' : 'bg-gray-100 dark:bg-gray-800'}`}>
                <AlertTriangle className={`h-5 w-5 ${queueStats && queueStats.dead_letter_count > 0 ? 'text-orange-600' : 'text-gray-400'}`} />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Dead Letter</p>
                <p className={`text-2xl font-bold ${queueStats && queueStats.dead_letter_count > 0 ? 'text-orange-600' : ''}`}>
                  {queueStats ? formatNumber(queueStats.dead_letter_count) : '-'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* External Services Health - visible to all authenticated users */}
      <Card>
          <CardHeader className="pb-2">
            <div
              className="flex items-center justify-between cursor-pointer"
              onClick={() => setExternalServicesOpen(!externalServicesOpen)}
            >
              <CardTitle className="text-lg flex items-center gap-2">
                <Server className="h-5 w-5" />
                External Services
                {serviceHealth && serviceHealth.services.length > 0 && (
                  <span className="text-sm font-normal text-muted-foreground">
                    ({serviceHealth.services.length})
                  </span>
                )}
              </CardTitle>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation()
                    loadServiceHealth()
                  }}
                  disabled={serviceHealthLoading}
                >
                  <RefreshCw className={`h-4 w-4 ${serviceHealthLoading ? 'animate-spin' : ''}`} />
                </Button>
                {externalServicesOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </div>
            <CardDescription>Status of integrated third-party services including threat intelligence, AI, and ticketing systems.</CardDescription>
          </CardHeader>
          {externalServicesOpen && (
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
          )}
        </Card>

      {/* Push Mode Detection Section */}
      <Card>
        <CardHeader className="pb-2">
          <div
            className="flex items-center justify-between cursor-pointer"
            onClick={() => setPushModeOpen(!pushModeOpen)}
          >
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5" />
              <CardTitle className="text-lg">Push Mode Detection</CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation()
                  loadQueueStats()
                }}
                disabled={isLoadingQueueStats}
              >
                <RefreshCw className={`h-4 w-4 ${isLoadingQueueStats ? 'animate-spin' : ''}`} />
              </Button>
              {pushModeOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </div>
          </div>
          <CardDescription>Queue health and dead letter monitoring for push-mode log ingestion.</CardDescription>
        </CardHeader>
        {pushModeOpen && (
          <CardContent className="space-y-4">
            {/* Queue Statistics */}
            <div className="border rounded-lg p-4">
              <div
                className="flex items-center justify-between cursor-pointer"
                onClick={() => setQueueDetailsOpen(!queueDetailsOpen)}
              >
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4" />
                  <span className="font-medium">Queue Health</span>
                </div>
                {queueDetailsOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
              {queueDetailsOpen && (
                <div className="mt-4">
                  {queueStats ? (
                    <div className="space-y-4">
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="p-3 border rounded-lg">
                          <div className="text-xl font-bold">{queueStats.total_depth.toLocaleString()}</div>
                          <div className="text-sm text-muted-foreground">Total Queue Depth</div>
                        </div>
                        <div className="p-3 border rounded-lg">
                          <div className="text-xl font-bold">{Object.keys(queueStats.queues).length}</div>
                          <div className="text-sm text-muted-foreground">Active Streams</div>
                        </div>
                        <div className="p-3 border rounded-lg">
                          <div className={`text-xl font-bold ${queueStats.dead_letter_count > 0 ? 'text-red-500' : ''}`}>
                            {queueStats.dead_letter_count.toLocaleString()}
                          </div>
                          <div className="text-sm text-muted-foreground">Dead Letter Count</div>
                        </div>
                      </div>
                      {Object.keys(queueStats.queues).length > 0 && (
                        <div className="pt-4 border-t">
                          <h4 className="font-medium mb-2 text-sm">Queue Depths by Index</h4>
                          <div className="space-y-2">
                            {Object.entries(queueStats.queues).map(([index, depth]) => (
                              <div key={index} className="flex justify-between items-center text-sm">
                                <span className="font-mono">{index}</span>
                                <span className={depth > 10000 ? 'text-yellow-500 font-medium' : ''}>{depth.toLocaleString()}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-4 text-muted-foreground text-sm">
                      {isLoadingQueueStats ? 'Loading...' : 'No queue statistics available. Redis may not be configured.'}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Dead Letter Queue */}
            <div className="border rounded-lg p-4">
              <div
                className="flex items-center justify-between cursor-pointer"
                onClick={() => setDeadLetterOpen(!deadLetterOpen)}
              >
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4" />
                  <span className="font-medium">Dead Letter Queue</span>
                  {deadLetterCount > 0 && (
                    <span className="text-xs bg-red-100 dark:bg-red-900/30 text-red-600 px-2 py-0.5 rounded-full">
                      {deadLetterCount}
                    </span>
                  )}
                </div>
                {deadLetterOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
              {deadLetterOpen && (
                <div className="mt-4">
                  {deadLetterMessages.length > 0 ? (
                    <div className="space-y-4">
                      {hasPermission('manage_health') && (
                        <div className="flex justify-end">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={clearDeadLetterQueue}
                            disabled={isClearingDeadLetter}
                          >
                            {isClearingDeadLetter ? (
                              <>
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                Clearing...
                              </>
                            ) : (
                              'Clear All'
                            )}
                          </Button>
                        </div>
                      )}
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {deadLetterMessages.map((msg, i) => (
                          <div key={i} className="p-3 border rounded-lg text-sm">
                            <div className="flex justify-between mb-1">
                              <span className="font-mono text-muted-foreground">{msg.original_stream}</span>
                              <span className="text-xs text-muted-foreground">ID: {msg.original_id}</span>
                            </div>
                            <p className="text-destructive">{msg.reason}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-4 text-muted-foreground text-sm">
                      No messages in dead letter queue
                    </div>
                  )}
                </div>
              )}
            </div>
          </CardContent>
        )}
      </Card>

      {/* Pull Mode Health Section */}
      {pullModeHealth && pullModeHealth.patterns.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div
              className="flex items-center justify-between cursor-pointer"
              onClick={() => setPullModeOpen(!pullModeOpen)}
            >
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                <CardTitle className="text-lg">Pull Mode Detection</CardTitle>
                <span className="text-sm font-normal text-muted-foreground">
                  ({pullModeHealth.patterns.length})
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation()
                    loadPullModeHealth()
                  }}
                  disabled={isLoadingPullMode}
                >
                  <RefreshCw className={`h-4 w-4 ${isLoadingPullMode ? 'animate-spin' : ''}`} />
                </Button>
                {pullModeOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </div>
            <CardDescription>Health metrics for pull-mode index patterns that query OpenSearch on a schedule.</CardDescription>
          </CardHeader>
          {pullModeOpen && (
            <CardContent>
              {/* Summary Stats */}
              <div className="grid gap-4 md:grid-cols-4 mb-6">
                <div className="p-4 border rounded-lg">
                  <div className="text-2xl font-bold">{pullModeHealth.summary.total_polls.toLocaleString()}</div>
                  <div className="text-sm text-muted-foreground">Total Polls</div>
                </div>
                <div className="p-4 border rounded-lg">
                  <div className="text-2xl font-bold">{pullModeHealth.summary.total_matches.toLocaleString()}</div>
                  <div className="text-sm text-muted-foreground">Total Matches</div>
                </div>
                <div className="p-4 border rounded-lg">
                  <div className="text-2xl font-bold">{formatNumber(pullModeHealth.summary.total_events_scanned)}</div>
                  <div className="text-sm text-muted-foreground">Events Scanned</div>
                </div>
                <div className="p-4 border rounded-lg">
                  <div className="flex items-center gap-2">
                    <StatusIcon status={pullModeHealth.overall_status} />
                    <div>
                      <div className="text-lg font-bold capitalize">{pullModeHealth.overall_status}</div>
                      <div className="text-sm text-muted-foreground">
                        {pullModeHealth.summary.healthy_patterns} healthy, {pullModeHealth.summary.warning_patterns + pullModeHealth.summary.critical_patterns} issues
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Pattern Table - similar to Queue Depths by Index */}
              <div className="border rounded-lg">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/50">
                      <th className="text-left p-3 font-medium">Index</th>
                      <th className="text-left p-3 font-medium">Last Poll</th>
                      <th className="text-right p-3 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pullModeHealth.patterns.map((pattern) => (
                      <tr key={pattern.index_pattern_id} className="border-b last:border-0">
                        <td className="p-3">
                          <div className="font-medium">{pattern.index_pattern_name}</div>
                          <div className="text-xs text-muted-foreground font-mono">{pattern.pattern}</div>
                        </td>
                        <td className="p-3 text-muted-foreground">
                          {pattern.last_poll_at ? (
                            <TimestampTooltip timestamp={pattern.last_poll_at}>
                              <span>{formatDateTime(pattern.last_poll_at)}</span>
                            </TimestampTooltip>
                          ) : 'Never'}
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <StatusIcon status={pattern.status} />
                            <span className={`capitalize ${statusColors[pattern.status]}`}>
                              {pattern.status}
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Index Pattern Health Cards */}
      <Card>
        <CardHeader className="pb-2">
          <div
            className="flex items-center justify-between cursor-pointer"
            onClick={() => setIndexesOpen(!indexesOpen)}
          >
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Database className="h-5 w-5" />
                Indexes
                {health.length > 0 && (
                  <span className="text-sm font-normal text-muted-foreground">
                    ({health.length})
                  </span>
                )}
              </CardTitle>
              <CardDescription>
                Health metrics and detection latency for monitored index patterns.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation()
                  loadHealth(true)
                }}
                disabled={isRefreshingIndexes}
              >
                <RefreshCw className={`h-4 w-4 ${isRefreshingIndexes ? 'animate-spin' : ''}`} />
              </Button>
              {indexesOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </div>
          </div>
        </CardHeader>
        {indexesOpen && (
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {health.length === 0 ? (
                <div className="col-span-full text-center py-12 text-muted-foreground">
                  No index patterns configured. Add index patterns to see health data.
                </div>
              ) : (
                health.map((h) => {
                  // For pull mode, get the pull mode metrics
                  const pullData = h.mode === 'pull'
                    ? pullModeHealth?.patterns.find(p => p.index_pattern_id === h.index_pattern_id)
                    : null

                  return (
                    <Card key={h.index_pattern_id} className={statusBgColors[h.status]}>
                      <CardHeader className="pb-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <CardTitle className="text-lg">{h.index_pattern_name}</CardTitle>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${
                              h.mode === 'push'
                                ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                : 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300'
                            }`}>
                              {h.mode}
                            </span>
                          </div>
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

                        {/* Mode-specific Metrics Grid */}
                        {h.mode === 'push' ? (
                          // Push Mode Metrics
                          <>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
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
                                  <p className="text-muted-foreground">Detection Latency</p>
                                  <p className="font-medium">{((h.latest.avg_detection_latency_ms || 0) / 1000).toFixed(1)}s</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">OpenSearch Query</p>
                                  <p className="font-medium">{((h.latest.avg_opensearch_query_latency_ms || 0) / 1000).toFixed(1)}s</p>
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
                            {/* 24h Totals - Push Mode */}
                            <div className="pt-2 border-t text-xs text-muted-foreground">
                              <span>24h: </span>
                              <span>{formatNumber(h.totals_24h.logs_received)} logs</span>
                              <span className="mx-1">|</span>
                              <span>{formatNumber(h.totals_24h.logs_errored)} errors</span>
                              <span className="mx-1">|</span>
                              <span>{formatNumber(h.totals_24h.alerts_generated)} alerts</span>
                            </div>
                          </>
                        ) : (
                          // Pull Mode Metrics
                          <>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
                              <div className="flex items-center gap-2">
                                <Activity className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">Matches/poll</p>
                                  <p className="font-medium">
                                    {pullData?.metrics.total_polls
                                      ? formatNumber(Math.round(pullData.metrics.total_matches / pullData.metrics.total_polls))
                                      : '-'}
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">Detection Latency</p>
                                  <p className="font-medium">{((h.latest.avg_detection_latency_ms || 0) / 1000).toFixed(1)}s</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">Avg Duration</p>
                                  <p className="font-medium">
                                    {pullData?.metrics.avg_poll_duration_ms
                                      ? `${(pullData.metrics.avg_poll_duration_ms / 1000).toFixed(1)}s`
                                      : '-'}
                                  </p>
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
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">Last Poll</p>
                                  <p className="font-medium">
                                    {pullData?.last_poll_at ? (
                                      <TimestampTooltip timestamp={pullData.last_poll_at}>
                                        <span>{formatDateTime(pullData.last_poll_at)}</span>
                                      </TimestampTooltip>
                                    ) : 'Never'}
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="text-muted-foreground">Success Rate</p>
                                  <p className="font-medium">{pullData?.metrics.success_rate ?? 0}%</p>
                                </div>
                              </div>
                            </div>
                            {/* 24h Totals - Pull Mode */}
                            <div className="pt-2 border-t text-xs text-muted-foreground">
                              <span>Total: </span>
                              <span>{formatNumber(pullData?.metrics.total_polls ?? 0)} polls</span>
                              <span className="mx-1">|</span>
                              <span>{formatNumber(pullData?.metrics.failed_polls ?? 0)} failures</span>
                              <span className="mx-1">|</span>
                              <span>{formatNumber(h.totals_24h.alerts_generated)} alerts</span>
                            </div>
                          </>
                        )}
                      </CardContent>
                    </Card>
                  )
                })
              )}
            </div>
          </CardContent>
        )}
      </Card>
    </div>
    </TooltipProvider>
  )
}
