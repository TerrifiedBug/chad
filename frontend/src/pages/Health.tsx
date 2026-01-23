import { useEffect, useState } from 'react'
import { healthApi, IndexHealth, HealthStatus } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertCircle, CheckCircle2, AlertTriangle, Activity, Clock, Zap, Bell } from 'lucide-react'

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

const StatusIcon = ({ status }: { status: HealthStatus }) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle2 className="h-5 w-5 text-green-600" />
    case 'warning':
      return <AlertTriangle className="h-5 w-5 text-yellow-600" />
    case 'critical':
      return <AlertCircle className="h-5 w-5 text-red-600" />
  }
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return n.toString()
}

export default function HealthPage() {
  const [health, setHealth] = useState<IndexHealth[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadHealth()
    // Refresh every 30 seconds
    const interval = setInterval(loadHealth, 30000)
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

  // Calculate overall status
  const overallStatus: HealthStatus = health.reduce((worst, h) => {
    if (h.status === 'critical') return 'critical'
    if (h.status === 'warning' && worst !== 'critical') return 'warning'
    return worst
  }, 'healthy' as HealthStatus)

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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">System Health</h1>
          <p className="text-muted-foreground">Monitor index pattern health and performance</p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${statusBgColors[overallStatus]}`}>
          <StatusIcon status={overallStatus} />
          <span className={`font-medium capitalize ${statusColors[overallStatus]}`}>
            {overallStatus === 'healthy' ? 'All Systems Healthy' : `System ${overallStatus}`}
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
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
  )
}
