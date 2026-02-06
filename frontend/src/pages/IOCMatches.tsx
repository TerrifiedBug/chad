import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  ShieldAlert,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Eye,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { Checkbox } from '@/components/ui/checkbox'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/dashboard/StatCard'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { RelativeTime } from '@/components/RelativeTime'
import { alertsApi, iocStatsApi, type Alert, type AlertStatus, type IOCMatchStats } from '@/lib/api'
import { useOpenSearchStatus } from '@/contexts/OpenSearchStatus'
import { cn } from '@/lib/utils'

const THREAT_LEVEL_COLORS: Record<string, string> = {
  high: 'text-red-600 dark:text-red-400',
  medium: 'text-orange-600 dark:text-orange-400',
  low: 'text-yellow-600 dark:text-yellow-400',
}

export default function IOCMatchesPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { isAvailable: osAvailable } = useOpenSearchStatus()

  // State
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [stats, setStats] = useState<IOCMatchStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())

  // Filters from URL
  const statusFilter = searchParams.get('status') as AlertStatus | null
  const severityFilter = searchParams.get('severity')
  const page = parseInt(searchParams.get('page') || '1', 10)
  const pageSize = parseInt(searchParams.get('pageSize') || '25', 10)

  const offset = (page - 1) * pageSize
  const totalPages = Math.ceil(total / pageSize)

  const loadData = useCallback(async () => {
    try {
      const result = await alertsApi.list({
        rule_id: 'ioc-detection',
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        limit: pageSize,
        offset,
        cluster: false,
      })
      setAlerts(result.alerts || [])
      setTotal(result.total || 0)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load IOC matches')
    }
  }, [statusFilter, severityFilter, pageSize, offset])

  const loadStats = useCallback(async () => {
    try {
      const result = await iocStatsApi.getStats()
      setStats(result)
    } catch {
      // Stats are non-critical
    }
  }, [])

  useEffect(() => {
    setIsLoading(true)
    Promise.all([loadData(), loadStats()]).finally(() => setIsLoading(false))
  }, [loadData, loadStats])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    await Promise.all([loadData(), loadStats()])
    setIsRefreshing(false)
  }

  const setPage = (p: number) => {
    const params = new URLSearchParams(searchParams)
    params.set('page', String(p))
    setSearchParams(params)
  }

  const setFilter = (key: string, value: string | null) => {
    const params = new URLSearchParams(searchParams)
    if (value) {
      params.set(key, value)
    } else {
      params.delete(key)
    }
    params.delete('page')
    setSearchParams(params)
  }

  const toggleSelect = (alertId: string) => {
    setSelectedAlerts(prev => {
      const next = new Set(prev)
      if (next.has(alertId)) next.delete(alertId)
      else next.add(alertId)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedAlerts.size === alerts.length) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(alerts.map(a => a.alert_id)))
    }
  }

  const handleBulkAction = async (status: AlertStatus) => {
    if (selectedAlerts.size === 0) return
    try {
      await alertsApi.bulkUpdateStatus({
        alert_ids: Array.from(selectedAlerts),
        status,
      })
      setSelectedAlerts(new Set())
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk action failed')
    }
  }

  const getIocInfo = (alert: Alert) => {
    const match = alert.ioc_matches?.[0]
    return {
      value: match?.value || alert.rule_title.replace('IOC Match: ', ''),
      type: match?.ioc_type || 'unknown',
      field: match?.field_name || '',
      mispEvent: match?.misp_event_info || '',
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="IOC Matches"
        description="Indicator of Compromise detections from threat intelligence"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isRefreshing}>
            <RefreshCw className={cn('h-4 w-4 mr-2', isRefreshing && 'animate-spin')} />
            Refresh
          </Button>
        }
      />

      {/* Stats Widgets */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-3">
          <StatCard
            title="IOC Matches Today"
            value={stats.today}
            subtext={`${stats.total} total`}
            icon={ShieldAlert}
            variant={stats.today > 10 ? 'danger' : stats.today > 0 ? 'warning' : 'default'}
          />
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Top Hitting IOCs</CardTitle>
            </CardHeader>
            <CardContent>
              {stats.top_iocs.length === 0 ? (
                <p className="text-sm text-muted-foreground">No IOC matches yet</p>
              ) : (
                <div className="space-y-1.5">
                  {stats.top_iocs.slice(0, 5).map((ioc, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <span className="font-mono text-xs truncate max-w-[200px]" title={ioc.value}>
                        {ioc.value}
                      </span>
                      <Badge variant="secondary" className="text-xs">{ioc.count}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Breakdown</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-xs text-muted-foreground mb-1">By Threat Level</p>
                <div className="flex gap-2 flex-wrap">
                  {Object.entries(stats.by_threat_level).map(([level, count]) => (
                    <Badge key={level} variant="outline" className={cn('text-xs', THREAT_LEVEL_COLORS[level])}>
                      {level}: {count}
                    </Badge>
                  ))}
                  {Object.keys(stats.by_threat_level).length === 0 && (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">By IOC Type</p>
                <div className="flex gap-2 flex-wrap">
                  {Object.entries(stats.by_type).map(([type, count]) => (
                    <Badge key={type} variant="outline" className="text-xs">
                      {type}: {count}
                    </Badge>
                  ))}
                  {Object.keys(stats.by_type).length === 0 && (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select
          value={statusFilter || 'all'}
          onValueChange={(v) => setFilter('status', v === 'all' ? null : v)}
        >
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={severityFilter || 'all'}
          onValueChange={(v) => setFilter('severity', v === 'all' ? null : v)}
        >
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Bulk Actions */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-lg">
          <span className="text-sm font-medium">{selectedAlerts.size} selected</span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleBulkAction('acknowledged')}
            disabled={!osAvailable}
            title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
          >
            <Eye className="h-3.5 w-3.5 mr-1" />
            Acknowledge
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleBulkAction('resolved')}
            disabled={!osAvailable}
            title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
          >
            <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
            Resolve
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleBulkAction('false_positive')}
            disabled={!osAvailable}
            title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
          >
            <XCircle className="h-3.5 w-3.5 mr-1" />
            False Positive
          </Button>
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-12 bg-muted/50 rounded animate-pulse" />
          ))}
        </div>
      ) : alerts.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ShieldAlert className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <p className="text-muted-foreground">No IOC matches found</p>
          </CardContent>
        </Card>
      ) : (
        <TooltipProvider>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    checked={selectedAlerts.size === alerts.length && alerts.length > 0}
                    onCheckedChange={toggleSelectAll}
                  />
                </TableHead>
                <TableHead className="w-24">Severity</TableHead>
                <TableHead>IOC Value</TableHead>
                <TableHead className="w-24">Type</TableHead>
                <TableHead>Matched Field</TableHead>
                <TableHead>MISP Event</TableHead>
                <TableHead className="w-28">Status</TableHead>
                <TableHead className="w-24">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.map((alert) => {
                const ioc = getIocInfo(alert)
                return (
                  <TableRow
                    key={alert.alert_id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedAlerts.has(alert.alert_id)}
                        onCheckedChange={() => toggleSelect(alert.alert_id)}
                      />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={alert.severity} />
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="font-mono text-xs truncate max-w-[250px] block">
                            {ioc.value}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{ioc.value}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{ioc.type}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">
                      {ioc.field}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">
                      {ioc.mispEvent || '\u2014'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs capitalize">{alert.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <RelativeTime date={alert.created_at} />
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </TooltipProvider>
      )}

      {/* Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {Math.min(offset + 1, total)} - {Math.min(offset + pageSize, total)} of {total}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage(page - 1)} disabled={page <= 1}>
              <ChevronLeft className="h-4 w-4" />Previous
            </Button>
            <span className="text-sm text-muted-foreground">Page {page} of {totalPages}</span>
            <Button variant="outline" size="sm" onClick={() => setPage(page + 1)} disabled={page >= totalPages}>
              Next<ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
