import { Fragment, useCallback, useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  ShieldAlert,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  Eye,
  Search,
  X,
  RotateCcw,
  LayoutList,
  List,
  UserPlus,
  Trash2,
  Layers,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, Badge as StatusBadge } from '@/components/ui/badge'
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
import { KpiStrip, KpiTile } from '@/components/ui/kpi-tile'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { SeverityPills } from '@/components/filters/SeverityPills'
import { RelativeTime } from '@/components/RelativeTime'
import { Skeleton, SkeletonTable } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/ui/empty-state'
import { alertsApi, iocStatsApi, type Alert, type AlertStatus, type IOCMatchStats, type AlertCluster, type AlertListResponse, type ClusteredAlertListResponse } from '@/lib/api'
import { useOpenSearchStatus } from '@/contexts/OpenSearchStatus'
import { useAuth } from '@/hooks/use-auth'
import { ALERT_STATUS_LABELS, capitalize, SEVERITY_CONFIG, alertStatusBadgeVariant } from '@/lib/constants'
import { cn } from '@/lib/utils'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

// The "Active" status view hides triaged matches (resolved + false positives).
const ACTIVE_EXCLUDED_STATUSES: AlertStatus[] = ['resolved', 'false_positive']

// Type guard to check if response is clustered
function isClusteredResponse(response: AlertListResponse | ClusteredAlertListResponse): response is ClusteredAlertListResponse {
  return 'clusters' in response
}

export default function IOCMatchesPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { isAvailable: osAvailable } = useOpenSearchStatus()
  const { hasPermission } = useAuth()

  // State
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [clusters, setClusters] = useState<AlertCluster[]>([])
  const [isClustered, setIsClustered] = useState(false)
  const [total, setTotal] = useState(0)
  const [totalClusters, setTotalClusters] = useState(0)
  const [stats, setStats] = useState<IOCMatchStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [selectAll, setSelectAll] = useState(false)
  const [isBulkUpdating, setIsBulkUpdating] = useState(false)
  const [search, setSearch] = useState(() => searchParams.get('search') || '')
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set())

  // Filters from URL. Absent 'status' param => default "Active" view, which
  // hides resolved + false-positive matches. Explicit 'all' shows every status.
  const statusFilter = searchParams.get('status') as AlertStatus | 'all' | null
  const isActiveView = statusFilter === null
  const [severityFilter, setSeverityFilter] = useState<string[]>(() => {
    const severities = searchParams.get('severity')
    return severities ? severities.split(',').filter(s => SEVERITIES.includes(s as typeof SEVERITIES[number])) : []
  })
  const page = parseInt(searchParams.get('page') || '1', 10)
  const [pageSize, setPageSize] = useState(25)

  // Owner filter - initialize from URL query param, fallback to localStorage
  const [ownerFilter, setOwnerFilter] = useState<string | null>(() => {
    const urlParam = searchParams.get('owner')
    if (urlParam) return urlParam
    const stored = localStorage.getItem('ioc-assigned-to-me')
    return stored === 'true' ? 'me' : null
  })

  // Compact mode with localStorage persistence
  const [isCompact, setIsCompact] = useState(() => {
    const saved = localStorage.getItem('ioc-compact-mode')
    return saved ? JSON.parse(saved) : false
  })

  useEffect(() => {
    localStorage.setItem('ioc-compact-mode', JSON.stringify(isCompact))
  }, [isCompact])

  const offset = (page - 1) * pageSize
  const totalPages = Math.ceil(total / pageSize)

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    )
  }

  // Toggle cluster expansion
  const toggleCluster = (clusterId: string) => {
    setExpandedClusters(prev => {
      const newSet = new Set(prev)
      if (newSet.has(clusterId)) {
        newSet.delete(clusterId)
      } else {
        newSet.add(clusterId)
      }
      return newSet
    })
  }

  const loadData = useCallback(async () => {
    try {
      const result = await alertsApi.list({
        rule_id: 'ioc-detection',
        status: statusFilter && statusFilter !== 'all' ? statusFilter : undefined,
        exclude_status: isActiveView ? ACTIVE_EXCLUDED_STATUSES : undefined,
        severity: severityFilter.length === 1 ? severityFilter[0] : undefined,
        owner: ownerFilter,
        limit: pageSize,
        offset,
      }) as AlertListResponse | ClusteredAlertListResponse

      // Handle clustered or non-clustered response
      if (isClusteredResponse(result)) {
        setIsClustered(true)
        setClusters(result.clusters)
        setAlerts([])
        setTotal(result.total)
        setTotalClusters(result.total_clusters)
      } else {
        setIsClustered(false)
        setClusters([])
        setAlerts(result.alerts || [])
        setTotal(result.total || 0)
        setTotalClusters(0)
      }
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load IOC matches')
    }
  }, [statusFilter, isActiveView, severityFilter, ownerFilter, pageSize, offset])

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

  // Sync filters with URL
  useEffect(() => {
    const newParams = new URLSearchParams()
    if (search) newParams.set('search', search)
    if (statusFilter) newParams.set('status', statusFilter)
    if (severityFilter.length > 0) newParams.set('severity', severityFilter.join(','))
    if (ownerFilter) newParams.set('owner', ownerFilter)
    setSearchParams(newParams, { replace: true })

    localStorage.setItem('ioc-assigned-to-me', ownerFilter === 'me' ? 'true' : 'false')
  }, [search, statusFilter, severityFilter, ownerFilter, setSearchParams])

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

  const getIocInfo = (alert: Alert) => {
    const match = alert.ioc_matches?.[0]
    return {
      value: match?.value || alert.rule_title.replace('IOC Match: ', ''),
      type: match?.ioc_type || 'unknown',
      mispEvent: match?.misp_event_info || '',
    }
  }

  // Client-side filters for non-clustered mode
  const filteredAlerts = alerts.filter((alert) => {
    if (search && !(alert.rule_title || '').toLowerCase().includes(search.toLowerCase())) {
      return false
    }
    if (severityFilter.length > 1 && !severityFilter.includes(alert.severity)) {
      return false
    }
    return true
  })

  // Client-side filters for clustered mode
  const filteredClusters = clusters.filter((cluster) => {
    if (search && !(cluster.representative.rule_title || '').toLowerCase().includes(search.toLowerCase())) {
      return false
    }
    if (severityFilter.length > 1 && !severityFilter.includes(cluster.representative.severity)) {
      return false
    }
    return true
  })

  // Get all selectable alert IDs (from clusters or alerts)
  const getAllSelectableAlertIds = (): string[] => {
    if (isClustered) {
      return filteredClusters.flatMap(c => c.alert_ids)
    }
    return filteredAlerts.map(a => a.alert_id)
  }

  const handleSelectAll = (checked: boolean) => {
    setSelectAll(checked)
    if (checked) {
      setSelectedAlerts(new Set(getAllSelectableAlertIds()))
    } else {
      setSelectedAlerts(new Set())
    }
  }

  const handleSelectAlert = (alertId: string, checked: boolean) => {
    const newSelected = new Set(selectedAlerts)
    if (checked) {
      newSelected.add(alertId)
    } else {
      newSelected.delete(alertId)
    }
    setSelectedAlerts(newSelected)
    const allIds = getAllSelectableAlertIds()
    setSelectAll(newSelected.size === allIds.length && allIds.length > 0)
  }

  // Handle selecting/deselecting all alerts in a cluster
  const handleSelectCluster = (cluster: AlertCluster, checked: boolean) => {
    const newSelected = new Set(selectedAlerts)
    if (checked) {
      cluster.alert_ids.forEach(id => newSelected.add(id))
    } else {
      cluster.alert_ids.forEach(id => newSelected.delete(id))
    }
    setSelectedAlerts(newSelected)
    const allIds = getAllSelectableAlertIds()
    setSelectAll(newSelected.size === allIds.length && allIds.length > 0)
  }

  // Check if all alerts in a cluster are selected
  const isClusterSelected = (cluster: AlertCluster): boolean => {
    return cluster.alert_ids.every(id => selectedAlerts.has(id))
  }

  // Check if some alerts in a cluster are selected
  const isClusterPartiallySelected = (cluster: AlertCluster): boolean => {
    const selectedCount = cluster.alert_ids.filter(id => selectedAlerts.has(id)).length
    return selectedCount > 0 && selectedCount < cluster.alert_ids.length
  }

  const handleBulkAction = async (status: AlertStatus) => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setError(null)
    try {
      await alertsApi.bulkUpdateStatus({
        alert_ids: Array.from(selectedAlerts),
        status,
      })
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk action failed')
    } finally {
      setIsBulkUpdating(false)
    }
  }

  const handleBulkTakeOwnership = async () => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setError(null)
    try {
      await Promise.all(
        Array.from(selectedAlerts).map(alertId => alertsApi.assign(alertId))
      )
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to take ownership')
    } finally {
      setIsBulkUpdating(false)
    }
  }

  const handleBulkDelete = async () => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setError(null)
    try {
      await alertsApi.bulkDelete({
        alert_ids: Array.from(selectedAlerts),
      })
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete IOC matches')
    } finally {
      setIsBulkUpdating(false)
    }
  }

  // Compute severity counts from stats for pills
  const severityCounts: Record<string, number> | undefined = stats ? {
    critical: 0,
    high: stats.by_threat_level['high'] || 0,
    medium: stats.by_threat_level['medium'] || 0,
    low: stats.by_threat_level['low'] || 0,
  } : undefined

  const canGoPrevious = page > 1
  const canGoNext = page < totalPages
  const hasActiveFilters = !!(search || statusFilter || severityFilter.length > 0 || ownerFilter)
  const isEmpty = isClustered ? filteredClusters.length === 0 : filteredAlerts.length === 0

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <div className="flex items-center gap-3">
            <span>IOC Matches</span>
            {isClustered && totalClusters > 0 && (
              <div className="flex items-center gap-1.5 text-sm font-normal text-muted-foreground bg-muted/50 px-2 py-0.5 rounded">
                <Layers className="h-3.5 w-3.5" />
                <span>{totalClusters} clusters from {total} IOC matches</span>
              </div>
            )}
          </div>
        }
        description="Indicator of Compromise detections from threat intelligence"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isRefreshing}>
            <RefreshCw className={cn('h-4 w-4 mr-2', isRefreshing && 'animate-spin')} />
            Refresh
          </Button>
        }
      />

      {/* VF console KPI strip + Top IOCs panel — matches the Dashboard's metric
          presentation. Tone carries the urgency signal the old StatCard grid
          expressed via pulse/urgency-ring (today>10 = error, >0 = degraded;
          any high-threat = error). */}
      {stats && (
        <div className="grid gap-4 lg:grid-cols-3">
          <KpiStrip className="lg:col-span-2">
            <KpiTile
              label="Total IOC Alerts"
              value={stats.total}
              sublabel={Object.values(stats.by_type).reduce((a, b) => a + b, 0) > 0
                ? Object.entries(stats.by_type).map(([t, c]) => `${c} ${t}`).join(', ')
                : 'No types recorded'}
              tone="accent"
            />
            <KpiTile
              label="IOC Matches Today"
              value={stats.today}
              sublabel={`${stats.total} total`}
              tone={stats.today > 10 ? 'error' : stats.today > 0 ? 'degraded' : 'default'}
            />
            <KpiTile
              label="High Threat"
              value={stats.by_threat_level['high'] || 0}
              sublabel="Elevated threat level"
              tone={(stats.by_threat_level['high'] || 0) > 0 ? 'error' : 'default'}
              onClick={() => setSeverityFilter(['high'])}
            />
          </KpiStrip>

          {/* Top Hitting IOCs — unique signal preserved, restyled to the VF
              console surface (hairline border, mono values, status Badge). */}
          <div className="flex flex-col gap-2 rounded-[3px] border border-line bg-bg-2 px-5 py-4">
            <span className="vf-thead text-fg-2">Top Hitting IOCs</span>
            {stats.top_iocs.length === 0 ? (
              <p className="vf-mono-xs text-fg-3">No matches yet</p>
            ) : (
              <div className="space-y-1.5">
                {stats.top_iocs.slice(0, 3).map((ioc, i) => (
                  <div key={i} className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[12px] text-fg-1 truncate max-w-[160px]" title={ioc.value}>
                      {ioc.value}
                    </span>
                    <Badge variant="secondary">{ioc.count}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {/* Filters - Primary Row */}
      <div className="space-y-3">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search IOC matches..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Clear search"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
          <Select
            value={statusFilter || 'active'}
            onValueChange={(v) => setFilter('status', v === 'active' ? null : v)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent className="z-50 bg-popover">
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="acknowledged">Acknowledged</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="ioc-my-alerts"
              checked={ownerFilter === 'me'}
              onCheckedChange={(checked) => setOwnerFilter(checked ? 'me' : null)}
            />
            <Label htmlFor="ioc-my-alerts" className="text-sm cursor-pointer">Assigned to me</Label>
          </div>
        </div>

        {/* Filters - Secondary Row: Severity Pills */}
        <div className="flex flex-wrap items-center gap-3">
          <SeverityPills
            selected={severityFilter}
            onChange={toggleSeverityFilter}
            showCounts={severityCounts}
            size="sm"
          />

          {/* Clear All Filters */}
          {hasActiveFilters && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearch('')
                setFilter('status', null)
                setSeverityFilter([])
                setOwnerFilter(null)
              }}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3 mr-1" />
              Clear all filters
            </Button>
          )}

          {/* Refresh and Compact toggle */}
          <div className="ml-auto flex items-center gap-1">
            <Button variant="ghost" size="icon" onClick={handleRefresh} title="Refresh" className="text-muted-foreground">
              <RotateCcw className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsCompact(!isCompact)}
              className="text-muted-foreground"
            >
              {isCompact ? (
                <>
                  <LayoutList className="h-4 w-4 mr-1" />
                  Comfortable
                </>
              ) : (
                <>
                  <List className="h-4 w-4 mr-1" />
                  Compact
                </>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-4">
          <div className="flex gap-2">
            <Skeleton className="h-10 w-64" />
            <Skeleton className="h-10 w-32" />
          </div>
          <SkeletonTable rows={10} columns={7} />
        </div>
      ) : isEmpty ? (
        <EmptyState
          icon={<ShieldAlert className="h-12 w-12" />}
          title={hasActiveFilters ? 'No IOC matches match your filters' : 'No IOC matches found'}
          description={hasActiveFilters
            ? 'Try adjusting your filters to see more results.'
            : 'IOC matches will appear when threat intelligence indicators match incoming logs.'}
        />
      ) : (
        <TooltipProvider>
          <div className="border rounded-lg">
            <Table className={cn(isCompact && 'table-compact')}>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectAll}
                      onCheckedChange={handleSelectAll}
                      aria-label="Select all IOC matches"
                    />
                  </TableHead>
                  {isClustered && <TableHead className="w-[60px]"></TableHead>}
                  <TableHead>Severity</TableHead>
                  <TableHead>IOC Value</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>MISP Event</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isClustered ? (
                  // Clustered view
                  filteredClusters.map((cluster) => {
                    const alert = cluster.representative
                    const clusterId = cluster.alert_ids[0]
                    const isExpanded = expandedClusters.has(clusterId)
                    const hasMultiple = cluster.count > 1
                    const ioc = getIocInfo(alert)

                    return (
                      <Fragment key={clusterId}>
                        {/* Cluster header row */}
                        <TableRow
                          className={cn(
                            "cursor-pointer hover:bg-muted/50",
                            hasMultiple ? "border-l-2 border-l-primary" : SEVERITY_CONFIG[alert.severity]?.rowClass
                          )}
                          onClick={(e) => {
                            if ((e.target as HTMLElement).closest('input[type="checkbox"]') ||
                                (e.target as HTMLElement).closest('button')) {
                              return
                            }
                            if (hasMultiple) {
                              toggleCluster(clusterId)
                            } else {
                              navigate(`/alerts/${alert.alert_id}`)
                            }
                          }}
                        >
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            <Checkbox
                              checked={isClusterSelected(cluster)}
                              ref={(el) => {
                                if (el) {
                                  (el as unknown as HTMLInputElement).indeterminate = isClusterPartiallySelected(cluster)
                                }
                              }}
                              onCheckedChange={(checked) => handleSelectCluster(cluster, checked as boolean)}
                              aria-label={`Select cluster of ${cluster.count} IOC matches`}
                            />
                          </TableCell>
                          <TableCell onClick={(e) => e.stopPropagation()} className="w-[60px]">
                            {hasMultiple ? (
                              <button
                                className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
                                onClick={() => toggleCluster(clusterId)}
                              >
                                <Badge variant="secondary" className="font-mono">
                                  {cluster.count}
                                </Badge>
                                {isExpanded ? (
                                  <ChevronUp className="h-4 w-4 transition-transform" />
                                ) : (
                                  <ChevronDown className="h-4 w-4 transition-transform" />
                                )}
                              </button>
                            ) : (
                              <div className="w-[60px]" />
                            )}
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
                          <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">
                            {ioc.mispEvent || '\u2014'}
                          </TableCell>
                          <TableCell>
                            <StatusBadge variant={alertStatusBadgeVariant(alert.status)}>
                              {ALERT_STATUS_LABELS[alert.status] || capitalize(alert.status)}
                            </StatusBadge>
                          </TableCell>
                          <TableCell>
                            {alert.owner_username ? (
                              <span className="text-sm">{alert.owner_username}</span>
                            ) : (
                              <span className="text-sm text-muted-foreground">Unassigned</span>
                            )}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {hasMultiple ? (
                              <span className="text-xs">
                                {cluster.time_range[0] && cluster.time_range[1] ? (
                                  cluster.time_range[0] !== cluster.time_range[1] &&
                                  Math.abs(new Date(cluster.time_range[0]).getTime() - new Date(cluster.time_range[1]).getTime()) > 60000 ? (
                                    <>
                                      <RelativeTime date={cluster.time_range[0]} /> - <RelativeTime date={cluster.time_range[1]} />
                                    </>
                                  ) : (
                                    <RelativeTime date={cluster.time_range[1]} />
                                  )
                                ) : (
                                  <RelativeTime date={alert.created_at} />
                                )}
                              </span>
                            ) : (
                              <RelativeTime date={alert.created_at} />
                            )}
                          </TableCell>
                        </TableRow>

                        {/* Expanded cluster rows */}
                        {isExpanded && hasMultiple && cluster.alerts.map((clusterAlert, idx) => {
                          const clusterIoc = getIocInfo(clusterAlert)
                          return (
                            <TableRow
                              key={`${clusterId}-${clusterAlert.alert_id}`}
                              className="bg-muted/30 cursor-pointer hover:bg-muted/50"
                              onClick={() => navigate(`/alerts/${clusterAlert.alert_id}`)}
                            >
                              <TableCell onClick={(e) => e.stopPropagation()}>
                                <Checkbox
                                  checked={selectedAlerts.has(clusterAlert.alert_id)}
                                  onCheckedChange={(checked) => handleSelectAlert(clusterAlert.alert_id, checked as boolean)}
                                  aria-label={`Select IOC match ${clusterAlert.alert_id}`}
                                />
                              </TableCell>
                              <TableCell></TableCell>
                              <TableCell>
                                <SeverityBadge severity={clusterAlert.severity} />
                              </TableCell>
                              <TableCell className="pl-8">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-muted-foreground">#{idx + 1}</span>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <span className="font-mono text-xs truncate max-w-[220px] block">
                                        {clusterIoc.value}
                                      </span>
                                    </TooltipTrigger>
                                    <TooltipContent>{clusterIoc.value}</TooltipContent>
                                  </Tooltip>
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className="text-xs">{clusterIoc.type}</Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">
                                {clusterIoc.mispEvent || '\u2014'}
                              </TableCell>
                              <TableCell>
                                <StatusBadge variant={alertStatusBadgeVariant(clusterAlert.status)}>
                                  {ALERT_STATUS_LABELS[clusterAlert.status] || capitalize(clusterAlert.status)}
                                </StatusBadge>
                              </TableCell>
                              <TableCell>
                                {clusterAlert.owner_username ? (
                                  <span className="text-sm">{clusterAlert.owner_username}</span>
                                ) : (
                                  <span className="text-sm text-muted-foreground">Unassigned</span>
                                )}
                              </TableCell>
                              <TableCell className="text-muted-foreground">
                                <RelativeTime date={clusterAlert.created_at} />
                              </TableCell>
                            </TableRow>
                          )
                        })}
                      </Fragment>
                    )
                  })
                ) : (
                  // Non-clustered view
                  filteredAlerts.map((alert) => {
                    const ioc = getIocInfo(alert)
                    return (
                      <TableRow
                        key={alert.alert_id}
                        className={cn(
                          "cursor-pointer hover:bg-muted/50",
                          SEVERITY_CONFIG[alert.severity]?.rowClass
                        )}
                        onClick={(e) => {
                          if ((e.target as HTMLElement).closest('input[type="checkbox"]')) return
                          navigate(`/alerts/${alert.alert_id}`)
                        }}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={selectedAlerts.has(alert.alert_id)}
                            onCheckedChange={(checked) => handleSelectAlert(alert.alert_id, checked as boolean)}
                            aria-label={`Select IOC match ${alert.alert_id}`}
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
                        <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">
                          {ioc.mispEvent || '\u2014'}
                        </TableCell>
                        <TableCell>
                          <StatusBadge variant={alertStatusBadgeVariant(alert.status)}>
                            {ALERT_STATUS_LABELS[alert.status] || capitalize(alert.status)}
                          </StatusBadge>
                        </TableCell>
                        <TableCell>
                          {alert.owner_username ? (
                            <span className="text-sm">{alert.owner_username}</span>
                          ) : (
                            <span className="text-sm text-muted-foreground">Unassigned</span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          <RelativeTime date={alert.created_at} />
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </TooltipProvider>
      )}

      {/* Pagination Controls */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span>Show</span>
            <Select
              value={String(pageSize)}
              onValueChange={(value) => {
                setPageSize(Number(value))
                setPage(1)
              }}
            >
              <SelectTrigger className="w-20 h-8">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="z-50 bg-popover">
                <SelectItem value="10">10</SelectItem>
                <SelectItem value="25">25</SelectItem>
                <SelectItem value="50">50</SelectItem>
                <SelectItem value="100">100</SelectItem>
              </SelectContent>
            </Select>
            <span>per page</span>
          </div>

          <div className="text-sm text-muted-foreground">
            Showing {Math.min(offset + 1, total)} - {Math.min(offset + pageSize, total)} of {total}
          </div>

          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage(page - 1)} disabled={!canGoPrevious}>
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </span>
            <Button variant="outline" size="sm" onClick={() => setPage(page + 1)} disabled={!canGoNext}>
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Floating Bulk Action Bar */}
      {selectedAlerts.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 z-50">
          <span className="text-sm font-medium">
            {selectedAlerts.size} IOC match{selectedAlerts.size !== 1 ? 'es' : ''} selected
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleBulkAction('acknowledged')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts') || !osAvailable}
              title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
            >
              <Eye className="h-4 w-4 mr-1" />
              Acknowledge
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleBulkAction('resolved')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts') || !osAvailable}
              title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
            >
              <CheckCircle2 className="h-4 w-4 mr-1" />
              Resolve
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleBulkAction('false_positive')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts') || !osAvailable}
              title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
            >
              <XCircle className="h-4 w-4 mr-1" />
              False Positive
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleBulkTakeOwnership}
              disabled={isBulkUpdating || !hasPermission('manage_alerts') || !osAvailable}
              title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
            >
              <UserPlus className="h-4 w-4 mr-1" />
              Take Ownership
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={handleBulkDelete}
              disabled={isBulkUpdating || !hasPermission('manage_alerts') || !osAvailable}
              title={!osAvailable ? 'Unavailable while OpenSearch is offline' : undefined}
            >
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setSelectedAlerts(new Set())
              setSelectAll(false)
            }}
          >
            Cancel
          </Button>
        </div>
      )}
    </div>
  )
}
