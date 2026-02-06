import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { alertsApi, Alert, AlertStatus, AlertCountsResponse, reportsApi, ReportFormat, AlertCluster, ClusteredAlertListResponse, AlertListResponse, mispApi, mispFeedbackApi } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Search, Bell, AlertTriangle, CheckCircle2, XCircle, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, Link2, Trash2, Download, Loader2, FileText, FileSpreadsheet, Layers, UserPlus, ShieldAlert, ExternalLink, X, RotateCcw, LayoutList, List } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'
import { DateRangePicker } from '@/components/ui/date-range-picker'
import { DateRange } from 'react-day-picker'
import { cn } from '@/lib/utils'
import { SEVERITY_COLORS, ALERT_STATUS_COLORS, ALERT_STATUS_LABELS, capitalize, SEVERITY_CONFIG } from '@/lib/constants'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { Skeleton, SkeletonTable } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/dashboard/StatCard'
import { SeverityPills } from '@/components/filters/SeverityPills'
import { chunkedBulkOperation, type BulkProgress } from '@/lib/bulk-utils'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const
const ALERT_TYPES = ['sigma', 'ioc', 'correlation'] as const
type AlertType = typeof ALERT_TYPES[number]

// Type guard to check if response is clustered
function isClusteredResponse(response: AlertListResponse | ClusteredAlertListResponse): response is ClusteredAlertListResponse {
  return 'clusters' in response
}

export default function AlertsPage() {
  const navigate = useNavigate()
  const { hasPermission } = useAuth()
  const { showToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [clusters, setClusters] = useState<AlertCluster[]>([])
  const [isClustered, setIsClustered] = useState(false)
  const [counts, setCounts] = useState<AlertCountsResponse | null>(null)
  const [total, setTotal] = useState(0)
  const [totalClusters, setTotalClusters] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Initialize filters from URL params
  const [search, setSearch] = useState(() => searchParams.get('search') || '')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>(() => {
    const status = searchParams.get('status')
    if (status === 'new' || status === 'acknowledged' || status === 'resolved' || status === 'false_positive') {
      return status
    }
    return 'all'
  })
  const [severityFilter, setSeverityFilter] = useState<string[]>(() => {
    const severities = searchParams.get('severity')
    return severities ? severities.split(',').filter(s => SEVERITIES.includes(s as typeof SEVERITIES[number])) : []
  })
  const [alertTypeFilter, setAlertTypeFilter] = useState<AlertType[]>(() => {
    const types = searchParams.get('type')
    return types ? types.split(',').filter(t => ALERT_TYPES.includes(t as AlertType)) as AlertType[] : []
  })
  const [page, setPage] = useState(1)

  // Owner filter - initialize from URL query param, fallback to localStorage
  const [ownerFilter, setOwnerFilter] = useState<string | null>(() => {
    const urlParam = searchParams.get('owner')
    if (urlParam) return urlParam
    // Fallback to localStorage for persistent "Assigned to Me" preference
    const stored = localStorage.getItem('alerts-assigned-to-me')
    return stored === 'true' ? 'me' : null
  })

  // Expanded clusters state
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set())

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    )
  }
  const toggleAlertTypeFilter = (type: AlertType) => {
    setAlertTypeFilter(prev =>
      prev.includes(type)
        ? prev.filter(t => t !== type)
        : [...prev, type]
    )
  }
  const [pageSize, setPageSize] = useState(25)

  // Compact mode state with localStorage persistence
  const [isCompact, setIsCompact] = useState(() => {
    const saved = localStorage.getItem('alerts-compact-mode')
    return saved ? JSON.parse(saved) : false
  })

  // Persist compact mode to localStorage
  useEffect(() => {
    localStorage.setItem('alerts-compact-mode', JSON.stringify(isCompact))
  }, [isCompact])

  // Bulk selection state
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [selectAll, setSelectAll] = useState(false)
  const [isBulkUpdating, setIsBulkUpdating] = useState(false)
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false)
  const [bulkProgress, setBulkProgress] = useState<BulkProgress | null>(null)

  // Export state
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [exportFormat, setExportFormat] = useState<ReportFormat>('pdf')
  const [exportDateRange, setExportDateRange] = useState<DateRange | undefined>()
  const [isExporting, setIsExporting] = useState(false)

  // Bulk MISP export state
  const [showBulkMISPExport, setShowBulkMISPExport] = useState(false)
  const [mispExportProgress, setMispExportProgress] = useState({ current: 0, total: 0 })
  const [mispExportResults, setMispExportResults] = useState<{ success: number; failed: number } | null>(null)

  // Check MISP status for bulk export
  const { data: mispStatus } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
  })

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

  // Load data function - must be declared before useEffect that uses it
  const loadData = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const offset = (page - 1) * pageSize
      const [alertsResponse, countsResponse] = await Promise.all([
        alertsApi.list({
          status: statusFilter === 'all' ? undefined : statusFilter,
          // Pass single severity if exactly one selected, otherwise filter client-side
          severity: severityFilter.length === 1 ? severityFilter[0] : undefined,
          owner: ownerFilter,
          limit: pageSize,
          offset,
        }) as Promise<AlertListResponse | ClusteredAlertListResponse>,
        alertsApi.getCounts(),
      ])

      // Handle clustered or non-clustered response
      if (isClusteredResponse(alertsResponse)) {
        setIsClustered(true)
        setClusters(alertsResponse.clusters)
        setAlerts([])
        setTotal(alertsResponse.total)
        setTotalClusters(alertsResponse.total_clusters)
      } else {
        setIsClustered(false)
        setClusters([])
        setAlerts(alertsResponse.alerts)
        setTotal(alertsResponse.total)
        setTotalClusters(0)
      }
      setCounts(countsResponse)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts')
    } finally {
      setIsLoading(false)
    }
  }, [statusFilter, severityFilter, ownerFilter, page, pageSize])

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1)
  }, [statusFilter, severityFilter, alertTypeFilter, ownerFilter])

  // Sync all filters with URL
  useEffect(() => {
    const newParams = new URLSearchParams()

    if (search) newParams.set('search', search)
    if (statusFilter !== 'all') newParams.set('status', statusFilter)
    if (severityFilter.length > 0) newParams.set('severity', severityFilter.join(','))
    if (alertTypeFilter.length > 0) newParams.set('type', alertTypeFilter.join(','))
    if (ownerFilter) newParams.set('owner', ownerFilter)

    setSearchParams(newParams, { replace: true })

    // Persist "Assigned to Me" preference to localStorage
    localStorage.setItem('alerts-assigned-to-me', ownerFilter === 'me' ? 'true' : 'false')
  }, [search, statusFilter, severityFilter, alertTypeFilter, ownerFilter, setSearchParams])

  useEffect(() => {
    loadData()
  }, [statusFilter, severityFilter, ownerFilter, page, pageSize, loadData])

  const totalPages = Math.ceil(total / pageSize)
  const canGoPrevious = page > 1
  const canGoNext = page < totalPages

  // Helper to determine alert type
  const getAlertType = (alert: Alert): AlertType => {
    if (alert.tags.includes('correlation')) return 'correlation'
    if (alert.rule_id === 'ioc-detection') return 'ioc'
    return 'sigma'
  }

  // Filter alerts (works for non-clustered mode)
  const filteredAlerts = alerts.filter((alert) => {
    // Search filter (handle null rule_title for deleted rules)
    if (!(alert.rule_title || '').toLowerCase().includes(search.toLowerCase())) {
      return false
    }
    // Severity filter (client-side when multiple selected)
    if (severityFilter.length > 1 && !severityFilter.includes(alert.severity)) {
      return false
    }
    // Alert type filter
    if (alertTypeFilter.length > 0 && !alertTypeFilter.includes(getAlertType(alert))) {
      return false
    }
    return true
  })

  // Filter clusters (client-side search/filter for clustered mode)
  const filteredClusters = clusters.filter((cluster) => {
    // Search filter (handle null rule_title for deleted rules)
    if (!(cluster.representative.rule_title || '').toLowerCase().includes(search.toLowerCase())) {
      return false
    }
    // Severity filter
    if (severityFilter.length > 1 && !severityFilter.includes(cluster.representative.severity)) {
      return false
    }
    // Alert type filter
    if (alertTypeFilter.length > 0 && !alertTypeFilter.includes(getAlertType(cluster.representative))) {
      return false
    }
    return true
  })

  // Get all alert IDs for selection (from clusters or alerts)
  const getAllSelectableAlertIds = (): string[] => {
    if (isClustered) {
      return filteredClusters.flatMap(c => c.alert_ids)
    }
    return filteredAlerts.map(a => a.alert_id)
  }

  // Bulk operation handlers
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

  const handleBulkStatusUpdate = async (newStatus: AlertStatus) => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setBulkProgress(null)
    setError('')
    try {
      const ids = Array.from(selectedAlerts)
      const result = await chunkedBulkOperation(
        ids,
        (batch) => alertsApi.bulkUpdateStatus({ alert_ids: batch, status: newStatus }),
        (progress) => setBulkProgress(progress),
      )
      if (result.errors.length > 0) {
        setError(`Updated ${result.totalProcessed} alerts. ${result.totalFailed} failed: ${result.errors[0]}`)
      }
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update alerts')
    } finally {
      setIsBulkUpdating(false)
      setBulkProgress(null)
    }
  }

  const handleBulkDelete = () => {
    if (selectedAlerts.size === 0) return
    setShowBulkDeleteConfirm(true)
  }

  const handleBulkTakeOwnership = async () => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setError('')
    try {
      // Assign each selected alert to current user
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

  const confirmBulkDelete = async () => {
    if (selectedAlerts.size === 0) return
    setIsBulkUpdating(true)
    setBulkProgress(null)
    setError('')
    setShowBulkDeleteConfirm(false)
    try {
      const ids = Array.from(selectedAlerts)
      const result = await chunkedBulkOperation(
        ids,
        (batch) => alertsApi.bulkDelete({ alert_ids: batch }),
        (progress) => setBulkProgress(progress),
      )
      if (result.errors.length > 0) {
        setError(`Deleted ${result.totalProcessed} alerts. ${result.totalFailed} failed: ${result.errors[0]}`)
      }
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete alerts')
    } finally {
      setIsBulkUpdating(false)
      setBulkProgress(null)
    }
  }

  // Handle bulk MISP export
  const handleBulkMISPExport = async () => {
    if (selectedAlerts.size === 0) return

    setMispExportProgress({ current: 0, total: selectedAlerts.size })
    setMispExportResults(null)
    setIsBulkUpdating(true)

    let success = 0
    let failed = 0
    const alertIds = Array.from(selectedAlerts)

    for (let i = 0; i < alertIds.length; i++) {
      const alertId = alertIds[i]
      try {
        // Find the alert to get its title
        const alert = alerts.find(a => a.alert_id === alertId)
        const title = alert?.rule_title || `Alert ${alertId}`

        await mispFeedbackApi.createEvent({
          alert_id: alertId,
          info: `CHAD Alert: ${title}`,
          threat_level: 2, // Medium
          distribution: 0, // Your organization only
          tags: ['source:chad', 'bulk-export'],
          attributes: [],
        })
        success++
      } catch {
        failed++
      }
      setMispExportProgress({ current: i + 1, total: alertIds.length })
    }

    setMispExportResults({ success, failed })
    setIsBulkUpdating(false)

    if (success > 0) {
      showToast(`Created ${success} MISP event${success !== 1 ? 's' : ''}`)
    }
    if (failed > 0) {
      showToast(`Failed to create ${failed} event${failed !== 1 ? 's' : ''}`, 'error')
    }
  }

  // Handle export
  const handleExport = async () => {
    setIsExporting(true)
    try {
      const blob = await reportsApi.generateAlertSummary({
        format: exportFormat,
        date_from: exportDateRange?.from?.toISOString().split('T')[0],
        date_to: exportDateRange?.to?.toISOString().split('T')[0],
        severity: severityFilter.length > 0 ? severityFilter : undefined,
      })

      // Create download link
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const timestamp = new Date().toISOString().slice(0, 10)
      a.download = `alert-summary-${timestamp}.${exportFormat}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)

      setShowExportDialog(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export report')
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <div className="flex items-center gap-3">
            <span>Alerts</span>
            {isClustered && totalClusters > 0 && (
              <div className="flex items-center gap-1.5 text-sm font-normal text-muted-foreground bg-muted/50 px-2 py-0.5 rounded">
                <Layers className="h-3.5 w-3.5" />
                <span>{totalClusters} clusters from {total} alerts</span>
              </div>
            )}
          </div>
        }
        description="Monitor and manage security alerts"
        actions={
          <Button variant="outline" onClick={() => setShowExportDialog(true)}>
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
        }
      />

      {/* Stats Cards */}
      {counts && (
        <div className="grid gap-4 md:grid-cols-4">
          <StatCard
            title="Total Alerts"
            value={counts.total}
            subtext={`${counts.last_24h} in last 24h`}
            icon={Bell}
            onClick={() => setStatusFilter('all')}
          />
          <StatCard
            title="New"
            value={counts.by_status['new'] || 0}
            subtext="Requires attention"
            icon={AlertTriangle}
            onClick={() => setStatusFilter('new')}
            variant={(counts.by_status['new'] || 0) > 10 ? 'warning' : 'default'}
            showUrgencyRing={(counts.by_status['new'] || 0) > 10}
            pulseOnCritical
            criticalThreshold={10}
          />
          <StatCard
            title="Critical"
            value={counts.by_severity['critical'] || 0}
            subtext="High priority"
            icon={XCircle}
            onClick={() => {
              setSeverityFilter(['critical'])
              setStatusFilter('all')
            }}
            variant={(counts.by_severity['critical'] || 0) > 0 ? 'danger' : 'default'}
            showUrgencyRing={(counts.by_severity['critical'] || 0) > 0}
            pulseOnCritical
            criticalThreshold={0}
          />
          <StatCard
            title="Resolved"
            value={counts.by_status['resolved'] || 0}
            subtext="Investigated"
            icon={CheckCircle2}
            onClick={() => setStatusFilter('resolved')}
            variant="success"
          />
        </div>
      )}

      {/* Filters - Primary Row */}
      <div className="space-y-3">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search alerts..."
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
            value={statusFilter}
            onValueChange={(value) => setStatusFilter(value as AlertStatus | 'all')}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent className="z-50 bg-popover">
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="acknowledged">Acknowledged</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="w-32 justify-between">
                Type
                {alertTypeFilter.length > 0 && (
                  <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                    {alertTypeFilter.length}
                  </Badge>
                )}
                <ChevronDown className="h-4 w-4 ml-auto" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="z-50">
              <DropdownMenuLabel>Filter by Type</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuCheckboxItem
                checked={alertTypeFilter.includes('sigma')}
                onCheckedChange={() => toggleAlertTypeFilter('sigma')}
                onSelect={(e) => e.preventDefault()}
              >
                <FileText className="h-3 w-3 mr-2 text-blue-500" />
                Sigma
              </DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                checked={alertTypeFilter.includes('ioc')}
                onCheckedChange={() => toggleAlertTypeFilter('ioc')}
                onSelect={(e) => e.preventDefault()}
              >
                <ShieldAlert className="h-3 w-3 mr-2 text-red-500" />
                IOC
              </DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                checked={alertTypeFilter.includes('correlation')}
                onCheckedChange={() => toggleAlertTypeFilter('correlation')}
                onSelect={(e) => e.preventDefault()}
              >
                <Link2 className="h-3 w-3 mr-2 text-purple-500" />
                Correlation
              </DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="my-alerts"
              checked={ownerFilter === 'me'}
              onCheckedChange={(checked) => setOwnerFilter(checked ? 'me' : null)}
            />
            <Label htmlFor="my-alerts" className="text-sm cursor-pointer">Assigned to me</Label>
          </div>
        </div>

        {/* Filters - Secondary Row: Severity Pills + Clustering Info */}
        <div className="flex flex-wrap items-center gap-3">
          <SeverityPills
            selected={severityFilter}
            onChange={toggleSeverityFilter}
            showCounts={counts?.by_severity}
            size="sm"
          />

          {/* Clear All Filters */}
          {(search || statusFilter !== 'all' || severityFilter.length > 0 || alertTypeFilter.length > 0 || ownerFilter) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearch('')
                setStatusFilter('all')
                setSeverityFilter([])
                setAlertTypeFilter([])
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
            <Button variant="ghost" size="icon" onClick={loadData} title="Refresh" className="text-muted-foreground">
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

      {/* Bulk Action Bar */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
          <div className="text-sm font-medium">
            {bulkProgress
              ? `Processing ${bulkProgress.completed}/${bulkProgress.total}...`
              : `${selectedAlerts.size} alert${selectedAlerts.size !== 1 ? 's' : ''} selected`
            }
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('acknowledged')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts')}
              title={!hasPermission('manage_alerts') ? 'Permission required: manage_alerts' : undefined}
            >
              Acknowledge
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('resolved')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts')}
              title={!hasPermission('manage_alerts') ? 'Permission required: manage_alerts' : undefined}
            >
              Resolve
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('false_positive')}
              disabled={isBulkUpdating || !hasPermission('manage_alerts')}
              title={!hasPermission('manage_alerts') ? 'Permission required: manage_alerts' : undefined}
            >
              False Positive
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleBulkTakeOwnership}
              disabled={isBulkUpdating || !hasPermission('manage_alerts')}
              title={!hasPermission('manage_alerts') ? 'Permission required: manage_alerts' : undefined}
            >
              <UserPlus className="h-4 w-4 mr-1" />
              Take Ownership
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowBulkMISPExport(true)}
              disabled={isBulkUpdating || !mispStatus?.configured}
              title={!mispStatus?.configured ? 'MISP not configured' : undefined}
            >
              <ExternalLink className="h-4 w-4 mr-1 text-purple-500" />
              Export to MISP
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleBulkDelete}
              disabled={isBulkUpdating || !hasPermission('manage_alerts')}
              title={!hasPermission('manage_alerts') ? 'Permission required: manage_alerts' : undefined}
            >
              <Trash2 className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      )}


      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="space-y-4">
          {/* Skeleton for filter bar */}
          <div className="flex gap-2">
            <Skeleton className="h-10 w-64" />
            <Skeleton className="h-10 w-32" />
            <Skeleton className="h-10 w-32" />
          </div>
          {/* Skeleton table */}
          <SkeletonTable rows={10} columns={7} />
        </div>
      ) : (isClustered ? filteredClusters.length === 0 : filteredAlerts.length === 0) ? (
        <EmptyState
          icon={<Bell className="h-12 w-12" />}
          title={search || statusFilter !== 'all' || severityFilter.length > 0 ? 'No alerts match your filters' : 'No alerts yet'}
          description={search || statusFilter !== 'all' || severityFilter.length > 0
            ? 'Try adjusting your filters to see more results.'
            : 'Alerts will appear when rules match incoming logs.'}
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
                      aria-label="Select all alerts"
                    />
                  </TableHead>
                  {isClustered && <TableHead className="w-[60px]"></TableHead>}
                  <TableHead>Rule</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Created</TableHead>
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

                    return (
                      <>
                        {/* Cluster header row */}
                        <TableRow
                          key={clusterId}
                          className={cn(
                            "cursor-pointer hover:bg-muted/50",
                            hasMultiple ? "border-l-2 border-l-primary" : SEVERITY_CONFIG[alert.severity]?.rowClass
                          )}
                          onClick={(e) => {
                            // Don't navigate if clicking checkbox or expand button
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
                              aria-label={`Select cluster of ${cluster.count} alerts`}
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
                              <div className="w-[60px]" /> // Spacer for alignment
                            )}
                          </TableCell>
                          <TableCell className="font-medium">
                            <div className="flex items-center gap-2">
                              {alert.tags.includes('correlation') && (
                                <div className="flex items-center gap-1 px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs font-medium">
                                  <Link2 className="h-3 w-3" />
                                  <span>Correlation</span>
                                </div>
                              )}
                              {alert.rule_id === 'ioc-detection' && (
                                <div className="flex items-center gap-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                                  <ShieldAlert className="h-3 w-3" />
                                  <span>IOC</span>
                                </div>
                              )}
                              {!alert.tags.includes('correlation') && alert.rule_id !== 'ioc-detection' && (
                                <div className="flex items-center gap-1 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded text-xs font-medium">
                                  <FileText className="h-3 w-3" />
                                  <span>Sigma</span>
                                </div>
                              )}
                              <span>{alert.rule_title}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <span
                              className={`px-2 py-1 rounded text-xs font-medium ${
                                SEVERITY_COLORS[alert.severity] || 'bg-gray-500 text-white'
                              }`}
                            >
                              {capitalize(alert.severity)}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className={`px-2 py-1 rounded text-xs font-medium ${ALERT_STATUS_COLORS[alert.status]}`}
                            >
                              {ALERT_STATUS_LABELS[alert.status]}
                            </span>
                          </TableCell>
                          <TableCell>
                            {alert.owner_username ? (
                              <span className="text-sm">{alert.owner_username}</span>
                            ) : (
                              <span className="text-sm text-muted-foreground">Unassigned</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              {alert.tags
                                .filter(tag => tag !== 'correlation' && tag !== 'ioc-match')
                                .slice(0, 2)
                                .map((tag, i) => (
                                  <span
                                    key={i}
                                    className="px-1.5 py-0.5 bg-muted rounded text-xs truncate max-w-[80px]"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              {alert.tags.filter(tag => tag !== 'correlation' && tag !== 'ioc-match').length > 2 && (
                                <span className="text-xs text-muted-foreground whitespace-nowrap">
                                  +{alert.tags.filter(tag => tag !== 'correlation' && tag !== 'ioc-match').length - 2}
                                </span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {hasMultiple ? (
                              <span className="text-xs">
                                {cluster.time_range[0] && cluster.time_range[1] ? (
                                  // Only show range if timestamps differ by more than a minute
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

                        {/* Expanded cluster rows - show full alert details */}
                        {isExpanded && hasMultiple && cluster.alerts.map((clusterAlert, idx) => (
                          <TableRow
                            key={`${clusterId}-${clusterAlert.alert_id}`}
                            className="bg-muted/30 cursor-pointer hover:bg-muted/50"
                            onClick={() => navigate(`/alerts/${clusterAlert.alert_id}`)}
                          >
                            <TableCell onClick={(e) => e.stopPropagation()}>
                              <Checkbox
                                checked={selectedAlerts.has(clusterAlert.alert_id)}
                                onCheckedChange={(checked) => handleSelectAlert(clusterAlert.alert_id, checked as boolean)}
                                aria-label={`Select alert ${clusterAlert.alert_id}`}
                              />
                            </TableCell>
                            <TableCell></TableCell>
                            <TableCell className="font-medium pl-8">
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-muted-foreground">#{idx + 1}</span>
                                {clusterAlert.tags.includes('correlation') && (
                                  <div className="flex items-center gap-1 px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs font-medium">
                                    <Link2 className="h-3 w-3" />
                                    <span>Correlation</span>
                                  </div>
                                )}
                                {clusterAlert.rule_id === 'ioc-detection' && (
                                  <div className="flex items-center gap-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                                    <ShieldAlert className="h-3 w-3" />
                                    <span>IOC</span>
                                  </div>
                                )}
                                {!clusterAlert.tags.includes('correlation') && clusterAlert.rule_id !== 'ioc-detection' && (
                                  <div className="flex items-center gap-1 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded text-xs font-medium">
                                    <FileText className="h-3 w-3" />
                                    <span>Sigma</span>
                                  </div>
                                )}
                                <span>{clusterAlert.rule_title}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <span
                                className={`px-2 py-1 rounded text-xs font-medium ${
                                  SEVERITY_COLORS[clusterAlert.severity] || 'bg-gray-500 text-white'
                                }`}
                              >
                                {capitalize(clusterAlert.severity)}
                              </span>
                            </TableCell>
                            <TableCell>
                              <span
                                className={`px-2 py-1 rounded text-xs font-medium ${ALERT_STATUS_COLORS[clusterAlert.status]}`}
                              >
                                {ALERT_STATUS_LABELS[clusterAlert.status]}
                              </span>
                            </TableCell>
                            <TableCell>
                              {clusterAlert.owner_username ? (
                                <span className="text-sm">{clusterAlert.owner_username}</span>
                              ) : (
                                <span className="text-sm text-muted-foreground">Unassigned</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <div className="flex gap-1 flex-wrap">
                                {clusterAlert.tags
                                  .filter(tag => tag !== 'correlation' && tag !== 'ioc-match')
                                  .slice(0, 2)
                                  .map((tag, i) => (
                                    <span
                                      key={i}
                                      className="px-1.5 py-0.5 bg-muted rounded text-xs"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                {clusterAlert.tags.filter(tag => tag !== 'correlation').length > 2 && (
                                  <span className="text-xs text-muted-foreground">
                                    +{clusterAlert.tags.filter(tag => tag !== 'correlation').length - 2}
                                  </span>
                                )}
                              </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              <RelativeTime date={clusterAlert.created_at} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </>
                    )
                  })
                ) : (
                  // Non-clustered view
                  filteredAlerts.map((alert) => (
                    <TableRow
                      key={alert.alert_id}
                      className={cn(
                        "cursor-pointer hover:bg-muted/50",
                        SEVERITY_CONFIG[alert.severity]?.rowClass
                      )}
                      onClick={(e) => {
                        // Don't navigate if clicking checkbox
                        if ((e.target as HTMLElement).closest('input[type="checkbox"]')) {
                          return
                        }
                        navigate(`/alerts/${alert.alert_id}`)
                      }}
                    >
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selectedAlerts.has(alert.alert_id)}
                          onCheckedChange={(checked) => handleSelectAlert(alert.alert_id, checked as boolean)}
                          aria-label={`Select alert ${alert.alert_id}`}
                        />
                      </TableCell>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          {alert.tags.includes('correlation') && (
                            <div className="flex items-center gap-1 px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs font-medium">
                              <Link2 className="h-3 w-3" />
                              <span>Correlation</span>
                            </div>
                          )}
                          {alert.rule_id === 'ioc-detection' && (
                            <div className="flex items-center gap-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                              <ShieldAlert className="h-3 w-3" />
                              <span>IOC</span>
                            </div>
                          )}
                          {!alert.tags.includes('correlation') && alert.rule_id !== 'ioc-detection' && (
                            <div className="flex items-center gap-1 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded text-xs font-medium">
                              <FileText className="h-3 w-3" />
                              <span>Sigma</span>
                            </div>
                          )}
                          <span>{alert.rule_title}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <span
                          className={`px-2 py-1 rounded text-xs font-medium ${
                            SEVERITY_COLORS[alert.severity] || 'bg-gray-500 text-white'
                          }`}
                        >
                          {capitalize(alert.severity)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span
                          className={`px-2 py-1 rounded text-xs font-medium ${ALERT_STATUS_COLORS[alert.status]}`}
                        >
                          {ALERT_STATUS_LABELS[alert.status]}
                        </span>
                      </TableCell>
                      <TableCell>
                        {alert.owner_username ? (
                          <span className="text-sm">{alert.owner_username}</span>
                        ) : (
                          <span className="text-sm text-muted-foreground">Unassigned</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {alert.tags
                            .filter(tag => tag !== 'correlation' && tag !== 'ioc-match')
                            .slice(0, 2)
                            .map((tag, i) => (
                              <span
                                key={i}
                                className="px-1.5 py-0.5 bg-muted rounded text-xs truncate max-w-[80px]"
                              >
                                {tag}
                              </span>
                            ))}
                          {alert.tags.filter(tag => tag !== 'correlation' && tag !== 'ioc-match').length > 2 && (
                            <span className="text-xs text-muted-foreground whitespace-nowrap">
                              +{alert.tags.filter(tag => tag !== 'correlation' && tag !== 'ioc-match').length - 2}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        <RelativeTime date={alert.created_at} />
                      </TableCell>
                    </TableRow>
                  ))
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
            Showing {Math.min((page - 1) * pageSize + 1, total)} - {Math.min(page * pageSize, total)} of {total} alerts
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(page - 1)}
              disabled={!canGoPrevious}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(page + 1)}
              disabled={!canGoNext}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Bulk Delete Confirmation Dialog */}
      <Dialog
        open={showBulkDeleteConfirm}
        onOpenChange={(open) => {
          if (isBulkUpdating) return
          setShowBulkDeleteConfirm(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Alerts</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete {selectedAlerts.size} alert{selectedAlerts.size !== 1 ? 's' : ''}? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowBulkDeleteConfirm(false)}
              disabled={isBulkUpdating}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmBulkDelete}
              disabled={isBulkUpdating}
            >
              {isBulkUpdating ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk MISP Export Dialog */}
      <Dialog
        open={showBulkMISPExport}
        onOpenChange={(open) => {
          if (isBulkUpdating) return
          setShowBulkMISPExport(open)
          if (!open) {
            setMispExportProgress({ current: 0, total: 0 })
            setMispExportResults(null)
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Export to MISP</DialogTitle>
            <DialogDescription>
              {mispExportResults ? (
                `Export complete: ${mispExportResults.success} created, ${mispExportResults.failed} failed`
              ) : isBulkUpdating ? (
                `Exporting ${mispExportProgress.current} of ${mispExportProgress.total} alerts...`
              ) : (
                `Create ${selectedAlerts.size} MISP event${selectedAlerts.size !== 1 ? 's' : ''} from the selected alerts. Each alert will be exported as a separate event.`
              )}
            </DialogDescription>
          </DialogHeader>
          {isBulkUpdating && (
            <div className="w-full bg-muted rounded-full h-2">
              <div
                className="bg-primary h-2 rounded-full transition-all"
                style={{ width: `${(mispExportProgress.current / mispExportProgress.total) * 100}%` }}
              />
            </div>
          )}
          <DialogFooter>
            {mispExportResults ? (
              <Button onClick={() => {
                setShowBulkMISPExport(false)
                setMispExportResults(null)
                setSelectedAlerts(new Set())
                setSelectAll(false)
              }}>
                Done
              </Button>
            ) : (
              <>
                <Button
                  variant="outline"
                  onClick={() => setShowBulkMISPExport(false)}
                  disabled={isBulkUpdating}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleBulkMISPExport}
                  disabled={isBulkUpdating}
                >
                  {isBulkUpdating ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Exporting...
                    </>
                  ) : (
                    'Export'
                  )}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Export Dialog */}
      <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Export Alert Summary Report</DialogTitle>
            <DialogDescription>
              Generate a report of alert statistics and trends.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Format</Label>
              <Select value={exportFormat} onValueChange={(v) => setExportFormat(v as ReportFormat)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pdf">
                    <span className="flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      PDF
                    </span>
                  </SelectItem>
                  <SelectItem value="csv">
                    <span className="flex items-center gap-2">
                      <FileSpreadsheet className="h-4 w-4" />
                      CSV
                    </span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Date Range</Label>
              <DateRangePicker
                value={exportDateRange}
                onChange={setExportDateRange}
              />
              <p className="text-xs text-muted-foreground">
                Leave empty to export the last 30 days.
              </p>
            </div>

            {severityFilter.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Filtering by severity: {severityFilter.join(', ')}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowExportDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleExport} disabled={isExporting}>
              {isExporting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
