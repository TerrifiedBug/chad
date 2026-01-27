import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { alertsApi, Alert, AlertStatus, AlertCountsResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Search, Bell, AlertTriangle, CheckCircle2, XCircle, ChevronLeft, ChevronRight, Link2, Trash2 } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'

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

export default function AlertsPage() {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [counts, setCounts] = useState<AlertCountsResponse | null>(null)
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  // Bulk selection state
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [selectAll, setSelectAll] = useState(false)
  const [isBulkUpdating, setIsBulkUpdating] = useState(false)

  // Load data function - must be declared before useEffect that uses it
  const loadData = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const offset = (page - 1) * pageSize
      const [alertsResponse, countsResponse] = await Promise.all([
        alertsApi.list({
          status: statusFilter === 'all' ? undefined : statusFilter,
          severity: severityFilter === 'all' ? undefined : severityFilter,
          limit: pageSize,
          offset,
        }),
        alertsApi.getCounts(),
      ])
      setAlerts(alertsResponse.alerts)
      setTotal(alertsResponse.total)
      setCounts(countsResponse)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts')
    } finally {
      setIsLoading(false)
    }
  }, [statusFilter, severityFilter, page, pageSize])

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1)
  }, [statusFilter, severityFilter])

  useEffect(() => {
    loadData()
  }, [statusFilter, severityFilter, page, pageSize, loadData])

  const totalPages = Math.ceil(total / pageSize)
  const canGoPrevious = page > 1
  const canGoNext = page < totalPages

  const filteredAlerts = alerts.filter((alert) =>
    alert.rule_title.toLowerCase().includes(search.toLowerCase())
  )

  // Bulk operation handlers
  const handleSelectAll = (checked: boolean) => {
    setSelectAll(checked)
    if (checked) {
      setSelectedAlerts(new Set(filteredAlerts.map(a => a.alert_id)))
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
    setSelectAll(newSelected.size === filteredAlerts.length && filteredAlerts.length > 0)
  }

  const handleBulkStatusUpdate = async (newStatus: AlertStatus) => {
    if (selectedAlerts.size === 0) return

    setIsBulkUpdating(true)
    setError('')
    try {
      await alertsApi.bulkUpdateStatus({
        alert_ids: Array.from(selectedAlerts),
        status: newStatus
      })
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update alerts')
    } finally {
      setIsBulkUpdating(false)
    }
  }

  const handleBulkDelete = async () => {
    if (selectedAlerts.size === 0) return

    if (!confirm(`Are you sure you want to delete ${selectedAlerts.size} alert(s)?`)) {
      return
    }

    setIsBulkUpdating(true)
    setError('')
    try {
      await alertsApi.bulkDelete({
        alert_ids: Array.from(selectedAlerts)
      })
      setSelectedAlerts(new Set())
      setSelectAll(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete alerts')
    } finally {
      setIsBulkUpdating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Alerts</h1>
      </div>

      {/* Stats Cards */}
      {counts && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
              <Bell className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.total}</div>
              <p className="text-xs text-muted-foreground">
                {counts.last_24h} in last 24h
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">New</CardTitle>
              <AlertTriangle className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_status['new'] || 0}</div>
              <p className="text-xs text-muted-foreground">Requires attention</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical</CardTitle>
              <XCircle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_severity['critical'] || 0}</div>
              <p className="text-xs text-muted-foreground">High priority</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Resolved</CardTitle>
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_status['resolved'] || 0}</div>
              <p className="text-xs text-muted-foreground">Investigated</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
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
        <Select
          value={severityFilter}
          onValueChange={setSeverityFilter}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="z-50 bg-popover">
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" onClick={loadData}>
          Refresh
        </Button>
      </div>

      {/* Bulk Action Bar */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
          <div className="text-sm font-medium">
            {selectedAlerts.size} alert{selectedAlerts.size !== 1 ? 's' : ''} selected
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('acknowledged')}
              disabled={isBulkUpdating}
            >
              Acknowledge
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('resolved')}
              disabled={isBulkUpdating}
            >
              Resolve
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleBulkStatusUpdate('false_positive')}
              disabled={isBulkUpdating}
            >
              False Positive
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleBulkDelete}
              disabled={isBulkUpdating}
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
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : filteredAlerts.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          {search || statusFilter !== 'all' || severityFilter !== 'all'
            ? 'No alerts match your filters'
            : 'No alerts yet. Alerts will appear when rules match incoming logs.'}
        </div>
      ) : (
        <TooltipProvider>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectAll}
                      onCheckedChange={handleSelectAll}
                      aria-label="Select all alerts"
                    />
                  </TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.map((alert) => (
                  <TableRow
                    key={alert.alert_id}
                    className="cursor-pointer hover:bg-muted/50"
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
                        <span>{alert.rule_title}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          severityColors[alert.severity] || 'bg-gray-500 text-white'
                        }`}
                      >
                        {capitalize(alert.severity)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${statusColors[alert.status]}`}
                      >
                        {statusLabels[alert.status]}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {alert.tags
                          .filter(tag => tag !== 'correlation')
                          .slice(0, 3)
                          .map((tag, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.5 bg-muted rounded text-xs"
                            >
                              {tag}
                            </span>
                          ))}
                        {alert.tags.filter(tag => tag !== 'correlation').length > 3 && (
                          <span className="text-xs text-muted-foreground">
                            +{alert.tags.filter(tag => tag !== 'correlation').length - 3}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <RelativeTime date={alert.created_at} />
                    </TableCell>
                  </TableRow>
                ))}
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
    </div>
  )
}
