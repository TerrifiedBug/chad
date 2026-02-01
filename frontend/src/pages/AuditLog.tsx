import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { DateRange } from 'react-day-picker'
import { auditApi, AuditLogEntry, AuditLogListResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { DateRangePicker } from '@/components/ui/date-range-picker'
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ArrowLeft, ChevronLeft, ChevronRight, Download, Eye, RefreshCw, FileText } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { TooltipProvider } from '@/components/ui/tooltip'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'

const PAGE_SIZE = 50

export default function AuditLogPage() {
  const [auditData, setAuditData] = useState<AuditLogListResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Filter options from API
  const [actions, setActions] = useState<string[]>([])
  const [resourceTypes, setResourceTypes] = useState<string[]>([])

  // Current filters
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [resourceTypeFilter, setResourceTypeFilter] = useState<string>('all')
  const [dateRange, setDateRange] = useState<DateRange | undefined>()
  const [currentPage, setCurrentPage] = useState(0)

  // Detail dialog
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null)
  const [isDetailOpen, setIsDetailOpen] = useState(false)

  // Load functions - must be declared before useEffect that uses them
  const loadAuditLogs = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const params: Parameters<typeof auditApi.list>[0] = {
        limit: PAGE_SIZE,
        offset: currentPage * PAGE_SIZE,
      }
      if (actionFilter !== 'all') params.action = actionFilter
      if (resourceTypeFilter !== 'all') params.resource_type = resourceTypeFilter
      if (dateRange?.from) params.start_date = dateRange.from.toISOString()
      if (dateRange?.to) {
        // Set end date to end of day
        const end = new Date(dateRange.to)
        end.setHours(23, 59, 59, 999)
        params.end_date = end.toISOString()
      }

      const response = await auditApi.list(params)
      setAuditData(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit logs')
    } finally {
      setIsLoading(false)
    }
  }, [actionFilter, resourceTypeFilter, dateRange, currentPage])

  const loadFilterOptions = async () => {
    try {
      const [actionsRes, typesRes] = await Promise.all([
        auditApi.getActions(),
        auditApi.getResourceTypes(),
      ])
      setActions(actionsRes.actions)
      setResourceTypes(typesRes.resource_types)
    } catch {
      console.log('Failed to load filter options')
    }
  }

  useEffect(() => {
    loadFilterOptions()
  }, [])

  useEffect(() => {
    loadAuditLogs()
  }, [loadAuditLogs])

  const handleViewDetails = (entry: AuditLogEntry) => {
    setSelectedEntry(entry)
    setIsDetailOpen(true)
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  const formatAction = (action: string, details?: Record<string, unknown>) => {
    // Special formatting for correlation rule events
    if (action.startsWith('correlation_rule_')) {
      const actions: Record<string, string> = {
        correlation_rule_created: 'Created correlation rule',
        correlation_rule_updated: 'Updated correlation rule',
        correlation_rule_deleted: 'Deleted correlation rule',
        correlation_rule_enabled: 'Enabled correlation rule',
        correlation_rule_disabled: 'Disabled correlation rule',
      }
      const formatted = actions[action] || action
      // Add rule name if available
      if (details?.name) {
        return `${formatted}: ${details.name}`
      }
      return formatted
    }

    // Convert snake_case to Title Case
    return action
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  const formatResourceType = (type: string) => {
    // Convert snake_case to Title Case
    return type
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  const totalPages = auditData ? Math.ceil(auditData.total / PAGE_SIZE) : 0

  const handlePrevPage = () => {
    if (currentPage > 0) {
      setCurrentPage(currentPage - 1)
    }
  }

  const handleNextPage = () => {
    if (currentPage < totalPages - 1) {
      setCurrentPage(currentPage + 1)
    }
  }

  const resetFilters = () => {
    setActionFilter('all')
    setResourceTypeFilter('all')
    setDateRange(undefined)
    setCurrentPage(0)
  }

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const filters: {
        action?: string
        resource_type?: string
        start_date?: string
        end_date?: string
      } = {}

      if (actionFilter !== 'all') filters.action = actionFilter
      if (resourceTypeFilter !== 'all') filters.resource_type = resourceTypeFilter
      if (dateRange?.from) filters.start_date = dateRange.from.toISOString()
      if (dateRange?.to) {
        const end = new Date(dateRange.to)
        end.setHours(23, 59, 59, 999)
        filters.end_date = end.toISOString()
      }

      const blob = await auditApi.export(format, filters)

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit_logs.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError('Export failed')
    }
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/settings">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div>
            <h1 className="text-2xl font-bold">Audit Log</h1>
            <p className="text-muted-foreground">View system activity and changes</p>
          </div>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline">
              <Download className="mr-2 h-4 w-4" /> Export
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={() => handleExport('csv')}>
              Export as CSV
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleExport('json')}>
              Export as JSON
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label>Action</Label>
              <Select value={actionFilter} onValueChange={(v) => { setActionFilter(v); setCurrentPage(0); }}>
                <SelectTrigger>
                  <SelectValue placeholder="All Actions" />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  <SelectItem value="all">All Actions</SelectItem>
                  {actions.map((action) => (
                    <SelectItem key={action} value={action}>
                      {formatAction(action)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Resource Type</Label>
              <Select value={resourceTypeFilter} onValueChange={(v) => { setResourceTypeFilter(v); setCurrentPage(0); }}>
                <SelectTrigger>
                  <SelectValue placeholder="All Types" />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  <SelectItem value="all">All Types</SelectItem>
                  {resourceTypes.map((type) => (
                    <SelectItem key={type} value={type}>
                      {formatResourceType(type)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Date Range</Label>
              <DateRangePicker
                value={dateRange}
                onChange={(range) => { setDateRange(range); setCurrentPage(0); }}
              />
            </div>
            <div className="flex items-end gap-2">
              <Button variant="outline" onClick={resetFilters}>
                Reset
              </Button>
              <Button variant="outline" onClick={loadAuditLogs}>
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {error && (
        <div className="bg-destructive/10 text-destructive p-3 rounded-md">
          {error}
        </div>
      )}

      {/* Results Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Timestamp</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Resource Type</TableHead>
              <TableHead>Resource ID</TableHead>
              <TableHead>IP Address</TableHead>
              <TableHead className="w-[100px]">Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7}>
                  <LoadingState message="Loading audit logs..." />
                </TableCell>
              </TableRow>
            ) : !auditData || auditData.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7}>
                  <EmptyState
                    icon={<FileText className="h-12 w-12" />}
                    title="No audit log entries"
                    description="Audit events will appear here as users interact with the system."
                    action={
                      (actionFilter !== 'all' || resourceTypeFilter !== 'all' || dateRange) && (
                        <Button variant="outline" onClick={resetFilters}>
                          Clear Filters
                        </Button>
                      )
                    }
                  />
                </TableCell>
              </TableRow>
            ) : (
              auditData.items.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="text-muted-foreground whitespace-nowrap">
                    <TimestampTooltip timestamp={entry.created_at}>
                      <span>{formatTimestamp(entry.created_at)}</span>
                    </TimestampTooltip>
                  </TableCell>
                  <TableCell className="font-medium">
                    {entry.user_email || (entry.user_id ? 'Unknown User' : 'System')}
                  </TableCell>
                  <TableCell>{formatAction(entry.action, entry.details ?? undefined)}</TableCell>
                  <TableCell>{formatResourceType(entry.resource_type)}</TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {entry.resource_id ? entry.resource_id.slice(0, 8) + '...' : '-'}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {entry.ip_address || '-'}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleViewDetails(entry)}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {auditData && auditData.total > 0 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {auditData.offset + 1} to{' '}
            {Math.min(auditData.offset + auditData.items.length, auditData.total)} of{' '}
            {auditData.total} entries
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handlePrevPage}
              disabled={currentPage === 0}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {currentPage + 1} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={handleNextPage}
              disabled={currentPage >= totalPages - 1}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Detail Dialog */}
      <Dialog open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Audit Log Details</DialogTitle>
            <DialogDescription>
              Full details for this audit event
            </DialogDescription>
          </DialogHeader>
          {selectedEntry && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Timestamp:</span>
                  <div className="font-medium">
                    <TimestampTooltip timestamp={selectedEntry.created_at}>
                      <span>{formatTimestamp(selectedEntry.created_at)}</span>
                    </TimestampTooltip>
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">User:</span>
                  <p className="font-medium">
                    {selectedEntry.user_email || (selectedEntry.user_id ? 'Unknown User' : 'System')}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">Action:</span>
                  <p className="font-medium">{formatAction(selectedEntry.action, selectedEntry.details ?? undefined)}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Resource Type:</span>
                  <p className="font-medium">{formatResourceType(selectedEntry.resource_type)}</p>
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">Resource ID:</span>
                  <p className="font-mono text-sm">{selectedEntry.resource_id || '-'}</p>
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">Entry ID:</span>
                  <p className="font-mono text-sm">{selectedEntry.id}</p>
                </div>
                {selectedEntry.user_id && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">User ID:</span>
                    <p className="font-mono text-sm">{selectedEntry.user_id}</p>
                  </div>
                )}
                <div className="col-span-2">
                  <span className="text-muted-foreground">IP Address:</span>
                  <p className="font-mono text-sm">
                    {selectedEntry.ip_address || (selectedEntry.details?.ip_address ? String(selectedEntry.details.ip_address) : '-')}
                  </p>
                </div>
              </div>
              {selectedEntry.details && Object.keys(selectedEntry.details).length > 0 && (
                <div>
                  <span className="text-muted-foreground text-sm">Details:</span>
                  <pre className="mt-2 p-4 bg-muted rounded-md text-sm overflow-auto max-h-64">
                    {JSON.stringify(selectedEntry.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
    </TooltipProvider>
  )
}
