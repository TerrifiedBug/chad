import { useEffect, useState, useCallback, useMemo } from 'react'
import { DateRange } from 'react-day-picker'
import {
  auditApi,
  AuditLogEntry,
  AuditLogListResponse,
  AuditExportResult,
} from '@/lib/api'
import { verifyChainLinks } from '@/lib/audit-chain'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  ChevronLeft,
  ChevronRight,
  Download,
  RefreshCw,
  FileText,
  ShieldCheck,
  Shield,
} from 'lucide-react'
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
import { PageHeader } from '@/components/PageHeader'
import { useToast } from '@/components/ui/toast-provider'
import { AuditDetailDrawer } from '@/components/AuditDetailDrawer'

const PAGE_SIZE = 50

// Actions surfaced under the "Deployments" tab. Covers the legacy rule deploy
// verbs plus the dual-control deployment_request.* family (matched by prefix).
const DEPLOYMENT_ACTIONS = new Set([
  'rule.deploy',
  'rule.undeploy',
  'rule.rollback',
  'rule.bulk_deploy',
])

function isDeploymentAction(action: string): boolean {
  return DEPLOYMENT_ACTIONS.has(action) || action.startsWith('deployment_request.')
}

type AuditTab = 'activity' | 'deployments'

export default function AuditLogPage() {
  const { showToast } = useToast()

  const [activeTab, setActiveTab] = useState<AuditTab>('activity')
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

  // Detail drawer
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
    // Friendly labels for dual-control deployment approval events
    if (action.startsWith('deployment_request.')) {
      const deploymentActions: Record<string, string> = {
        'deployment_request.created': 'Submitted deployment request',
        'deployment_request.approved': 'Approved deployment request',
        'deployment_request.rejected': 'Rejected deployment request',
        'deployment_request.cancelled': 'Cancelled deployment request',
        'deployment_request.applied': 'Applied deployment request',
        'deployment_request.failed': 'Deployment request failed',
        'deployment_request.stale': 'Deployment request went stale',
      }
      return deploymentActions[action] || action
    }

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

  // Server returns a single page; the Deployments tab narrows it to the
  // deployment action set client-side (the list API takes one action only).
  const visibleItems = useMemo(() => {
    const items = auditData?.items ?? []
    if (activeTab === 'deployments') {
      return items.filter((entry) => isDeploymentAction(entry.action))
    }
    return items
  }, [auditData, activeTab])

  // Integrity pill: green only when the visible rows' chain links verify.
  const chainVerified = useMemo(
    () => verifyChainLinks(visibleItems),
    [visibleItems]
  )

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

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  // Toast summarising the export, with the cap warning when truncated.
  const reportExport = (result: AuditExportResult, kind: string) => {
    if (result.truncated) {
      showToast(`${kind} exported — capped at 10,000 rows`, 'info')
    } else {
      showToast(`${kind} exported`, 'success')
    }
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

      const result = await auditApi.export(format, filters)
      triggerDownload(result.blob, `audit_logs.${format}`)
      reportExport(result, format.toUpperCase())
    } catch {
      setError('Export failed')
      showToast('Export failed', 'error')
    }
  }

  const handleExportChain = async () => {
    try {
      const result = await auditApi.exportChain()
      triggerDownload(result.blob, 'audit_chain.json')
      reportExport(result, 'Verifiable chain')
    } catch {
      setError('Export failed')
      showToast('Export failed', 'error')
    }
  }

  const integrityPill = chainVerified ? (
    <Badge variant="success-subtle" className="gap-1">
      <ShieldCheck className="h-3 w-3" />
      Tamper-evident
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 text-muted-foreground">
      <Shield className="h-3 w-3" />
      Tamper-evident
    </Badge>
  )

  const exportControl = (
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
        <DropdownMenuItem onClick={handleExportChain}>
          Export verifiable chain (.json)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  // Table body shared by both tabs (rows differ only by the active filter).
  const renderTableBody = () => {
    if (isLoading) {
      return (
        <TableRow>
          <TableCell colSpan={6}>
            <LoadingState message="Loading audit logs..." />
          </TableCell>
        </TableRow>
      )
    }
    if (visibleItems.length === 0) {
      return (
        <TableRow>
          <TableCell colSpan={6}>
            <EmptyState
              icon={<FileText className="h-12 w-12" />}
              title="No audit log entries"
              description={
                activeTab === 'deployments'
                  ? 'Deployment events will appear here as rules are deployed and reviewed.'
                  : 'Audit events will appear here as users interact with the system.'
              }
              action={
                (actionFilter !== 'all' || resourceTypeFilter !== 'all' || dateRange) ? (
                  <Button variant="outline" onClick={resetFilters}>
                    Clear Filters
                  </Button>
                ) : undefined
              }
            />
          </TableCell>
        </TableRow>
      )
    }
    return visibleItems.map((entry) => (
      <TableRow
        key={entry.id}
        className="cursor-pointer"
        onClick={() => handleViewDetails(entry)}
      >
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
      </TableRow>
    ))
  }

  const auditTable = (
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
          </TableRow>
        </TableHeader>
        <TableBody>{renderTableBody()}</TableBody>
      </Table>
    </div>
  )

  return (
    <TooltipProvider>
      <div className="space-y-6">
        <PageHeader
          title={
            <div className="flex items-center gap-3">
              <span>Audit Log</span>
              {integrityPill}
            </div>
          }
          description="Immutable, tamper-evident record of activity across CHAD."
          actions={exportControl}
        />

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

        {/* Tabbed results. The table renders once, driven by activeTab, so the
            inactive panel never keeps a stale (unfiltered) copy mounted. */}
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as AuditTab)}>
          <TabsList>
            <TabsTrigger value="activity">Activity Log</TabsTrigger>
            <TabsTrigger value="deployments">Deployments</TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} forceMount className="space-y-6">
            {auditTable}
          </TabsContent>
        </Tabs>

        {/* Pagination (shared) */}
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

        {/* Detail drawer */}
        <AuditDetailDrawer
          entry={selectedEntry}
          open={isDetailOpen}
          onOpenChange={setIsDetailOpen}
          formatAction={formatAction}
          formatResourceType={formatResourceType}
        />
      </div>
    </TooltipProvider>
  )
}
