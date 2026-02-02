import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { correlationRulesApi, CorrelationRule } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { ChevronDown, ChevronLeft, CircleOff, Clock, Download, Plus, Rocket, RotateCcw, Search, Trash2, X } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { cn } from '@/lib/utils'
import { SEVERITY_COLORS, capitalize } from '@/lib/constants'
import { RelativeTime } from '@/components/RelativeTime'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'
import { Link2 } from 'lucide-react'
import { RulesExportDialog } from '@/components/RulesExportDialog'

// Severity options
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

// Status options
const STATUSES = ['deployed', 'undeployed', 'snoozed', 'needs_redeploy'] as const

// Filter types
type Filters = {
  severity: string[]
  status: string[]
  search: string
}

export default function CorrelationRulesPage() {
  const navigate = useNavigate()
  const { canManageRules, canDeployRules } = useAuth()
  const [rules, setRules] = useState<CorrelationRule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Filters
  const [filters, setFilters] = useState<Filters>({
    severity: [],
    status: [],
    search: '',
  })

  // Selection state
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set())
  const [lastSelectedIndex, setLastSelectedIndex] = useState<number | null>(null)

  // Bulk operation state
  const [isBulkOperating, setIsBulkOperating] = useState(false)

  // Bulk operation change reason state
  const [bulkOperationReason, setBulkOperationReason] = useState('')
  const [showBulkDeployReason, setShowBulkDeployReason] = useState(false)
  const [showBulkUndeployReason, setShowBulkUndeployReason] = useState(false)
  const [showBulkDeleteReason, setShowBulkDeleteReason] = useState(false)
  const [showBulkSnooze, setShowBulkSnooze] = useState(false)
  const [showBulkSnoozeReason, setShowBulkSnoozeReason] = useState(false)
  const [showBulkUnsnoozeReason, setShowBulkUnsnoozeReason] = useState(false)
  const [pendingBulkSnoozeHours, setPendingBulkSnoozeHours] = useState<number | undefined>(undefined)
  const [pendingBulkSnoozeIndefinite, setPendingBulkSnoozeIndefinite] = useState(false)

  // Export dialog state
  const [showExportDialog, setShowExportDialog] = useState(false)

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setIsLoading(true)
    setError('')
    try {
      const response = await correlationRulesApi.list(true)
      setRules(response.correlation_rules)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load correlation rules')
    } finally {
      setIsLoading(false)
    }
  }

  // Filtered rules based on all filters
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Severity filter
      if (filters.severity.length > 0 && !filters.severity.includes(rule.severity)) {
        return false
      }
      // Status filter
      if (filters.status.length > 0) {
        const isSnoozed = rule.snooze_indefinite || (rule.snooze_until && new Date(rule.snooze_until) > new Date())
        let ruleStatus: string
        if (isSnoozed) {
          ruleStatus = 'snoozed'
        } else if (rule.needs_redeploy) {
          ruleStatus = 'needs_redeploy'
        } else if (rule.deployed_at) {
          ruleStatus = 'deployed'
        } else {
          ruleStatus = 'undeployed'
        }
        if (!filters.status.includes(ruleStatus)) {
          return false
        }
      }
      // Search filter
      if (filters.search) {
        const searchLower = filters.search.toLowerCase()
        const matchesName = rule.name.toLowerCase().includes(searchLower)
        const matchesRuleA = (rule.rule_a_title || '').toLowerCase().includes(searchLower)
        const matchesRuleB = (rule.rule_b_title || '').toLowerCase().includes(searchLower)
        if (!matchesName && !matchesRuleA && !matchesRuleB) {
          return false
        }
      }
      return true
    })
  }, [rules, filters])

  // Check if any filters are active
  const hasActiveFilters = filters.severity.length > 0 || filters.status.length > 0 || filters.search !== ''

  // Toggle filter values
  const toggleFilter = (filterKey: 'severity' | 'status', value: string) => {
    setFilters((prev) => {
      const current = prev[filterKey]
      const newValues = current.includes(value)
        ? current.filter((v) => v !== value)
        : [...current, value]
      return { ...prev, [filterKey]: newValues }
    })
  }

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      severity: [],
      status: [],
      search: '',
    })
  }

  // Selection helpers
  const toggleRuleSelection = (ruleId: string, index: number, shiftKey: boolean) => {
    setSelectedRules((prev) => {
      const newSet = new Set(prev)

      if (shiftKey && lastSelectedIndex !== null) {
        // Shift-click: select range
        const start = Math.min(lastSelectedIndex, index)
        const end = Math.max(lastSelectedIndex, index)
        for (let i = start; i <= end; i++) {
          newSet.add(filteredRules[i].id)
        }
      } else {
        // Normal click: toggle single item
        if (newSet.has(ruleId)) {
          newSet.delete(ruleId)
        } else {
          newSet.add(ruleId)
        }
      }

      return newSet
    })
    setLastSelectedIndex(index)
  }

  const selectAll = () => {
    if (selectedRules.size === filteredRules.length) {
      setSelectedRules(new Set())
    } else {
      setSelectedRules(new Set(filteredRules.map((r) => r.id)))
    }
    setLastSelectedIndex(null)
  }

  const clearSelection = () => {
    setSelectedRules(new Set())
    setLastSelectedIndex(null)
  }

  // Compute which bulk actions are applicable based on selected rules' states
  const selectedRulesData = useMemo(() => {
    return rules.filter(r => selectedRules.has(r.id))
  }, [rules, selectedRules])

  const hasDeployedRules = useMemo(() => {
    return selectedRulesData.some(r => r.deployed_at !== null)
  }, [selectedRulesData])

  const hasUndeployedRules = useMemo(() => {
    return selectedRulesData.some(r => r.deployed_at === null)
  }, [selectedRulesData])

  // Check if all selected rules can be deployed (linked rules must be deployed)
  const canBulkDeploy = useMemo(() => {
    if (!hasUndeployedRules) return false // No undeployed rules to deploy
    return selectedRulesData.every(r => r.rule_a_deployed && r.rule_b_deployed)
  }, [selectedRulesData, hasUndeployedRules])

  // Get rules that can't be deployed due to undeployed linked rules
  const rulesWithUndeployedLinked = useMemo(() => {
    return selectedRulesData.filter(r => !r.rule_a_deployed || !r.rule_b_deployed)
  }, [selectedRulesData])

  // Check if any selected rules are snoozed
  const hasSnoozedRules = useMemo(() => {
    return selectedRulesData.some(r =>
      r.snooze_indefinite || (r.snooze_until && new Date(r.snooze_until) > new Date())
    )
  }, [selectedRulesData])

  // Check if any selected rules can be snoozed (deployed but not snoozed)
  const hasSnoozeableRules = useMemo(() => {
    return selectedRulesData.some(r => {
      const isSnoozed = r.snooze_indefinite || (r.snooze_until && new Date(r.snooze_until) > new Date())
      return r.deployed_at && !isSnoozed
    })
  }, [selectedRulesData])

  // Bulk action handler
  const handleBulkAction = (action: 'deploy' | 'undeploy' | 'unsnooze' | 'delete') => {
    if (selectedRules.size === 0) return
    setBulkOperationReason('')

    switch (action) {
      case 'deploy':
        setShowBulkDeployReason(true)
        break
      case 'undeploy':
        setShowBulkUndeployReason(true)
        break
      case 'unsnooze':
        setShowBulkUnsnoozeReason(true)
        break
      case 'delete':
        setShowBulkDeleteReason(true)
        break
    }
  }

  // Execute bulk deploy
  const handleBulkDeployConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkDeployReason(false)
    setIsBulkOperating(true)
    try {
      let successCount = 0
      const failures: string[] = []
      for (const ruleId of selectedRules) {
        try {
          await correlationRulesApi.deploy(ruleId, bulkOperationReason)
          successCount++
        } catch (err) {
          const ruleName = rules.find(r => r.id === ruleId)?.name || ruleId
          const errorMsg = err instanceof Error ? err.message : 'Unknown error'
          failures.push(`${ruleName}: ${errorMsg}`)
        }
      }
      if (failures.length > 0) {
        setError(`${successCount} deployed, ${failures.length} failed:\n${failures.join('\n')}`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk deploy failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Execute bulk undeploy
  const handleBulkUndeployConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkUndeployReason(false)
    setIsBulkOperating(true)
    try {
      let successCount = 0
      let failCount = 0
      for (const ruleId of selectedRules) {
        try {
          await correlationRulesApi.undeploy(ruleId, bulkOperationReason)
          successCount++
        } catch {
          failCount++
        }
      }
      if (failCount > 0) {
        setError(`${successCount} undeployed, ${failCount} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk undeploy failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Execute bulk delete
  const handleBulkDeleteConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkDeleteReason(false)
    setIsBulkOperating(true)
    try {
      let successCount = 0
      let failCount = 0
      for (const ruleId of selectedRules) {
        try {
          await correlationRulesApi.delete(ruleId)
          successCount++
        } catch {
          failCount++
        }
      }
      if (failCount > 0) {
        setError(`${successCount} deleted, ${failCount} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk delete failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Bulk snooze handler - shows snooze duration dropdown
  const handleBulkSnooze = (hours?: number, indefinite?: boolean) => {
    if (selectedRules.size === 0) return
    setShowBulkSnooze(false)
    setPendingBulkSnoozeHours(hours)
    setPendingBulkSnoozeIndefinite(indefinite ?? false)
    setBulkOperationReason('')
    setShowBulkSnoozeReason(true)
  }

  // Execute bulk snooze after change reason provided
  const handleBulkSnoozeConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkSnoozeReason(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await correlationRulesApi.bulkSnooze(
        ruleIds,
        pendingBulkSnoozeHours ?? null,
        pendingBulkSnoozeIndefinite,
        bulkOperationReason
      )
      if (result.failed.length > 0) {
        setError(`${result.success.length} snoozed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk snooze failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Execute bulk unsnooze after change reason provided
  const handleBulkUnsnoozeConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkUnsnoozeReason(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await correlationRulesApi.bulkUnsnooze(ruleIds, bulkOperationReason)
      if (result.failed.length > 0) {
        setError(`${result.success.length} unsnoozed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk unsnooze failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  const getStatusBadge = (rule: CorrelationRule) => {
    // Check if rule is snoozed
    const isSnoozed = rule.snooze_indefinite || (rule.snooze_until && new Date(rule.snooze_until) > new Date())
    if (isSnoozed) {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-600 text-white">
          Snoozed
        </span>
      )
    }
    if (rule.deployed_at) {
      return (
        <div className="flex items-center gap-1.5">
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-600 text-white">
            Deployed
          </span>
          {rule.needs_redeploy && (
            <span className="px-2 py-0.5 rounded text-xs font-medium border border-yellow-500 text-yellow-600">
              Needs Redeploy
            </span>
          )}
        </div>
      )
    }
    return (
      <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-500 text-white">
        Undeployed
      </span>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/settings')}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">Correlation Rules</h1>
            <p className="text-sm text-muted-foreground">
              Detect patterns across multiple rules
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowExportDialog(true)}>
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
          {canManageRules() && (
            <Button onClick={() => navigate('/correlation/new')}>
              <Plus className="h-4 w-4 mr-2" />
              Create Correlation Rule
            </Button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        {/* Search */}
        <div className="relative w-64">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search rules..."
            value={filters.search}
            onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
            className="pl-9"
          />
        </div>

        {/* Severity filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2">
              Severity
              {filters.severity.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                  {filters.severity.length}
                </Badge>
              )}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Severity Levels</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {SEVERITIES.map((severity) => (
              <DropdownMenuCheckboxItem
                key={severity}
                checked={filters.severity.includes(severity)}
                onCheckedChange={() => toggleFilter('severity', severity)}
                onSelect={(e) => e.preventDefault()}
              >
                <span
                  className={cn(
                    'mr-2 inline-block w-2 h-2 rounded-full',
                    severity === 'critical' && 'bg-red-500',
                    severity === 'high' && 'bg-orange-500',
                    severity === 'medium' && 'bg-yellow-500',
                    severity === 'low' && 'bg-blue-500',
                    severity === 'informational' && 'bg-gray-500'
                  )}
                />
                {capitalize(severity)}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Status filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2">
              Status
              {filters.status.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                  {filters.status.length}
                </Badge>
              )}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Rule Status</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {STATUSES.map((status) => (
              <DropdownMenuCheckboxItem
                key={status}
                checked={filters.status.includes(status)}
                onCheckedChange={() => toggleFilter('status', status)}
                onSelect={(e) => e.preventDefault()}
              >
                {status === 'needs_redeploy' ? 'Needs Redeploy' : capitalize(status)}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Clear filters button */}
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            <X className="h-4 w-4 mr-1" />
            Clear filters
          </Button>
        )}
      </div>

      {/* Active filters display */}
      {hasActiveFilters && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-sm text-muted-foreground">Active filters:</span>
          {filters.search && (
            <Badge variant="secondary" className="gap-1">
              Search: {filters.search}
              <button
                type="button"
                onClick={() => setFilters((prev) => ({ ...prev, search: '' }))}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {filters.severity.map((sev) => (
            <Badge key={sev} variant="secondary" className="gap-1">
              {capitalize(sev)}
              <button
                type="button"
                onClick={() => toggleFilter('severity', sev)}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
          {filters.status.map((status) => (
            <Badge key={status} variant="secondary" className="gap-1">
              {status === 'needs_redeploy' ? 'Needs Redeploy' : capitalize(status)}
              <button
                type="button"
                onClick={() => toggleFilter('status', status)}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <LoadingState message="Loading correlation rules..." />
      ) : filteredRules.length === 0 ? (
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title={hasActiveFilters ? 'No correlation rules match your filters' : 'No correlation rules found'}
          description={hasActiveFilters
            ? 'Try adjusting your filters to see more results.'
            : 'Create a correlation rule to detect patterns across multiple rules.'}
          action={!hasActiveFilters && canManageRules() ? (
            <Button onClick={() => navigate('/correlation/new')}>
              <Plus className="h-4 w-4 mr-2" />
              Create Correlation Rule
            </Button>
          ) : undefined}
        />
      ) : (
        <TooltipProvider>
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">
                  <Checkbox
                    checked={selectedRules.size === filteredRules.length && filteredRules.length > 0}
                    onCheckedChange={selectAll}
                    aria-label="Select all rules"
                  />
                </TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Rules</TableHead>
                <TableHead>Entity Field</TableHead>
                <TableHead>Time Window</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Updated By</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRules.map((rule, index) => (
                  <TableRow
                    key={rule.id}
                    className={cn(
                      'cursor-pointer hover:bg-muted/50',
                      selectedRules.has(rule.id) && 'bg-muted/50'
                    )}
                    onClick={() => navigate(`/correlation/${rule.id}`)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedRules.has(rule.id)}
                        onClick={(e: React.MouseEvent) => {
                          e.stopPropagation()
                          toggleRuleSelection(rule.id, index, e.shiftKey)
                        }}
                        aria-label={`Select rule: ${rule.name}`}
                      />
                    </TableCell>
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <div className="text-xs">
                        <div className="truncate max-w-[200px]">{rule.rule_a_title || rule.rule_a_id}</div>
                        <div className="text-muted-foreground">and</div>
                        <div className="truncate max-w-[200px]">{rule.rule_b_title || rule.rule_b_id}</div>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{rule.entity_field}</TableCell>
                    <TableCell>{rule.time_window_minutes} min</TableCell>
                    <TableCell>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${SEVERITY_COLORS[rule.severity]}`}>
                        {capitalize(rule.severity)}
                      </span>
                    </TableCell>
                    <TableCell>
                      {getStatusBadge(rule)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <RelativeTime date={rule.updated_at} />
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {rule.last_edited_by || '-'}
                    </TableCell>
                  </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        </TooltipProvider>
      )}

      {/* Bulk Action Bar */}
      {selectedRules.size > 0 && (
        <TooltipProvider>
          <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 z-50">
            <span className="text-sm font-medium">
              {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''} selected
            </span>
            <div className="flex gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleBulkAction('deploy')}
                      disabled={isBulkOperating || !canDeployRules() || !canBulkDeploy}
                    >
                      <Rocket className="mr-2 h-4 w-4" /> Deploy
                    </Button>
                  </span>
                </TooltipTrigger>
                {!hasUndeployedRules ? (
                  <TooltipContent>All selected rules are already deployed</TooltipContent>
                ) : rulesWithUndeployedLinked.length > 0 ? (
                  <TooltipContent>
                    <p>Cannot deploy: Some rules have undeployed linked rules</p>
                    <ul className="list-disc ml-4 mt-1">
                      {rulesWithUndeployedLinked.slice(0, 3).map(r => (
                        <li key={r.id} className="text-xs">{r.name}</li>
                      ))}
                      {rulesWithUndeployedLinked.length > 3 && (
                        <li className="text-xs">...and {rulesWithUndeployedLinked.length - 3} more</li>
                      )}
                    </ul>
                  </TooltipContent>
                ) : null}
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleBulkAction('undeploy')}
                      disabled={isBulkOperating || !canDeployRules() || !hasDeployedRules}
                    >
                      <CircleOff className="mr-2 h-4 w-4" /> Undeploy
                    </Button>
                  </span>
                </TooltipTrigger>
                {!hasDeployedRules && (
                  <TooltipContent>All selected rules are already undeployed</TooltipContent>
                )}
              </Tooltip>

              <Tooltip open={!hasSnoozeableRules ? undefined : false}>
                <TooltipTrigger asChild>
                  <DropdownMenu open={showBulkSnooze} onOpenChange={setShowBulkSnooze}>
                    <DropdownMenuTrigger asChild>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={isBulkOperating || !hasSnoozeableRules || !canDeployRules()}
                      >
                        <Clock className="mr-2 h-4 w-4" /> Snooze
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent className="z-[60]">
                      <DropdownMenuLabel>Snooze Duration</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => handleBulkSnooze(1)}>1 hour</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(4)}>4 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(24)}>24 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(168)}>1 week</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(undefined, true)}>Indefinitely</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TooltipTrigger>
                {!hasSnoozeableRules && (
                  <TooltipContent>No deployed rules to snooze</TooltipContent>
                )}
              </Tooltip>

              <Button
                size="sm"
                variant="outline"
                onClick={() => handleBulkAction('unsnooze')}
                disabled={isBulkOperating || !hasSnoozedRules || !canDeployRules()}
              >
                <RotateCcw className="mr-2 h-4 w-4" /> Unsnooze
              </Button>

              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => handleBulkAction('delete')}
                      disabled={isBulkOperating || !canManageRules()}
                    >
                      <Trash2 className="mr-2 h-4 w-4" /> Delete
                    </Button>
                  </span>
                </TooltipTrigger>
                {!canManageRules() && (
                  <TooltipContent>You don't have permission to delete rules</TooltipContent>
                )}
              </Tooltip>
            </div>
            <Button size="sm" variant="ghost" onClick={clearSelection}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </TooltipProvider>
      )}

      {/* Bulk Deploy Reason Dialog */}
      <Dialog open={showBulkDeployReason} onOpenChange={setShowBulkDeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy Correlation Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're deploying {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-deploy-reason">Reason *</Label>
              <Textarea
                id="bulk-deploy-reason"
                placeholder="e.g., Ready for production, completed testing..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkDeployReason(false); setBulkOperationReason('') }}>
              Cancel
            </Button>
            <Button onClick={handleBulkDeployConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Deploying...' : 'Deploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Undeploy Reason Dialog */}
      <Dialog open={showBulkUndeployReason} onOpenChange={setShowBulkUndeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Undeploy Correlation Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're undeploying {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-undeploy-reason">Reason *</Label>
              <Textarea
                id="bulk-undeploy-reason"
                placeholder="e.g., Rules causing issues, needs revision..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkUndeployReason(false); setBulkOperationReason('') }}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleBulkUndeployConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Undeploying...' : 'Undeploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Snooze Reason Dialog */}
      <Dialog open={showBulkSnoozeReason} onOpenChange={setShowBulkSnoozeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Snooze Correlation Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're snoozing {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="text-sm text-muted-foreground">
              Duration: {pendingBulkSnoozeIndefinite ? 'Indefinitely' : `${pendingBulkSnoozeHours} hour${pendingBulkSnoozeHours !== 1 ? 's' : ''}`}
            </div>
            <div className="space-y-2">
              <Label htmlFor="bulk-snooze-reason">Reason *</Label>
              <Textarea
                id="bulk-snooze-reason"
                placeholder="e.g., Investigating false positives, scheduled maintenance..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkSnoozeReason(false); setBulkOperationReason('') }}>
              Cancel
            </Button>
            <Button onClick={handleBulkSnoozeConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Snoozing...' : 'Snooze'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Unsnooze Reason Dialog */}
      <Dialog open={showBulkUnsnoozeReason} onOpenChange={setShowBulkUnsnoozeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unsnooze Correlation Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're unsnoozing {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-unsnooze-reason">Reason *</Label>
              <Textarea
                id="bulk-unsnooze-reason"
                placeholder="e.g., Issue resolved, ready to re-enable..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkUnsnoozeReason(false); setBulkOperationReason('') }}>
              Cancel
            </Button>
            <Button onClick={handleBulkUnsnoozeConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Unsnoozing...' : 'Unsnooze'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Delete Reason Dialog */}
      <Dialog open={showBulkDeleteReason} onOpenChange={setShowBulkDeleteReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Correlation Rules</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-delete-reason">Reason *</Label>
              <Textarea
                id="bulk-delete-reason"
                placeholder="e.g., Rules no longer needed, cleanup..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkDeleteReason(false); setBulkOperationReason('') }}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleBulkDeleteConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Export Report Dialog */}
      <RulesExportDialog
        open={showExportDialog}
        onOpenChange={setShowExportDialog}
        onError={(msg) => setError(msg)}
      />
    </div>
  )
}
