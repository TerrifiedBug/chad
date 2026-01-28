import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { rulesApi, indexPatternsApi, Rule, IndexPattern, RuleStatus, RuleSource, DeploymentEligibilityResult } from '@/lib/api'
import yaml from 'js-yaml'
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
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ChevronDown, Clock, FileCode, FileText, FolderTree, Plus, RotateCcw, Rocket, Search, Table as TableIcon, Trash2, X } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { RulesTreeView } from '@/components/RulesTreeView'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

// Severity options
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

// Rule status options
const RULE_STATUSES: RuleStatus[] = ['deployed', 'undeployed', 'snoozed']

// Filter types
type Filters = {
  indexPattern: string[]
  severity: string[]
  status: string[]
  source: RuleSource | 'all'
  search: string
}

export default function RulesPage() {
  const navigate = useNavigate()
  const { canManageRules, canDeployRules } = useAuth()
  const [rules, setRules] = useState<Rule[]>([])
  const [indexPatterns, setIndexPatterns] = useState<Record<string, IndexPattern>>({})
  const [indexPatternsList, setIndexPatternsList] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [filters, setFilters] = useState<Filters>({
    indexPattern: [],
    severity: [],
    status: [],
    source: 'all',
    search: '',
  })
  const [viewMode, setViewMode] = useState<'tree' | 'table'>(() => {
    return (localStorage.getItem('rules-view-mode') as 'tree' | 'table') || 'table'
  })

  // Selection state
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set())
  const [lastSelectedIndex, setLastSelectedIndex] = useState<number | null>(null)

  // Bulk operation state
  const [isBulkOperating, setIsBulkOperating] = useState(false)
  const [showBulkSnooze, setShowBulkSnooze] = useState(false)

  // Bulk operation change reason state
  const [bulkOperationReason, setBulkOperationReason] = useState('')
  const [showBulkDeployReason, setShowBulkDeployReason] = useState(false)
  const [showBulkUndeployReason, setShowBulkUndeployReason] = useState(false)
  const [showBulkSnoozeReason, setShowBulkSnoozeReason] = useState(false)
  const [showBulkUnsnoozeReason, setShowBulkUnsnoozeReason] = useState(false)
  const [showBulkDeleteReason, setShowBulkDeleteReason] = useState(false)
  const [pendingBulkSnoozeHours, setPendingBulkSnoozeHours] = useState<number | undefined>(undefined)
  const [pendingBulkSnoozeIndefinite, setPendingBulkSnoozeIndefinite] = useState(false)
  const [bulkLinkedCorrelations, setBulkLinkedCorrelations] = useState<{ id: string; name: string; deployed: boolean }[]>([])

  // Deployment eligibility state
  const [deploymentEligibility, setDeploymentEligibility] = useState<DeploymentEligibilityResult | null>(null)
  const [isCheckingEligibility, setIsCheckingEligibility] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  // Persist view mode changes
  useEffect(() => {
    localStorage.setItem('rules-view-mode', viewMode)
  }, [viewMode])

  // Check deployment eligibility when selection changes
  useEffect(() => {
    if (selectedRules.size === 0) {
      setDeploymentEligibility(null)
      return
    }

    const checkEligibility = async () => {
      setIsCheckingEligibility(true)
      try {
        const result = await rulesApi.checkDeploymentEligibility(Array.from(selectedRules))
        setDeploymentEligibility(result)
      } catch (err) {
        console.error('Failed to check deployment eligibility', err)
        setDeploymentEligibility(null)
      } finally {
        setIsCheckingEligibility(false)
      }
    }

    checkEligibility()
  }, [selectedRules])

  // Compute which bulk actions are applicable based on selected rules' states
  const selectedRulesData = useMemo(() => {
    return rules.filter(r => selectedRules.has(r.id))
  }, [rules, selectedRules])

  const hasDeployedRules = useMemo(() => {
    return selectedRulesData.some(r => r.status === 'deployed')
  }, [selectedRulesData])

  const hasUndeployedRules = useMemo(() => {
    return selectedRulesData.some(r => r.status === 'undeployed')
  }, [selectedRulesData])

  const allDeployed = useMemo(() => {
    return selectedRulesData.length > 0 && selectedRulesData.every(r => r.status === 'deployed')
  }, [selectedRulesData])

  const hasSnoozedRules = useMemo(() => {
    return selectedRulesData.some(r => r.status === 'snoozed')
  }, [selectedRulesData])

  const loadData = async () => {
    setIsLoading(true)
    setError('')
    try {
      const [rulesData, patternsData] = await Promise.all([
        rulesApi.list(),
        indexPatternsApi.list(),
      ])
      setRules(rulesData)
      // Create lookup map for index patterns
      const patternsMap: Record<string, IndexPattern> = {}
      patternsData.forEach((p) => {
        patternsMap[p.id] = p
      })
      setIndexPatterns(patternsMap)
      setIndexPatternsList(patternsData)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules')
    } finally {
      setIsLoading(false)
    }
  }

  // Memoized filtered rules based on all filters
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Index pattern filter
      if (filters.indexPattern.length > 0 && !filters.indexPattern.includes(rule.index_pattern_id)) {
        return false
      }
      // Severity filter
      if (filters.severity.length > 0 && !filters.severity.includes(rule.severity)) {
        return false
      }
      // Status filter
      if (filters.status.length > 0 && !filters.status.includes(rule.status)) {
        return false
      }
      // Source filter
      if (filters.source !== 'all' && rule.source !== filters.source) {
        return false
      }
      // Search filter - searches title, ATT&CK IDs, and type
      if (filters.search && filters.search.trim()) {
        const searchLower = filters.search.trim().toLowerCase()
        const matchesTitle = rule.title?.toLowerCase().includes(searchLower)
        const matchesType = rule.source?.toLowerCase().includes(searchLower)

        // Search in tags (which include ATT&CK IDs like "attack.t1566")
        // Tags are stored in YAML content
        let matchesAttackIds = false
        try {
          const parsed = yaml.load(rule.yaml_content) as Record<string, unknown> | null
          if (parsed && typeof parsed === 'object' && 'tags' in parsed && Array.isArray(parsed.tags)) {
            const tags = parsed.tags as string[]
            matchesAttackIds = tags.some((tag: string) =>
              tag.toLowerCase().includes(searchLower)
            )
          }
        } catch (error) {
          // If YAML parsing fails, just skip tag search
          console.warn('Failed to parse YAML for rule search:', error)
        }

        if (!matchesTitle && !matchesType && !matchesAttackIds) {
          return false
        }
      }
      return true
    })
  }, [rules, filters])

  // Check if any filters are active
  const hasActiveFilters = useMemo(() => {
    return (
      filters.indexPattern.length > 0 ||
      filters.severity.length > 0 ||
      filters.status.length > 0 ||
      filters.source !== 'all' ||
      filters.search !== ''
    )
  }, [filters])

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      indexPattern: [],
      severity: [],
      status: [],
      source: 'all',
      search: '',
    })
  }

  // Toggle multi-select filter value
  const toggleFilter = <K extends keyof Filters>(
    key: K,
    value: Filters[K] extends string[] ? string : never
  ) => {
    setFilters((prev) => {
      const currentValues = prev[key] as string[]
      const newValues = currentValues.includes(value)
        ? currentValues.filter((v) => v !== value)
        : [...currentValues, value]
      return { ...prev, [key]: newValues }
    })
  }

  // Toggle single selection with shift+click support
  const toggleRuleSelection = (ruleId: string, index: number, shiftKey: boolean) => {
    setSelectedRules((prev) => {
      const newSet = new Set(prev)

      if (shiftKey && lastSelectedIndex !== null) {
        // Shift+click: select range
        const start = Math.min(lastSelectedIndex, index)
        const end = Math.max(lastSelectedIndex, index)
        for (let i = start; i <= end; i++) {
          if (filteredRules[i]) {
            newSet.add(filteredRules[i].id)
          }
        }
      } else {
        // Regular click: toggle single
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

  // Select all visible rules
  const selectAll = () => {
    if (selectedRules.size === filteredRules.length && filteredRules.length > 0) {
      setSelectedRules(new Set())
    } else {
      setSelectedRules(new Set(filteredRules.map((r) => r.id)))
    }
  }

  // Clear selection
  const clearSelection = () => {
    setSelectedRules(new Set())
    setLastSelectedIndex(null)
  }

  // Bulk action handler - shows change reason dialog
  const handleBulkAction = async (action: 'deploy' | 'undeploy' | 'unsnooze' | 'delete') => {
    if (selectedRules.size === 0) return
    setBulkOperationReason('')

    switch (action) {
      case 'deploy':
        setShowBulkDeployReason(true)
        break
      case 'undeploy':
        // Fetch linked correlations for all selected rules
        try {
          const allCorrelations: { id: string; name: string; deployed: boolean }[] = []
          const seenIds = new Set<string>()
          for (const ruleId of selectedRules) {
            const response = await rulesApi.getLinkedCorrelations(ruleId, false)
            for (const corr of response.correlations) {
              if (!seenIds.has(corr.id)) {
                seenIds.add(corr.id)
                allCorrelations.push(corr)
              }
            }
          }
          setBulkLinkedCorrelations(allCorrelations)
        } catch {
          setBulkLinkedCorrelations([])
        }
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

  // Execute bulk deploy after change reason provided
  const handleBulkDeployConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkDeployReason(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await rulesApi.bulkDeploy(ruleIds, bulkOperationReason)
      if (result.failed.length > 0) {
        setError(`${result.success.length} deployed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk deploy failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Execute bulk undeploy after change reason provided
  const handleBulkUndeployConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkUndeployReason(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await rulesApi.bulkUndeploy(ruleIds, bulkOperationReason)
      if (result.failed.length > 0) {
        setError(`${result.success.length} undeployed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      setBulkLinkedCorrelations([])
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk undeploy failed')
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
      const result = await rulesApi.bulkUnsnooze(ruleIds, bulkOperationReason)
      if (result.failed.length > 0) {
        setError(`${result.success.length} unsnoozed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk unsnooze failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Bulk snooze handler - shows change reason dialog
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
      const result = await rulesApi.bulkSnooze(ruleIds, bulkOperationReason, pendingBulkSnoozeHours, pendingBulkSnoozeIndefinite)
      if (result.failed.length > 0) {
        setError(`${result.success.length} snoozed, ${result.failed.length} failed`)
      }
      clearSelection()
      setBulkOperationReason('')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk snooze failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Handler for confirmed bulk delete
  const handleBulkDeleteConfirm = async () => {
    if (selectedRules.size === 0 || !bulkOperationReason.trim()) return
    setShowBulkDeleteReason(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await rulesApi.bulkDelete(ruleIds, bulkOperationReason)

      if (result.failed.length > 0) {
        setError(`${result.success.length} deleted, ${result.failed.length} failed`)
      }

      clearSelection()
      setBulkOperationReason('')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk delete failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Handler for bulk export
  const handleBulkExport = async () => {
    if (selectedRules.size === 0) return

    const ruleIds = Array.from(selectedRules)
    // Create a form and submit it to trigger the download
    const form = document.createElement('form')
    form.method = 'POST'
    form.action = '/api/export/rules/bulk'
    form.style.display = 'none'

    // Add the rule_ids as a JSON body - need to use fetch instead for JSON
    try {
      const token = localStorage.getItem('chad-token')
      const response = await fetch('/api/export/rules/bulk', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ rule_ids: ruleIds }),
      })

      if (!response.ok) {
        throw new Error('Export failed')
      }

      // Get the blob and trigger download
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `chad-rules-${new Date().toISOString().slice(0, 10)}.zip`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Rules</h1>
        <Button onClick={() => navigate('/rules/new')} disabled={!canManageRules()}>
          <Plus className="h-4 w-4 mr-2" />
          Create Rule
        </Button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap gap-3 items-center">
        {/* Search input */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search title, type, or ATT&CK ID..."
            value={filters.search}
            onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
            className="pl-10"
            aria-label="Search rules"
          />
        </div>

        {/* Index Pattern multi-select */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2">
              Index Pattern
              {filters.indexPattern.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                  {filters.indexPattern.length}
                </Badge>
              )}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56">
            <DropdownMenuLabel>Index Patterns</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {indexPatternsList.length === 0 ? (
              <div className="px-2 py-1.5 text-sm text-muted-foreground">
                No index patterns
              </div>
            ) : (
              indexPatternsList.map((pattern) => (
                <DropdownMenuCheckboxItem
                  key={pattern.id}
                  checked={filters.indexPattern.includes(pattern.id)}
                  onCheckedChange={() => toggleFilter('indexPattern', pattern.id)}
                  onSelect={(e) => e.preventDefault()}
                >
                  {pattern.name}
                </DropdownMenuCheckboxItem>
              ))
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Severity multi-select */}
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

        {/* Status multi-select */}
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
            {RULE_STATUSES.map((status) => (
              <DropdownMenuCheckboxItem
                key={status}
                checked={filters.status.includes(status)}
                onCheckedChange={() => toggleFilter('status', status)}
                onSelect={(e) => e.preventDefault()}
              >
                {capitalize(status)}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Source dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2">
              Source
              {filters.source !== 'all' && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                  1
                </Badge>
              )}
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Rule Source</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuCheckboxItem
              checked={filters.source === 'all'}
              onCheckedChange={() => setFilters((prev) => ({ ...prev, source: 'all' }))}
              onSelect={(e) => e.preventDefault()}
            >
              All Sources
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={filters.source === 'user'}
              onCheckedChange={() => setFilters((prev) => ({ ...prev, source: 'user' }))}
              onSelect={(e) => e.preventDefault()}
            >
              User-created
            </DropdownMenuCheckboxItem>
            <DropdownMenuCheckboxItem
              checked={filters.source === 'sigmahq'}
              onCheckedChange={() => setFilters((prev) => ({ ...prev, source: 'sigmahq' }))}
              onSelect={(e) => e.preventDefault()}
            >
              SigmaHQ
            </DropdownMenuCheckboxItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* View mode toggle */}
        <div className="flex items-center gap-1 ml-auto">
          <Button
            variant={viewMode === 'tree' ? 'default' : 'outline'}
            size="icon"
            onClick={() => setViewMode('tree')}
            title="Tree view"
            aria-label="Tree view"
            aria-pressed={viewMode === 'tree'}
          >
            <FolderTree className="h-4 w-4" />
          </Button>
          <Button
            variant={viewMode === 'table' ? 'default' : 'outline'}
            size="icon"
            onClick={() => setViewMode('table')}
            title="Table view"
            aria-label="Table view"
            aria-pressed={viewMode === 'table'}
          >
            <TableIcon className="h-4 w-4" />
          </Button>
        </div>
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
                aria-label={`Remove search filter: ${filters.search}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          {filters.indexPattern.map((id) => (
            <Badge key={id} variant="secondary" className="gap-1">
              {indexPatterns[id]?.name || id}
              <button
                type="button"
                onClick={() => toggleFilter('indexPattern', id)}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
                aria-label={`Remove index pattern filter: ${indexPatterns[id]?.name || id}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
          {filters.severity.map((sev) => (
            <Badge key={sev} variant="secondary" className="gap-1">
              {capitalize(sev)}
              <button
                type="button"
                onClick={() => toggleFilter('severity', sev)}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
                aria-label={`Remove severity filter: ${capitalize(sev)}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
          {filters.status.map((status) => (
            <Badge key={status} variant="secondary" className="gap-1">
              {capitalize(status)}
              <button
                type="button"
                onClick={() => toggleFilter('status', status)}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
                aria-label={`Remove status filter: ${capitalize(status)}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
          {filters.source !== 'all' && (
            <Badge variant="secondary" className="gap-1">
              {filters.source === 'user' ? 'User-created' : 'SigmaHQ'}
              <button
                type="button"
                onClick={() => setFilters((prev) => ({ ...prev, source: 'all' }))}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
                aria-label={`Remove source filter: ${filters.source === 'user' ? 'User-created' : 'SigmaHQ'}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          )}
          <Button variant="ghost" size="sm" onClick={clearFilters} className="h-6 px-2 text-xs">
            Clear all
          </Button>
        </div>
      )}

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : filteredRules.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          {hasActiveFilters
            ? 'No rules match your filters'
            : 'No rules found. Create your first rule!'}
        </div>
      ) : viewMode === 'table' ? (
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
                  <TableHead>Title</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Index Pattern</TableHead>
                  <TableHead>Last Edited By</TableHead>
                  <TableHead>Updated</TableHead>
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
                    onClick={() => navigate(`/rules/${rule.id}`)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedRules.has(rule.id)}
                        onClick={(e: React.MouseEvent) => {
                          e.stopPropagation()
                          toggleRuleSelection(rule.id, index, e.shiftKey)
                        }}
                        aria-label={`Select rule: ${rule.title}`}
                      />
                    </TableCell>
                    <TableCell className="font-medium">{rule.title}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        {rule.source === 'sigmahq' ? (
                          <>
                            <FileCode className="h-4 w-4 text-blue-500" />
                            <span className="text-xs text-muted-foreground">SigmaHQ</span>
                          </>
                        ) : (
                          <>
                            <FileText className="h-4 w-4 text-muted-foreground" />
                            <span className="text-xs text-muted-foreground">User</span>
                          </>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          severityColors[rule.severity] || 'bg-gray-500 text-white'
                        }`}
                      >
                        {capitalize(rule.severity)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium inline-block w-fit ${
                            rule.status === 'deployed'
                              ? 'bg-green-600 text-white'
                              : rule.status === 'snoozed'
                              ? 'bg-yellow-500 text-white'
                              : 'bg-gray-500 text-white'
                          }`}
                        >
                          {rule.status === 'deployed'
                            ? 'Deployed'
                            : rule.status === 'snoozed'
                            ? (rule.snooze_indefinite ? 'Snoozed (Indefinite)' : 'Snoozed')
                            : 'Undeployed'}
                        </span>
                        {rule.needs_redeploy && (
                          <span className="px-2 py-0.5 rounded text-xs font-medium border border-orange-500 text-orange-600">
                            Needs Redeploy
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {indexPatterns[rule.index_pattern_id]?.name || 'Unknown'}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {rule.last_edited_by || '-'}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <RelativeTime date={rule.updated_at} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </TooltipProvider>
      ) : (
        <RulesTreeView
          rules={filteredRules}
          indexPatterns={indexPatterns}
          onRuleClick={(rule) => navigate(`/rules/${rule.id}`)}
          selectedRules={selectedRules}
          onRuleSelect={toggleRuleSelection}
        />
      )}

      {/* Bulk Action Bar - shown when items are selected */}
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
                      disabled={isBulkOperating || isCheckingEligibility || !canDeployRules() || hasDeployedRules || (deploymentEligibility?.ineligible?.length ?? 0) > 0}
                    >
                      <Rocket className="mr-2 h-4 w-4" /> Deploy
                    </Button>
                  </span>
                </TooltipTrigger>
                {hasDeployedRules && (
                  <TooltipContent>
                    Cannot bulk deploy: Some selected rules are already deployed
                  </TooltipContent>
                )}
                {(deploymentEligibility?.ineligible?.length ?? 0) > 0 && !hasDeployedRules && (
                  <TooltipContent>
                    {deploymentEligibility!.ineligible.length} of {selectedRules.size} rules have unmapped fields
                  </TooltipContent>
                )}
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleBulkAction('undeploy')}
                      disabled={isBulkOperating || !allDeployed || !canDeployRules()}
                    >
                      <X className="mr-2 h-4 w-4" /> Undeploy
                    </Button>
                  </span>
                </TooltipTrigger>
                {!allDeployed && selectedRulesData.length > 0 && (
                  <TooltipContent>
                    Cannot bulk undeploy: All selected rules must be deployed
                  </TooltipContent>
                )}
              </Tooltip>
              <Tooltip open={hasUndeployedRules ? undefined : false}>
                <TooltipTrigger asChild>
                  <DropdownMenu open={showBulkSnooze} onOpenChange={setShowBulkSnooze}>
                    <DropdownMenuTrigger asChild>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={isBulkOperating || hasUndeployedRules || !canDeployRules()}
                      >
                        <Clock className="mr-2 h-4 w-4" /> Snooze
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent className="z-[60]">
                      <DropdownMenuLabel>Snooze Duration</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => handleBulkSnooze(1)}>1 hour</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(4)}>4 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(8)}>8 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(24)}>24 hours</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(168)}>1 week</DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkSnooze(undefined, true)}>Indefinitely</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TooltipTrigger>
                {hasUndeployedRules && (
                  <TooltipContent>
                    Cannot bulk snooze: Some selected rules are not deployed
                  </TooltipContent>
                )}
              </Tooltip>
              <Button size="sm" variant="outline" onClick={() => handleBulkAction('unsnooze')} disabled={isBulkOperating || !hasSnoozedRules || !canDeployRules()}>
                <RotateCcw className="mr-2 h-4 w-4" /> Unsnooze
              </Button>
              <Button size="sm" variant="destructive" onClick={() => handleBulkAction('delete')} disabled={isBulkOperating || !canManageRules()}>
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
              <Button size="sm" variant="outline" onClick={handleBulkExport} disabled={isBulkOperating}>
                Export
              </Button>
            </div>
            <Button size="sm" variant="ghost" onClick={clearSelection}>
              Cancel
            </Button>
          </div>
        </TooltipProvider>
      )}

      {/* Bulk Deploy Reason Dialog */}
      <Dialog open={showBulkDeployReason} onOpenChange={setShowBulkDeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're deploying {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-deploy-reason">Reason *</Label>
              <Textarea
                id="bulk-deploy-reason"
                placeholder="e.g., Deploying new detection rules for incident response..."
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
            <DialogTitle>Undeploy Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're undeploying {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {/* Show warning if there are deployed correlation rules */}
            {bulkLinkedCorrelations.some(c => c.deployed) && (
              <div className="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-md p-3">
                <p className="text-sm font-medium text-amber-800 dark:text-amber-200 mb-2">
                  Warning: Selected rules are linked to correlation rules
                </p>
                <p className="text-xs text-amber-700 dark:text-amber-300 mb-2">
                  Undeploying these rules will also undeploy any deployed correlation rules that depend on them.
                </p>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {bulkLinkedCorrelations.map((corr) => (
                    <div key={corr.id} className="flex items-center justify-between py-1 px-2 bg-white dark:bg-gray-900 rounded text-sm">
                      <span>{corr.name}</span>
                      <Badge variant={corr.deployed ? 'default' : 'secondary'} className="text-xs">
                        {corr.deployed ? 'Deployed' : 'Undeployed'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="bulk-undeploy-reason">Reason *</Label>
              <Textarea
                id="bulk-undeploy-reason"
                placeholder="e.g., Rules causing too many false positives, needs tuning..."
                value={bulkOperationReason}
                onChange={(e) => setBulkOperationReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowBulkUndeployReason(false); setBulkOperationReason(''); setBulkLinkedCorrelations([]) }}>
              Cancel
            </Button>
            <Button onClick={handleBulkUndeployConfirm} disabled={!bulkOperationReason.trim() || isBulkOperating}>
              {isBulkOperating ? 'Undeploying...' : 'Undeploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Snooze Reason Dialog */}
      <Dialog open={showBulkSnoozeReason} onOpenChange={setShowBulkSnoozeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Snooze Rules</DialogTitle>
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
            <DialogTitle>Unsnooze Rules</DialogTitle>
            <DialogDescription>
              Please explain why you're unsnoozing {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-unsnooze-reason">Reason *</Label>
              <Textarea
                id="bulk-unsnooze-reason"
                placeholder="e.g., Investigation complete, re-enabling detection..."
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
            <DialogTitle>Delete Rules</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''}? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="bulk-delete-reason">Reason for Deletion *</Label>
              <Textarea
                id="bulk-delete-reason"
                placeholder="e.g., Rules are obsolete, replaced by new detection logic..."
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
    </div>
  )
}
