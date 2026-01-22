import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { rulesApi, indexPatternsApi, Rule, IndexPattern, RuleStatus } from '@/lib/api'
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
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ChevronDown, FolderTree, Plus, Search, Table as TableIcon, X } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { RulesTreeView } from '@/components/RulesTreeView'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'

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
const RULE_STATUSES: RuleStatus[] = ['enabled', 'disabled', 'snoozed']

// Filter types
type Filters = {
  indexPattern: string[]
  severity: string[]
  status: string[]
  deployed: 'any' | 'yes' | 'no'
  search: string
}

export default function RulesPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState<Rule[]>([])
  const [indexPatterns, setIndexPatterns] = useState<Record<string, IndexPattern>>({})
  const [indexPatternsList, setIndexPatternsList] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [filters, setFilters] = useState<Filters>({
    indexPattern: [],
    severity: [],
    status: [],
    deployed: 'any',
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
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  // Persist view mode changes
  useEffect(() => {
    localStorage.setItem('rules-view-mode', viewMode)
  }, [viewMode])

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
      // Deployed filter
      if (filters.deployed === 'yes' && !rule.deployed_at) {
        return false
      }
      if (filters.deployed === 'no' && rule.deployed_at) {
        return false
      }
      // Search filter
      if (filters.search && !rule.title.toLowerCase().includes(filters.search.toLowerCase())) {
        return false
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
      filters.deployed !== 'any' ||
      filters.search !== ''
    )
  }, [filters])

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      indexPattern: [],
      severity: [],
      status: [],
      deployed: 'any',
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

  // Bulk action handler
  const handleBulkAction = async (action: 'enable' | 'disable' | 'deploy' | 'undeploy' | 'delete') => {
    if (selectedRules.size === 0) return

    if (action === 'delete') {
      setShowBulkDeleteConfirm(true)
      return
    }

    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      let result

      switch (action) {
        case 'enable':
          result = await rulesApi.bulkEnable(ruleIds)
          break
        case 'disable':
          result = await rulesApi.bulkDisable(ruleIds)
          break
        case 'deploy':
          result = await rulesApi.bulkDeploy(ruleIds)
          break
        case 'undeploy':
          result = await rulesApi.bulkUndeploy(ruleIds)
          break
      }

      if (result && result.failed.length > 0) {
        setError(`${result.success.length} succeeded, ${result.failed.length} failed`)
      }

      clearSelection()
      loadData() // Refresh the list
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk operation failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  // Handler for confirmed bulk delete
  const handleBulkDelete = async () => {
    setShowBulkDeleteConfirm(false)
    setIsBulkOperating(true)
    try {
      const ruleIds = Array.from(selectedRules)
      const result = await rulesApi.bulkDelete(ruleIds)

      if (result.failed.length > 0) {
        setError(`${result.success.length} deleted, ${result.failed.length} failed`)
      }

      clearSelection()
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk delete failed')
    } finally {
      setIsBulkOperating(false)
    }
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Rules</h1>
        <Button onClick={() => navigate('/rules/new')}>
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
            placeholder="Search rules..."
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

        {/* Deployed select */}
        <label className="sr-only" htmlFor="deployed-filter">Deployment status</label>
        <Select
          value={filters.deployed}
          onValueChange={(value) =>
            setFilters((prev) => ({ ...prev, deployed: value as Filters['deployed'] }))
          }
        >
          <SelectTrigger id="deployed-filter" className="w-[140px]">
            <SelectValue placeholder="Deployed" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any</SelectItem>
            <SelectItem value="yes">Deployed</SelectItem>
            <SelectItem value="no">Not Deployed</SelectItem>
          </SelectContent>
        </Select>

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
          {filters.deployed !== 'any' && (
            <Badge variant="secondary" className="gap-1">
              {filters.deployed === 'yes' ? 'Deployed' : 'Not Deployed'}
              <button
                type="button"
                onClick={() => setFilters((prev) => ({ ...prev, deployed: 'any' }))}
                className="inline-flex items-center justify-center rounded-sm hover:bg-muted"
                aria-label={`Remove deployment filter: ${filters.deployed === 'yes' ? 'Deployed' : 'Not Deployed'}`}
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
                      onCheckedChange={() => toggleRuleSelection(rule.id, index, false)}
                      onClick={(e: React.MouseEvent) => {
                        e.stopPropagation()
                        toggleRuleSelection(rule.id, index, e.shiftKey)
                      }}
                      aria-label={`Select rule: ${rule.title}`}
                    />
                  </TableCell>
                  <TableCell className="font-medium">{rule.title}</TableCell>
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
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        rule.deployed_at ? 'bg-green-500 text-white' : 'bg-gray-500 text-white'
                      }`}
                    >
                      {rule.deployed_at ? 'Deployed' : 'Not Deployed'}
                    </span>
                  </TableCell>
                  <TableCell>
                    {indexPatterns[rule.index_pattern_id]?.name || 'Unknown'}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {rule.last_edited_by || '-'}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(rule.updated_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
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
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 z-50">
          <span className="text-sm font-medium">
            {selectedRules.size} rule{selectedRules.size > 1 ? 's' : ''} selected
          </span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => handleBulkAction('enable')} disabled={isBulkOperating}>
              Enable
            </Button>
            <Button size="sm" variant="outline" onClick={() => handleBulkAction('disable')} disabled={isBulkOperating}>
              Disable
            </Button>
            <Button size="sm" variant="outline" onClick={() => handleBulkAction('deploy')} disabled={isBulkOperating}>
              Deploy
            </Button>
            <Button size="sm" variant="outline" onClick={() => handleBulkAction('undeploy')} disabled={isBulkOperating}>
              Undeploy
            </Button>
            <Button size="sm" variant="destructive" onClick={() => handleBulkAction('delete')} disabled={isBulkOperating}>
              Delete
            </Button>
          </div>
          <Button size="sm" variant="ghost" onClick={clearSelection}>
            Cancel
          </Button>
        </div>
      )}

      {/* Bulk Delete Confirmation */}
      <DeleteConfirmModal
        open={showBulkDeleteConfirm}
        onOpenChange={setShowBulkDeleteConfirm}
        title="Delete Rules"
        description={`Are you sure you want to delete ${selectedRules.size} rule${selectedRules.size > 1 ? 's' : ''}? This action cannot be undone.`}
        onConfirm={handleBulkDelete}
        isDeleting={isBulkOperating}
      />
    </div>
  )
}
