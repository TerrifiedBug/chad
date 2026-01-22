import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { rulesApi, indexPatternsApi, Rule, IndexPattern } from '@/lib/api'
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
import { FolderTree, Plus, Search, Table as TableIcon } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { RulesTreeView } from '@/components/RulesTreeView'
import { cn } from '@/lib/utils'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

type DeploymentFilter = 'all' | 'deployed' | 'not_deployed'

export default function RulesPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState<Rule[]>([])
  const [indexPatterns, setIndexPatterns] = useState<Record<string, IndexPattern>>({})
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [deploymentFilter, setDeploymentFilter] = useState<DeploymentFilter>('all')
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
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules')
    } finally {
      setIsLoading(false)
    }
  }

  const filteredRules = rules.filter((rule) => {
    const matchesSearch = rule.title.toLowerCase().includes(search.toLowerCase())
    const matchesDeployment =
      deploymentFilter === 'all' ||
      (deploymentFilter === 'deployed' && rule.deployed_at !== null) ||
      (deploymentFilter === 'not_deployed' && rule.deployed_at === null)
    return matchesSearch && matchesDeployment
  })

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

      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select
          value={deploymentFilter}
          onValueChange={(value) => setDeploymentFilter(value as DeploymentFilter)}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Rules</SelectItem>
            <SelectItem value="deployed">Deployed</SelectItem>
            <SelectItem value="not_deployed">Not Deployed</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex items-center gap-1">
          <Button
            variant={viewMode === 'tree' ? 'default' : 'outline'}
            size="icon"
            onClick={() => setViewMode('tree')}
            title="Tree view"
          >
            <FolderTree className="h-4 w-4" />
          </Button>
          <Button
            variant={viewMode === 'table' ? 'default' : 'outline'}
            size="icon"
            onClick={() => setViewMode('table')}
            title="Table view"
          >
            <TableIcon className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : filteredRules.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          {search ? 'No rules match your search' : 'No rules found. Create your first rule!'}
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
