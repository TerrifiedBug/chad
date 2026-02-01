import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  sigmahqApi,
  indexPatternsApi,
  SigmaHQStatus,
  SigmaHQCategory,
  SigmaHQRule,
  SigmaHQRuleContent,
  SigmaHQRuleType,
  IndexPattern,
} from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  ChevronRight,
  ChevronDown,
  RefreshCw,
  Search,
  Folder,
  FileText,
  Download,
  Loader2,
  GitBranch,
  X,
  Zap,
} from 'lucide-react'
import { SEVERITY_COLORS, capitalize } from '@/lib/constants'

// SigmaHQ rule stability status colors (different from alert status)
const sigmaStatusColors: Record<string, string> = {
  stable: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  test: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  experimental: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  deprecated: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  unsupported: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
}

type CategoryTreeItemProps = {
  name: string
  category: SigmaHQCategory
  path: string
  selectedPath: string | null
  expandedPaths: Set<string>
  onToggleExpand: (path: string) => void
  onSelectCategory: (path: string) => void
}

function CategoryTreeItem({
  name,
  category,
  path,
  selectedPath,
  expandedPaths,
  onToggleExpand,
  onSelectCategory,
}: CategoryTreeItemProps) {
  const isExpanded = expandedPaths.has(path)
  const isSelected = selectedPath === path
  const hasChildren = Object.keys(category.children).length > 0

  return (
    <div>
      <div
        className={`flex items-center gap-1 py-1 px-2 rounded cursor-pointer hover:bg-muted ${
          isSelected ? 'bg-muted font-medium' : ''
        }`}
        onClick={() => {
          if (hasChildren) {
            onToggleExpand(path)
          }
          onSelectCategory(path)
        }}
      >
        {hasChildren ? (
          isExpanded ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
          )
        ) : (
          <span className="w-4" />
        )}
        <Folder className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span className="truncate text-sm">{name}</span>
        <span className="ml-auto text-xs text-muted-foreground">
          {category.count}
        </span>
      </div>
      {isExpanded && hasChildren && (
        <div className="ml-4">
          {Object.entries(category.children)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([childName, childCategory]) => (
              <CategoryTreeItem
                key={childName}
                name={childName}
                category={childCategory}
                path={`${path}/${childName}`}
                selectedPath={selectedPath}
                expandedPaths={expandedPaths}
                onToggleExpand={onToggleExpand}
                onSelectCategory={onSelectCategory}
              />
            ))}
        </div>
      )}
    </div>
  )
}

export default function SigmaHQPage() {
  const navigate = useNavigate()

  // Rule type state (for tabs)
  const [ruleType, setRuleType] = useState<SigmaHQRuleType>('detection')

  // Status state
  const [status, setStatus] = useState<SigmaHQStatus | null>(null)
  const [isLoadingStatus, setIsLoadingStatus] = useState(true)
  const [isSyncing, setIsSyncing] = useState(false)
  const [syncError, setSyncError] = useState('')

  // Category tree state
  const [categories, setCategories] = useState<Record<string, SigmaHQCategory>>({})
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set())

  // Rules list state
  const [rules, setRules] = useState<SigmaHQRule[]>([])
  const [isLoadingRules, setIsLoadingRules] = useState(false)
  const [rulesError, setRulesError] = useState('')

  // Selected rule state
  const [selectedRule, setSelectedRule] = useState<SigmaHQRule | null>(null)
  const [ruleContent, setRuleContent] = useState<SigmaHQRuleContent | null>(null)
  const [isLoadingContent, setIsLoadingContent] = useState(false)

  // Search state
  const [searchQuery, setSearchQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [isSearchActive, setIsSearchActive] = useState(false)

  // Import dialog state
  const [showImportDialog, setShowImportDialog] = useState(false)
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [selectedIndexPatternId, setSelectedIndexPatternId] = useState('')
  const [isImporting, setIsImporting] = useState(false)
  const [importError, setImportError] = useState('')
  const [importSuccess, setImportSuccess] = useState('')

  // Define loadCategories first (no dependencies)
  const loadCategories = useCallback(async (type: SigmaHQRuleType) => {
    try {
      const data = await sigmahqApi.getCategories(type)
      setCategories(data.categories)
    } catch (err) {
      console.error('Failed to load categories:', err)
    }
  }, [])

  // Load status depends on loadCategories
  const loadStatus = useCallback(async () => {
    setIsLoadingStatus(true)
    try {
      const data = await sigmahqApi.getStatus()
      setStatus(data)
      if (data.cloned) {
        loadCategories(ruleType)
      }
    } catch (err) {
      console.error('Failed to load SigmaHQ status:', err)
    } finally {
      setIsLoadingStatus(false)
    }
  }, [loadCategories, ruleType])

  // Load status on mount
  useEffect(() => {
    loadStatus()
    loadIndexPatterns()
  }, [loadStatus])

  // Reload categories when rule type changes
  useEffect(() => {
    if (status?.cloned) {
      // Clear current state when switching rule types
      setSelectedPath(null)
      setExpandedPaths(new Set())
      setRules([])
      setSelectedRule(null)
      setRuleContent(null)
      setSearchQuery('')
      setIsSearchActive(false)
      loadCategories(ruleType)
    }
  }, [ruleType, status?.cloned, loadCategories])

  const loadIndexPatterns = async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
      if (patterns.length > 0) {
        setSelectedIndexPatternId(patterns[0].id)
      }
    } catch (err) {
      console.error('Failed to load index patterns:', err)
    }
  }

  const handleSync = async () => {
    setIsSyncing(true)
    setSyncError('')
    try {
      const result = await sigmahqApi.sync()
      if (result.success) {
        await loadStatus()
      } else {
        setSyncError(result.error || 'Sync failed')
      }
    } catch (err) {
      setSyncError(err instanceof Error ? err.message : 'Sync failed')
    } finally {
      setIsSyncing(false)
    }
  }

  const handleToggleExpand = (path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev)
      if (next.has(path)) {
        next.delete(path)
      } else {
        next.add(path)
      }
      return next
    })
  }

  const handleSelectCategory = async (path: string) => {
    setSelectedPath(path)
    setSelectedRule(null)
    setRuleContent(null)
    setIsSearchActive(false)
    setSearchQuery('')
    setIsLoadingRules(true)
    setRulesError('')
    try {
      const data = await sigmahqApi.listRulesInCategory(path, ruleType)
      setRules(data.rules)
    } catch (err) {
      setRulesError(err instanceof Error ? err.message : 'Failed to load rules')
      setRules([])
    } finally {
      setIsLoadingRules(false)
    }
  }

  const handleSelectRule = async (rule: SigmaHQRule) => {
    setSelectedRule(rule)
    setIsLoadingContent(true)
    try {
      const content = await sigmahqApi.getRuleContent(rule.path, ruleType)
      setRuleContent(content)
    } catch (err) {
      console.error('Failed to load rule content:', err)
      setRuleContent(null)
    } finally {
      setIsLoadingContent(false)
    }
  }

  const handleSearch = useCallback(
    async (query: string) => {
      if (!query.trim()) {
        setIsSearchActive(false)
        setRules([])
        setSelectedPath(null)
        return
      }

      setIsSearching(true)
      setIsSearchActive(true)
      setSelectedPath(null)
      setSelectedRule(null)
      setRuleContent(null)
      setRulesError('')

      try {
        const data = await sigmahqApi.searchRules(query.trim(), 100, ruleType)
        setRules(data.rules)
      } catch (err) {
        setRulesError(err instanceof Error ? err.message : 'Search failed')
        setRules([])
      } finally {
        setIsSearching(false)
      }
    },
    [ruleType]
  )

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery) {
        handleSearch(searchQuery)
      }
    }, 300)

    return () => clearTimeout(timer)
  }, [searchQuery, handleSearch])

  const handleClearSearch = () => {
    setSearchQuery('')
    setIsSearchActive(false)
    setRules([])
    setSelectedRule(null)
    setRuleContent(null)
  }

  const handleOpenImportDialog = () => {
    setShowImportDialog(true)
    setImportError('')
    setImportSuccess('')
  }

  const handleImport = async () => {
    if (!selectedRule || !selectedIndexPatternId) return

    // Prevent duplicate clicks - check if already importing
    if (isImporting) {
      console.warn('Import already in progress, ignoring duplicate click')
      return
    }

    setIsImporting(true)
    setImportError('')
    setImportSuccess('')

    try {
      const result = await sigmahqApi.importRule(selectedRule.path, selectedIndexPatternId, ruleType)
      if (result.success) {
        setImportSuccess(`Rule "${result.title}" imported successfully!`)
        setTimeout(() => {
          setShowImportDialog(false)
          navigate(`/rules/${result.rule_id}`)
        }, 1500)
        // Don't reset isImporting on success - keep button disabled until navigation
        return
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Import failed'

      // Check for duplicate rule error
      if (errorMessage.includes('rule_already_imported')) {
        setImportError('This rule has already been imported from SigmaHQ.')
      } else {
        setImportError(errorMessage)
      }
      // Reset loading state on error so user can try again
      setIsImporting(false)
    }
  }

  // Loading state
  if (isLoadingStatus) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  // Not cloned - show sync card
  if (!status?.cloned) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold">SigmaHQ Rules</h1>
          <p className="text-muted-foreground">
            Browse and import rules from the SigmaHQ community repository
          </p>
        </div>

        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitBranch className="h-5 w-5" />
              SigmaHQ Repository
            </CardTitle>
            <CardDescription>
              SigmaHQ is the official repository of Sigma detection rules maintained by the
              community. Syncing this repository gives you access to thousands of
              community-contributed detection rules.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-sm text-muted-foreground">
              <p>
                The repository will be cloned to your server. This may take a few minutes
                depending on your network connection.
              </p>
            </div>

            {syncError && (
              <div className="bg-destructive/10 text-destructive p-3 rounded-md text-sm">
                {syncError}
              </div>
            )}

            <Button onClick={handleSync} disabled={isSyncing}>
              {isSyncing ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Syncing...
                </>
              ) : (
                <>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Sync SigmaHQ Repository
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Cloned - show browser
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">SigmaHQ Rules</h1>
          <p className="text-muted-foreground">
            Browse and import rules from the SigmaHQ community repository
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-muted-foreground">
            {status.rule_counts && (
              <>
                {Object.values(status.rule_counts).reduce((a, b) => a + b, 0).toLocaleString()} total rules
              </>
            )}
            {status.commit_hash && (
              <span className="ml-2 font-mono text-xs">
                @ {status.commit_hash.substring(0, 7)}
              </span>
            )}
          </div>
          <Button variant="outline" onClick={handleSync} disabled={isSyncing}>
            {isSyncing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            <span className="ml-2">Sync</span>
          </Button>
        </div>
      </div>

      {syncError && (
        <div className="bg-destructive/10 text-destructive p-3 rounded-md text-sm">
          {syncError}
        </div>
      )}

      {/* Rule type tabs */}
      <Tabs value={ruleType} onValueChange={(v) => setRuleType(v as SigmaHQRuleType)}>
        <TabsList>
          <TabsTrigger value="detection">
            Detection Rules
            {status.rule_counts?.detection !== undefined && (
              <span className="ml-1.5 text-xs text-muted-foreground">
                ({status.rule_counts.detection.toLocaleString()})
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="threat_hunting">
            <Search className="mr-1.5 h-3.5 w-3.5" />
            Threat Hunting
            {status.rule_counts?.threat_hunting !== undefined && (
              <span className="ml-1.5 text-xs text-muted-foreground">
                ({status.rule_counts.threat_hunting.toLocaleString()})
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="emerging_threats">
            <Zap className="mr-1.5 h-3.5 w-3.5" />
            Emerging Threats
            {status.rule_counts?.emerging_threats !== undefined && (
              <span className="ml-1.5 text-xs text-muted-foreground">
                ({status.rule_counts.emerging_threats.toLocaleString()})
              </span>
            )}
          </TabsTrigger>
        </TabsList>
      </Tabs>

      {/* Search bar */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search rules by title, description, or tags..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 pr-10"
        />
        {searchQuery && (
          <button
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            onClick={handleClearSearch}
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Main content - 3 column layout */}
      <div className="grid grid-cols-12 gap-4 h-[calc(100vh-340px)] min-h-[500px]">
        {/* Category tree */}
        <div className="col-span-3 border rounded-lg overflow-auto">
          <div className="p-3 border-b bg-muted/50">
            <h3 className="font-medium text-sm">Categories</h3>
          </div>
          <div className="p-2">
            {Object.entries(categories)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([name, category]) => (
                <CategoryTreeItem
                  key={name}
                  name={name}
                  category={category}
                  path={name}
                  selectedPath={selectedPath}
                  expandedPaths={expandedPaths}
                  onToggleExpand={handleToggleExpand}
                  onSelectCategory={handleSelectCategory}
                />
              ))}
          </div>
        </div>

        {/* Rules list */}
        <div className="col-span-4 border rounded-lg overflow-auto">
          <div className="p-3 border-b bg-muted/50 flex items-center justify-between">
            <h3 className="font-medium text-sm">
              {isSearchActive
                ? `Search Results (${rules.length})`
                : selectedPath
                ? `Rules in ${selectedPath.split('/').pop()}`
                : 'Select a category'}
            </h3>
            {isSearching && <Loader2 className="h-4 w-4 animate-spin" />}
          </div>
          <div className="divide-y">
            {isLoadingRules ? (
              <div className="p-4 text-center text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mx-auto" />
              </div>
            ) : rulesError ? (
              <div className="p-4 text-center text-destructive text-sm">{rulesError}</div>
            ) : rules.length === 0 ? (
              <div className="p-4 text-center text-muted-foreground text-sm">
                {isSearchActive
                  ? 'No rules match your search'
                  : selectedPath
                  ? 'No rules in this category'
                  : 'Select a category to view rules'}
              </div>
            ) : (
              rules.map((rule) => (
                <div
                  key={rule.path}
                  className={`p-3 cursor-pointer hover:bg-muted/50 ${
                    selectedRule?.path === rule.path ? 'bg-muted' : ''
                  }`}
                  onClick={() => handleSelectRule(rule)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <span className="text-sm font-medium truncate">{rule.title}</span>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${
                        SEVERITY_COLORS[rule.severity] || 'bg-gray-500 text-white'
                      }`}
                    >
                      {capitalize(rule.severity)}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                    {rule.description}
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    <span
                      className={`px-1.5 py-0.5 rounded text-xs ${
                        sigmaStatusColors[rule.status] || 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {rule.status}
                    </span>
                    {rule.tags.slice(0, 2).map((tag) => (
                      <Badge key={tag} variant="outline" className="text-xs py-0">
                        {tag}
                      </Badge>
                    ))}
                    {rule.tags.length > 2 && (
                      <span className="text-xs text-muted-foreground">
                        +{rule.tags.length - 2}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Rule preview */}
        <div className="col-span-5 border rounded-lg overflow-auto flex flex-col">
          <div className="p-3 border-b bg-muted/50 flex items-center justify-between shrink-0">
            <h3 className="font-medium text-sm">
              {selectedRule ? selectedRule.title : 'Rule Preview'}
            </h3>
            {selectedRule && (
              <Button size="sm" onClick={handleOpenImportDialog} disabled={isImporting}>
                {isImporting ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                    Importing...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-1" />
                    Import
                  </>
                )}
              </Button>
            )}
          </div>
          <div className="flex-1 overflow-auto">
            {isLoadingContent ? (
              <div className="p-4 text-center text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mx-auto" />
              </div>
            ) : selectedRule && ruleContent ? (
              <div className="p-4 space-y-4">
                {/* Metadata */}
                <div className="space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        SEVERITY_COLORS[selectedRule.severity] || 'bg-gray-500 text-white'
                      }`}
                    >
                      {capitalize(selectedRule.severity)}
                    </span>
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        sigmaStatusColors[selectedRule.status] || 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {selectedRule.status}
                    </span>
                    {ruleType === 'threat_hunting' && (
                      <Badge variant="secondary" className="text-xs">
                        <Search className="mr-1 h-3 w-3" /> Hunting
                      </Badge>
                    )}
                    {ruleType === 'emerging_threats' && (
                      <Badge variant="secondary" className="text-xs">
                        <Zap className="mr-1 h-3 w-3" /> Emerging
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{selectedRule.description}</p>
                  {selectedRule.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {selectedRule.tags.map((tag) => (
                        <Badge key={tag} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>

                {/* YAML content */}
                <div className="space-y-2">
                  <Label className="text-xs font-medium text-muted-foreground">
                    YAML Content
                  </Label>
                  <pre className="text-xs bg-muted p-4 rounded-lg overflow-x-auto whitespace-pre font-mono">
                    {ruleContent.content}
                  </pre>
                </div>

                {/* File path */}
                <div className="text-xs text-muted-foreground">
                  <span className="font-medium">Path:</span> {selectedRule.path}
                </div>
              </div>
            ) : (
              <div className="p-4 text-center text-muted-foreground text-sm">
                Select a rule to preview its content
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Import dialog */}
      <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Import Rule</DialogTitle>
            <DialogDescription>
              Import &quot;{selectedRule?.title}&quot; to your rule library. Select the index
              pattern this rule should query.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {indexPatterns.length === 0 ? (
              <div className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 p-3 rounded-md text-sm">
                No index patterns configured. Please create an index pattern first.
              </div>
            ) : (
              <div className="space-y-2">
                <Label htmlFor="index-pattern">Index Pattern</Label>
                <Select
                  value={selectedIndexPatternId}
                  onValueChange={setSelectedIndexPatternId}
                >
                  <SelectTrigger id="index-pattern">
                    <SelectValue placeholder="Select an index pattern" />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    {indexPatterns.map((pattern) => (
                      <SelectItem key={pattern.id} value={pattern.id}>
                        {pattern.name} ({pattern.pattern})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  The imported rule will be configured to search this index pattern.
                </p>
              </div>
            )}

            {importError && (
              <div className="bg-destructive/10 text-destructive p-3 rounded-md text-sm">
                {importError}
              </div>
            )}

            {importSuccess && (
              <div className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 p-3 rounded-md text-sm">
                {importSuccess}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowImportDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleImport}
              disabled={isImporting || indexPatterns.length === 0 || !selectedIndexPatternId}
            >
              {isImporting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Importing...
                </>
              ) : (
                <>
                  <Download className="mr-2 h-4 w-4" />
                  Import Rule
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
