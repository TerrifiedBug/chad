import { useEffect, useState, useMemo, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  attackApi,
  indexPatternsApi,
  AttackMatrixResponse,
  AttackCoverageResponse,
  TechniqueDetailResponse,
  TechniqueWithCoverage,
  IndexPattern,
} from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { RefreshCw, ExternalLink, X, ChevronRight, Shield, Target } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'

type CoverageLevel = 'none' | 'low' | 'medium' | 'high'

function getCoverageLevel(count: number): CoverageLevel {
  if (count === 0) return 'none'
  if (count <= 2) return 'low'
  if (count <= 5) return 'medium'
  return 'high'
}

const coverageColors: Record<CoverageLevel, string> = {
  none: 'bg-red-100 dark:bg-red-900/30 hover:bg-red-200 dark:hover:bg-red-900/50 border-red-200 dark:border-red-800',
  low: 'bg-yellow-100 dark:bg-yellow-900/30 hover:bg-yellow-200 dark:hover:bg-yellow-900/50 border-yellow-200 dark:border-yellow-800',
  medium: 'bg-blue-100 dark:bg-blue-900/30 hover:bg-blue-200 dark:hover:bg-blue-900/50 border-blue-200 dark:border-blue-800',
  high: 'bg-green-100 dark:bg-green-900/30 hover:bg-green-200 dark:hover:bg-green-900/50 border-green-200 dark:border-green-800',
}

const coverageTextColors: Record<CoverageLevel, string> = {
  none: 'text-red-700 dark:text-red-300',
  low: 'text-yellow-700 dark:text-yellow-300',
  medium: 'text-blue-700 dark:text-blue-300',
  high: 'text-green-700 dark:text-green-300',
}

export default function AttackMatrixPage() {
  const navigate = useNavigate()
  const { hasPermission } = useAuth()
  const [matrix, setMatrix] = useState<AttackMatrixResponse | null>(null)
  const [coverage, setCoverage] = useState<AttackCoverageResponse | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueDetailResponse | null>(null)
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSyncing, setIsSyncing] = useState(false)
  const [error, setError] = useState('')

  // Filters
  const [deployedOnly, setDeployedOnly] = useState(false)
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([])
  const [selectedIndexPattern, setSelectedIndexPattern] = useState<string>('')

  // Load functions - must be declared before useEffect that uses them
  const loadData = useCallback(async () => {
    try {
      setIsLoading(true)
      const matrixData = await attackApi.getMatrix()
      setMatrix(matrixData)
      const coverageData = await attackApi.getCoverage()
      setCoverage(coverageData)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load ATT&CK data')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const loadCoverage = useCallback(async () => {
    try {
      const params: { deployed_only?: boolean; severity?: string[]; index_pattern_id?: string } = {}
      if (deployedOnly) params.deployed_only = true
      if (selectedSeverities.length > 0) params.severity = selectedSeverities
      if (selectedIndexPattern) params.index_pattern_id = selectedIndexPattern
      const coverageData = await attackApi.getCoverage(params)
      setCoverage(coverageData)
    } catch (err) {
      console.error('Failed to load coverage:', err)
    }
  }, [deployedOnly, selectedSeverities, selectedIndexPattern])

  useEffect(() => {
    loadData()
    loadIndexPatterns()
  }, [loadData])

  useEffect(() => {
    if (matrix) {
      loadCoverage()
    }
  }, [deployedOnly, selectedSeverities, selectedIndexPattern, matrix, loadCoverage])

  const loadIndexPatterns = async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
    } catch (err) {
      console.error('Failed to load index patterns:', err)
    }
  }

  const handleSync = async () => {
    try {
      setIsSyncing(true)
      await attackApi.sync()
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sync ATT&CK data')
    } finally {
      setIsSyncing(false)
    }
  }

  const handleTechniqueClick = async (technique: TechniqueWithCoverage) => {
    try {
      const params: { deployed_only?: boolean; severity?: string[]; index_pattern_id?: string } = {}
      if (deployedOnly) params.deployed_only = true
      if (selectedSeverities.length > 0) params.severity = selectedSeverities
      if (selectedIndexPattern) params.index_pattern_id = selectedIndexPattern
      const detail = await attackApi.getTechnique(technique.id, params)
      setSelectedTechnique(detail)
    } catch (err) {
      console.error('Failed to load technique details:', err)
    }
  }

  const toggleSeverity = (severity: string) => {
    setSelectedSeverities((prev) =>
      prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
    )
  }

  // Calculate stats
  const stats = useMemo(() => {
    if (!matrix || !coverage) return { total: 0, covered: 0, uncovered: 0, deployed: 0 }
    const allTechniques = matrix.tactics.flatMap((t) => t.techniques)
    const total = allTechniques.filter((t) => !t.is_subtechnique).length
    const covered = allTechniques.filter((t) => !t.is_subtechnique && (coverage.coverage[t.id]?.total || 0) > 0).length
    const deployed = allTechniques.filter((t) => !t.is_subtechnique && (coverage.coverage[t.id]?.deployed || 0) > 0).length
    return { total, covered, uncovered: total - covered, deployed }
  }, [matrix, coverage])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading ATT&CK matrix...</div>
      </div>
    )
  }

  if (error && !matrix) {
    return (
      <div className="space-y-4">
        <div className="bg-destructive/10 text-destructive p-4 rounded-md">{error}</div>
        <Button onClick={handleSync} disabled={isSyncing || !hasPermission('manage_settings')}>
          <RefreshCw className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
          Sync ATT&CK Data
        </Button>
      </div>
    )
  }

  // Show sync prompt when matrix is empty (no techniques synced yet)
  if (matrix && matrix.tactics.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" />
            MITRE ATT&CK Coverage
          </h1>
          <p className="text-muted-foreground">Visualize detection coverage across the ATT&CK Enterprise Matrix</p>
        </div>
        <Card>
          <CardContent className="py-8 text-center">
            <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <h3 className="text-lg font-semibold mb-2">No ATT&CK Data</h3>
            <p className="text-muted-foreground mb-4">
              The MITRE ATT&CK framework hasn't been synced yet. Click the button below to download the latest techniques.
            </p>
            <Button onClick={handleSync} disabled={isSyncing || !hasPermission('manage_settings')}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
              {isSyncing ? 'Syncing...' : 'Sync ATT&CK Framework'}
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" />
            MITRE ATT&CK Coverage
          </h1>
          <p className="text-muted-foreground">Visualize detection coverage across the ATT&CK Enterprise Matrix</p>
        </div>
        <Button onClick={handleSync} disabled={isSyncing || !hasPermission('manage_settings')} variant="outline">
          <RefreshCw className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
          Sync
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold">{stats.total}</div>
            <div className="text-sm text-muted-foreground">Total Techniques</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold text-green-600">{stats.covered}</div>
            <div className="text-sm text-muted-foreground">Covered</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold text-blue-600">{stats.deployed}</div>
            <div className="text-sm text-muted-foreground">Deployed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-2xl font-bold text-red-600">{stats.uncovered}</div>
            <div className="text-sm text-muted-foreground">No Coverage</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="py-3">
          <div className="flex items-center gap-6 flex-wrap">
            <div className="flex items-center gap-2">
              <Checkbox
                id="deployed-only"
                checked={deployedOnly}
                onCheckedChange={(checked) => setDeployedOnly(checked === true)}
              />
              <label htmlFor="deployed-only" className="text-sm">
                Deployed rules only
              </label>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Severity:</span>
              {['critical', 'high', 'medium', 'low'].map((sev) => (
                <Badge
                  key={sev}
                  variant={selectedSeverities.includes(sev) ? 'default' : 'outline'}
                  className="cursor-pointer capitalize"
                  onClick={() => toggleSeverity(sev)}
                >
                  {sev}
                </Badge>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Index:</span>
              <Select value={selectedIndexPattern || 'all'} onValueChange={(v) => setSelectedIndexPattern(v === 'all' ? '' : v)}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="All indices" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All indices</SelectItem>
                  {indexPatterns.map((ip) => (
                    <SelectItem key={ip.id} value={ip.id}>
                      {ip.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {/* Legend */}
            <div className="flex items-center gap-3 ml-auto">
              <span className="text-sm text-muted-foreground">Coverage:</span>
              <div className="flex items-center gap-1">
                <div className="w-4 h-4 bg-red-200 dark:bg-red-900/50 rounded" />
                <span className="text-xs">None</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-4 h-4 bg-yellow-200 dark:bg-yellow-900/50 rounded" />
                <span className="text-xs">1-2</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-4 h-4 bg-blue-200 dark:bg-blue-900/50 rounded" />
                <span className="text-xs">3-5</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-4 h-4 bg-green-200 dark:bg-green-900/50 rounded" />
                <span className="text-xs">6+</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Matrix Grid */}
      <div className="flex gap-4">
        <div className="flex-1 overflow-x-auto">
          <div className="flex gap-2 min-w-max">
            {matrix?.tactics.map((tactic) => (
              <div key={tactic.id} className="w-40 flex-shrink-0">
                <div className="bg-muted px-2 py-2 rounded-t-md text-center">
                  <div className="font-semibold text-xs truncate" title={tactic.name}>
                    {tactic.name}
                  </div>
                  <div className="text-xs text-muted-foreground">{tactic.id}</div>
                </div>
                <div className="space-y-1 p-1 bg-muted/30 rounded-b-md min-h-[200px]">
                  {tactic.techniques
                    .filter((t) => !t.is_subtechnique)
                    .map((technique) => {
                      const stats = coverage?.coverage[technique.id]
                      const totalCount = stats?.total || 0
                      const deployedCount = stats?.deployed || 0
                      const level = getCoverageLevel(totalCount)
                      return (
                        <button
                          key={technique.id}
                          onClick={() => handleTechniqueClick(technique)}
                          className={`w-full text-left p-1.5 rounded border text-xs transition-colors ${coverageColors[level]} ${
                            selectedTechnique?.technique.id === technique.id ? 'ring-2 ring-primary' : ''
                          }`}
                        >
                          <div className="font-medium truncate" title={technique.name}>
                            {technique.name}
                          </div>
                          <div className="flex items-center justify-between mt-0.5">
                            <span className="text-[10px] opacity-70">{technique.id}</span>
                            <span className={`text-[10px] font-medium ${coverageTextColors[level]}`}>
                              {totalCount} rule{totalCount !== 1 ? 's' : ''}{totalCount > 0 && ` (${deployedCount} deployed)`}
                            </span>
                          </div>
                        </button>
                      )
                    })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Detail Panel */}
        {selectedTechnique && (
          <Card className="w-96 flex-shrink-0">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-lg">{selectedTechnique.technique.name}</CardTitle>
                  <div className="text-sm text-muted-foreground">
                    {selectedTechnique.technique.id} - {selectedTechnique.technique.tactic_name}
                  </div>
                </div>
                <Button variant="ghost" size="icon" onClick={() => setSelectedTechnique(null)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px] pr-4">
                <div className="space-y-4">
                  {/* Description */}
                  {selectedTechnique.technique.description && (
                    <div>
                      <h4 className="font-medium text-sm mb-1">Description</h4>
                      <p className="text-sm text-muted-foreground line-clamp-4">
                        {selectedTechnique.technique.description}
                      </p>
                    </div>
                  )}

                  {/* External Link */}
                  {selectedTechnique.technique.url && (
                    <a
                      href={selectedTechnique.technique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-primary hover:underline flex items-center gap-1"
                    >
                      View on MITRE ATT&CK <ExternalLink className="h-3 w-3" />
                    </a>
                  )}

                  {/* Platforms */}
                  {selectedTechnique.technique.platforms && selectedTechnique.technique.platforms.length > 0 && (
                    <div>
                      <h4 className="font-medium text-sm mb-1">Platforms</h4>
                      <div className="flex flex-wrap gap-1">
                        {selectedTechnique.technique.platforms.map((p) => (
                          <Badge key={p} variant="secondary" className="text-xs">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Sub-techniques */}
                  {selectedTechnique.sub_techniques.length > 0 && (
                    <div>
                      <h4 className="font-medium text-sm mb-1">Sub-techniques</h4>
                      <div className="space-y-1">
                        {selectedTechnique.sub_techniques.map((sub) => {
                          const level = getCoverageLevel(sub.rule_count)
                          return (
                            <div
                              key={sub.id}
                              className={`text-xs p-2 rounded ${coverageColors[level]} cursor-pointer`}
                              onClick={() => handleTechniqueClick(sub)}
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-medium">{sub.name}</span>
                                <span className={coverageTextColors[level]}>{sub.rule_count} rules</span>
                              </div>
                              <span className="opacity-70">{sub.id}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Linked Rules */}
                  <div>
                    <h4 className="font-medium text-sm mb-1 flex items-center gap-1">
                      <Target className="h-4 w-4" />
                      Linked Rules ({selectedTechnique.rules.length})
                    </h4>
                    {selectedTechnique.rules.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No rules linked to this technique</p>
                    ) : (
                      <div className="space-y-1">
                        {selectedTechnique.rules.map((rule) => (
                          <button
                            key={rule.id}
                            onClick={() => navigate(`/rules/${rule.id}`)}
                            className="w-full text-left p-2 rounded bg-muted hover:bg-muted/80 text-xs flex items-center justify-between group"
                          >
                            <div>
                              <div className="font-medium">{rule.title}</div>
                              <div className="flex items-center gap-2 mt-0.5">
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] capitalize ${
                                    rule.severity === 'critical'
                                      ? 'border-red-500 text-red-500'
                                      : rule.severity === 'high'
                                        ? 'border-orange-500 text-orange-500'
                                        : rule.severity === 'medium'
                                          ? 'border-yellow-500 text-yellow-500'
                                          : 'border-blue-500 text-blue-500'
                                  }`}
                                >
                                  {rule.severity}
                                </Badge>
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] capitalize ${
                                    rule.status === 'deployed' ? 'border-green-500 text-green-500' : ''
                                  }`}
                                >
                                  {rule.status}
                                </Badge>
                              </div>
                            </div>
                            <ChevronRight className="h-4 w-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
