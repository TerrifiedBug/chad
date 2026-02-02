import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  indexPatternsApi,
  IndexPattern,
  healthApi,
  HealthStatus,
} from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Plus, Trash2, Check, Loader2, Copy, Eye, EyeOff, RefreshCw, CheckCircle2, AlertTriangle, AlertCircle, Database } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'

const HealthStatusIcon = ({ status }: { status: HealthStatus }) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle2 className="h-4 w-4 text-green-600" />
    case 'warning':
      return <AlertTriangle className="h-4 w-4 text-yellow-600" />
    case 'critical':
      return <AlertCircle className="h-4 w-4 text-red-600" />
  }
}

// Format relative time (e.g., "2 hours ago", "3 days ago")
const formatRelativeTime = (dateString: string): string => {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 60) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHour < 24) return `${diffHour}h ago`
  if (diffDay < 7) return `${diffDay}d ago`

  return date.toLocaleDateString()
}

export default function IndexPatternsPage() {
  const navigate = useNavigate()

  const [patterns, setPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [healthData, setHealthData] = useState<Record<string, HealthStatus>>({})

  // Delete confirmation
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')

  // Token visibility state
  const [visibleTokens, setVisibleTokens] = useState<Set<string>>(new Set())
  const [copiedToken, setCopiedToken] = useState<string | null>(null)

  // Token regeneration state
  const [regenerateId, setRegenerateId] = useState<string | null>(null)
  const [isRegenerating, setIsRegenerating] = useState(false)

  // Token details dialog
  const [tokenDetailsPattern, setTokenDetailsPattern] = useState<IndexPattern | null>(null)

  const loadPatterns = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const data = await indexPatternsApi.list()
      setPatterns(data)
      loadHealthData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load patterns')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadPatterns()
  }, [loadPatterns])

  const loadHealthData = async () => {
    try {
      const health = await healthApi.listIndices()
      const healthMap: Record<string, HealthStatus> = {}
      for (const h of health) {
        healthMap[h.index_pattern_id] = h.status
      }
      setHealthData(healthMap)
    } catch {
      // Health data is optional, continue without it
    }
  }

  // Navigation handlers
  const handleCreatePattern = () => {
    navigate('/index-patterns/new')
  }

  const handleOpenPattern = (patternId: string) => {
    navigate(`/index-patterns/${patternId}`)
  }

  const handleDelete = async () => {
    if (!deleteId) return

    setIsDeleting(true)
    setDeleteError('')
    try {
      await indexPatternsApi.delete(deleteId)
      setDeleteId(null)
      loadPatterns()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setIsDeleting(false)
    }
  }

  const openDeleteDialog = (patternId: string) => {
    setDeleteId(patternId)
    setDeleteError('')
  }

  const handleRegenerateToken = async () => {
    if (!regenerateId) return

    setIsRegenerating(true)
    try {
      const result = await indexPatternsApi.regenerateToken(regenerateId)
      // Update the pattern in state with the new token
      setPatterns(prev =>
        prev.map(p =>
          p.id === regenerateId ? { ...p, auth_token: result.auth_token } : p
        )
      )
      // Also update token details dialog if open
      if (tokenDetailsPattern?.id === regenerateId) {
        setTokenDetailsPattern(prev =>
          prev ? { ...prev, auth_token: result.auth_token } : null
        )
      }
      setRegenerateId(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to regenerate token')
    } finally {
      setIsRegenerating(false)
    }
  }

  const toggleTokenVisibility = (patternId: string) => {
    setVisibleTokens(prev => {
      const newSet = new Set(prev)
      if (newSet.has(patternId)) {
        newSet.delete(patternId)
      } else {
        newSet.add(patternId)
      }
      return newSet
    })
  }

  const copyToClipboard = async (text: string, patternId: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedToken(patternId)
      setTimeout(() => setCopiedToken(null), 2000)
    } catch {
      setError('Failed to copy to clipboard')
    }
  }

  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Index Patterns</h1>
        <Button onClick={handleCreatePattern}>
          <Plus className="h-4 w-4 mr-2" />
          Create Pattern
        </Button>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <LoadingState message="Loading index patterns..." />
      ) : patterns.length === 0 ? (
        <EmptyState
          icon={<Database className="h-12 w-12" />}
          title="No index patterns"
          description="Create your first index pattern to start matching rules against your OpenSearch indices."
          action={
            <Button onClick={handleCreatePattern}>
              <Plus className="h-4 w-4 mr-2" />
              Create Pattern
            </Button>
          }
        />
      ) : (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Pattern</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Last Edited By</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="w-20">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {patterns.map((pattern) => (
                <TableRow
                  key={pattern.id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => handleOpenPattern(pattern.id)}
                >
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      {healthData[pattern.id] && (
                        <HealthStatusIcon status={healthData[pattern.id]} />
                      )}
                      {pattern.name}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {pattern.pattern}
                  </TableCell>
                  <TableCell>
                    <Badge
                      className={
                        pattern.mode === 'push'
                          ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                          : 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
                      }
                    >
                      {pattern.mode === 'push' ? 'Push' : `Pull (${pattern.poll_interval_minutes}m)`}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className="text-sm text-muted-foreground">
                      {pattern.last_edited_by || '—'}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span
                      className="text-sm text-muted-foreground"
                      title={new Date(pattern.updated_at).toLocaleString()}
                    >
                      {formatRelativeTime(pattern.updated_at)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Delete pattern"
                        onClick={() => openDeleteDialog(pattern.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Token Details Dialog */}
      <Dialog open={!!tokenDetailsPattern} onOpenChange={() => setTokenDetailsPattern(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>
              {tokenDetailsPattern?.mode === 'pull' ? 'Pull Mode Configuration' : 'Log Shipping Configuration'}
            </DialogTitle>
            <DialogDescription>
              {tokenDetailsPattern?.mode === 'pull'
                ? `This pattern polls OpenSearch every ${tokenDetailsPattern?.poll_interval_minutes} minutes for new logs.`
                : `Use this token to authenticate log shipping requests for "${tokenDetailsPattern?.name}"`}
            </DialogDescription>
          </DialogHeader>

          {tokenDetailsPattern && tokenDetailsPattern.mode === 'pull' && (
            <div className="space-y-4 py-4">
              <div className="p-3 bg-muted rounded-md space-y-2">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  <span className="font-medium text-sm">Pull Mode Active</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  CHAD automatically queries OpenSearch for logs matching the pattern "{tokenDetailsPattern.pattern}"
                  every {tokenDetailsPattern.poll_interval_minutes} minutes. No log shipping configuration is needed.
                </p>
              </div>
              <p className="text-xs text-muted-foreground">
                To change to push mode, edit this index pattern and select "Push" as the detection mode.
              </p>
            </div>
          )}

          {tokenDetailsPattern && tokenDetailsPattern.mode !== 'pull' && (
            <div className="space-y-4 py-4">
              {/* Fluentd Endpoints */}
              <div className="space-y-3">
                <Label className="text-sm font-medium">Fluentd Endpoints</Label>

                {/* Standard (Synchronous) Endpoint */}
                <div className="space-y-1.5">
                  <div className="text-xs text-muted-foreground font-medium">Standard (Synchronous)</div>
                  <div className="flex gap-2">
                    <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                      POST {window.location.origin}/api/logs/{getIndexSuffix(tokenDetailsPattern.percolator_index)}
                    </code>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(
                        `${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}`,
                        `${tokenDetailsPattern.id}-url-sync`
                      )}
                    >
                      {copiedToken === `${tokenDetailsPattern.id}-url-sync` ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Returns 200 OK with match count after processing completes. Best for lower volume, real-time alerting, and testing.
                  </p>
                </div>

                {/* Queue (Asynchronous) Endpoint - Recommended */}
                <div className="space-y-1.5 p-3 border rounded-lg bg-muted/30">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium">Queue (Asynchronous)</span>
                    <span className="text-xs text-green-600 dark:text-green-400 font-medium">Recommended for Production</span>
                  </div>
                  <div className="flex gap-2">
                    <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                      POST {window.location.origin}/api/logs/{getIndexSuffix(tokenDetailsPattern.percolator_index)}/queue
                    </code>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(
                        `${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}/queue`,
                        `${tokenDetailsPattern.id}-url-queue`
                      )}
                    >
                      {copiedToken === `${tokenDetailsPattern.id}-url-queue` ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Returns 202 Accepted immediately, processes in background. Best for high volume production deployments with backpressure handling, dead letter queue, and retry logic.
                  </p>
                </div>

                <p className="text-xs text-muted-foreground italic">
                  Both endpoints accept the same payload format. Use /queue for production deployments to handle traffic spikes gracefully.
                </p>
              </div>

              {/* Auth Token */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Auth Token</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 text-xs"
                    onClick={() => setRegenerateId(tokenDetailsPattern.id)}
                  >
                    <RefreshCw className="h-3 w-3 mr-1" />
                    Regenerate
                  </Button>
                </div>
                <div className="flex gap-2">
                  <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                    {visibleTokens.has(tokenDetailsPattern.id)
                      ? tokenDetailsPattern.auth_token
                      : `${'*'.repeat(20)}...${tokenDetailsPattern.auth_token.slice(-4)}`
                    }
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => toggleTokenVisibility(tokenDetailsPattern.id)}
                  >
                    {visibleTokens.has(tokenDetailsPattern.id) ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(tokenDetailsPattern.auth_token, `${tokenDetailsPattern.id}-token`)}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-token` ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Example curl command */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Example Request</Label>
                <div className="relative">
                  <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap">
{`curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\
  -H "Authorization: Bearer ${visibleTokens.has(tokenDetailsPattern.id) ? tokenDetailsPattern.auth_token : '<your-token>'}" \\
  -H "Content-Type: application/json" \\
  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`}
                  </pre>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-2 right-2 h-6 w-6"
                    onClick={() => copyToClipboard(
                      `curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\\n  -H "Authorization: Bearer ${tokenDetailsPattern.auth_token}" \\\n  -H "Content-Type: application/json" \\\n  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`,
                      `${tokenDetailsPattern.id}-curl`
                    )}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-curl` ? (
                      <Check className="h-3 w-3 text-green-500" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </Button>
                </div>
              </div>

              <p className="text-xs text-muted-foreground">
                Send a JSON array of log documents to this endpoint. Each log will be matched against deployed rules and alerts will be generated for matches.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setTokenDetailsPattern(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Index Pattern</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this index pattern? This action
              cannot be undone. Rules using this pattern will need to be
              reassigned.
            </DialogDescription>
          </DialogHeader>
          {deleteError && (
            <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
              {deleteError}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Regenerate Token Confirmation Dialog */}
      <Dialog open={!!regenerateId} onOpenChange={() => setRegenerateId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate Auth Token</DialogTitle>
            <DialogDescription>
              Are you sure you want to regenerate the auth token? This will
              immediately invalidate the existing token. Any log shippers using
              the old token will stop working until updated with the new token.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegenerateId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRegenerateToken}
              disabled={isRegenerating}
            >
              {isRegenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Regenerating...
                </>
              ) : (
                'Regenerate Token'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
