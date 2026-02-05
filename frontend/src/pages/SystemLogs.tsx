import { useEffect, useState, useCallback, useRef } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { systemLogsApi, SystemLogEntry, SystemLogListResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { AlertCircle, AlertTriangle, ChevronDown, ChevronRight, RefreshCw, Search } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'
import { cn } from '@/lib/utils'

const PAGE_SIZE = 50

const TIME_RANGES = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '14d', label: 'Last 14 days' },
]

const CATEGORIES = [
  { value: 'all', label: 'All Categories' },
  { value: 'opensearch', label: 'OpenSearch' },
  { value: 'alerts', label: 'Alerts' },
  { value: 'pull_mode', label: 'Pull Mode' },
  { value: 'integrations', label: 'Integrations' },
  { value: 'background', label: 'Background' },
]

const LEVELS = [
  { value: 'all', label: 'All Levels' },
  { value: 'error', label: 'Errors Only' },
  { value: 'warning', label: 'Warnings Only' },
]

function getTimeRange(range: string): { start: Date; end: Date } {
  const now = new Date()
  const end = now
  let start: Date

  switch (range) {
    case '1h':
      start = new Date(now.getTime() - 60 * 60 * 1000)
      break
    case '7d':
      start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
      break
    case '14d':
      start = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000)
      break
    case '24h':
    default:
      start = new Date(now.getTime() - 24 * 60 * 60 * 1000)
  }

  return { start, end }
}

interface LogEntryRowProps {
  entry: SystemLogEntry
  isNew?: boolean
}

function LogEntryRow({ entry, isNew }: LogEntryRowProps) {
  const [isOpen, setIsOpen] = useState(false)
  const isError = entry.level === 'ERROR'

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div
        className={cn(
          'border-b py-3 px-4 transition-colors',
          isNew && 'bg-primary/5 animate-pulse'
        )}
      >
        <CollapsibleTrigger className="w-full text-left">
          <div className="flex items-start gap-3">
            {isError ? (
              <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
            )}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <TooltipProvider>
                  <TimestampTooltip timestamp={entry.timestamp}>
                    <span>{formatDistanceToNow(new Date(entry.timestamp), { addSuffix: true })}</span>
                  </TimestampTooltip>
                </TooltipProvider>
                <span className="text-muted-foreground/60">·</span>
                <span>{entry.category}</span>
                <span className="text-muted-foreground/60">/</span>
                <span>{entry.service}</span>
              </div>
              <p className="text-sm mt-1">{entry.message}</p>
            </div>
            {entry.details && (
              <div className="flex-shrink-0">
                {isOpen ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
              </div>
            )}
          </div>
        </CollapsibleTrigger>
        {entry.details && (
          <CollapsibleContent>
            <div className="mt-3 ml-8 p-3 bg-muted rounded-md">
              <pre className="text-xs overflow-x-auto">
                {JSON.stringify(entry.details, null, 2)}
              </pre>
            </div>
          </CollapsibleContent>
        )}
      </div>
    </Collapsible>
  )
}

export default function SystemLogsPage() {
  const [logsData, setLogsData] = useState<SystemLogListResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Filters
  const [timeRange, setTimeRange] = useState('24h')
  const [levelFilter, setLevelFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [currentPage, setCurrentPage] = useState(0)

  // Live Tail
  const [liveTail, setLiveTail] = useState(false)
  const [newLogIds, setNewLogIds] = useState<Set<string>>(new Set())
  const wsRef = useRef<WebSocket | null>(null)

  const loadLogs = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const { start, end } = getTimeRange(timeRange)
      const params: Parameters<typeof systemLogsApi.list>[0] = {
        start_time: start.toISOString(),
        end_time: end.toISOString(),
        limit: PAGE_SIZE,
        offset: currentPage * PAGE_SIZE,
      }
      if (levelFilter !== 'all') params.level = levelFilter
      if (categoryFilter !== 'all') params.category = categoryFilter
      if (searchQuery) params.search = searchQuery

      const data = await systemLogsApi.list(params)
      setLogsData(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load system logs')
    } finally {
      setIsLoading(false)
    }
  }, [timeRange, levelFilter, categoryFilter, searchQuery, currentPage])

  // Initial load and filter changes
  useEffect(() => {
    loadLogs()
  }, [loadLogs])

  // WebSocket for Live Tail
  useEffect(() => {
    if (!liveTail) {
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      return
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        if (message.type === 'system_log') {
          const newLog = message.data as SystemLogEntry
          setLogsData((prev) => {
            if (!prev) return prev
            // Add to top of list
            const newItems = [newLog, ...prev.items.slice(0, PAGE_SIZE - 1)]
            return { ...prev, items: newItems, total: prev.total + 1 }
          })
          // Mark as new for animation
          setNewLogIds((prev) => new Set(prev).add(newLog.id))
          setTimeout(() => {
            setNewLogIds((prev) => {
              const next = new Set(prev)
              next.delete(newLog.id)
              return next
            })
          }, 3000)
        }
      } catch {
        // Ignore parse errors
      }
    }

    ws.onerror = () => {
      wsRef.current = null
    }

    return () => {
      if (wsRef.current === ws) {
        ws.close()
        wsRef.current = null
      }
    }
  }, [liveTail])

  const totalPages = logsData ? Math.ceil(logsData.total / PAGE_SIZE) : 0

  return (
    <div className="space-y-6">
      {/* Refresh button */}
      <div className="flex justify-end">
        <Button variant="outline" size="sm" onClick={loadLogs} disabled={isLoading}>
          <RefreshCw className={cn('h-4 w-4 mr-2', isLoading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4 items-end">
            <div className="space-y-2">
              <Label>Time Range</Label>
              <Select value={timeRange} onValueChange={(v) => { setTimeRange(v); setCurrentPage(0); }}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TIME_RANGES.map((r) => (
                    <SelectItem key={r.value} value={r.value}>
                      {r.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Level</Label>
              <Select value={levelFilter} onValueChange={(v) => { setLevelFilter(v); setCurrentPage(0); }}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {LEVELS.map((l) => (
                    <SelectItem key={l.value} value={l.value}>
                      {l.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Category</Label>
              <Select value={categoryFilter} onValueChange={(v) => { setCategoryFilter(v); setCurrentPage(0); }}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c.value} value={c.value}>
                      {c.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2 flex-1 min-w-[200px]">
              <Label>Search</Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search messages..."
                  value={searchQuery}
                  onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(0); }}
                  className="pl-9"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Switch
                id="live-tail"
                checked={liveTail}
                onCheckedChange={setLiveTail}
              />
              <Label htmlFor="live-tail" className="cursor-pointer">
                Live Tail
              </Label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Log Entries */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {logsData ? `${logsData.total} entries` : 'Loading...'}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading && !logsData ? (
            <LoadingState message="Loading system logs..." />
          ) : error ? (
            <div className="p-6 text-center text-destructive">{error}</div>
          ) : !logsData?.items.length ? (
            <EmptyState
              icon={<AlertCircle className="h-12 w-12" />}
              title="No log entries"
              description="No system log entries found matching your filters."
            />
          ) : (
            <div className="divide-y">
              {logsData.items.map((entry) => (
                <LogEntryRow
                  key={entry.id}
                  entry={entry}
                  isNew={newLogIds.has(entry.id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {currentPage * PAGE_SIZE + 1} to{' '}
            {Math.min((currentPage + 1) * PAGE_SIZE, logsData?.total || 0)} of{' '}
            {logsData?.total || 0}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => Math.max(0, p - 1))}
              disabled={currentPage === 0}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => p + 1)}
              disabled={currentPage >= totalPages - 1}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
