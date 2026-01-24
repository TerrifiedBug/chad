import { useState } from 'react'
import { DateRange } from 'react-day-picker'
import { format, subDays } from 'date-fns'
import { Play, ChevronDown, ChevronUp, AlertCircle, Clock, Database, FileSearch, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { DateRangePicker } from '@/components/ui/date-range-picker'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { rulesApi } from '@/lib/api'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'

interface HistoricalTestPanelProps {
  ruleId: string
  onClose?: () => void
}

interface HistoricalTestResult {
  total_scanned: number
  total_matches: number
  matches: Array<{ _id: string; _index: string; _source: Record<string, unknown> }>
  truncated: boolean
  error?: string
}

export function HistoricalTestPanel({ ruleId, onClose: _onClose }: HistoricalTestPanelProps) {
  // Default to last 7 days
  const [dateRange, setDateRange] = useState<DateRange | undefined>({
    from: subDays(new Date(), 7),
    to: new Date(),
  })
  const [limit, setLimit] = useState(500)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<HistoricalTestResult | null>(null)
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [currentPage, setCurrentPage] = useState(1)
  const pageSize = 10

  const handleRunTest = async () => {
    if (!dateRange?.from || !dateRange?.to) {
      setError('Please select both start and end dates')
      return
    }

    setIsLoading(true)
    setError(null)
    setResults(null)
    setExpandedRows(new Set())
    setCurrentPage(1)

    try {
      const result = await rulesApi.testHistorical(
        ruleId,
        dateRange.from,
        dateRange.to,
        limit
      )

      if (result.error) {
        setError(result.error)
      } else {
        setResults(result)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run historical test')
    } finally {
      setIsLoading(false)
    }
  }

  const toggleRowExpand = (id: string) => {
    const newExpanded = new Set(expandedRows)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedRows(newExpanded)
  }

  const exportToCsv = () => {
    if (!results || results.matches.length === 0) return

    // Build CSV header
    const allKeys = new Set<string>()
    results.matches.forEach((match) => {
      Object.keys(match._source).forEach((key) => allKeys.add(key))
    })
    const headers = ['_id', '_index', ...Array.from(allKeys).sort()]

    // Build CSV rows
    const rows = results.matches.map((match) => {
      const row = [match._id, match._index]
      Array.from(allKeys).sort().forEach((key) => {
        const value = match._source[key]
        if (value === undefined || value === null) {
          row.push('')
        } else if (typeof value === 'object') {
          row.push(JSON.stringify(value).replace(/"/g, '""'))
        } else {
          row.push(String(value).replace(/"/g, '""'))
        }
      })
      return row.map((cell) => `"${cell}"`).join(',')
    })

    // Create CSV content
    const csvContent = [headers.map((h) => `"${h}"`).join(','), ...rows].join('\n')

    // Download file
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.setAttribute('href', url)
    link.setAttribute('download', `historical-test-results-${format(new Date(), 'yyyy-MM-dd-HHmmss')}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const getTimestampFromSource = (source: Record<string, unknown>): string | null => {
    // Try common timestamp field names
    const timestampFields = ['@timestamp', 'timestamp', 'time', 'created_at', 'date']
    for (const field of timestampFields) {
      const value = source[field]
      if (typeof value === 'string') {
        try {
          return format(new Date(value), 'MMM dd, yyyy HH:mm:ss')
        } catch {
          // Invalid date format, continue to next field
        }
      }
    }
    return null
  }

  // Pagination
  const totalPages = results ? Math.ceil(results.matches.length / pageSize) : 0
  const paginatedMatches = results
    ? results.matches.slice((currentPage - 1) * pageSize, currentPage * pageSize)
    : []

  return (
    <div className="space-y-4">
        {/* Configuration Section */}
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="space-y-2 flex-1">
            <Label>Date Range</Label>
            <DateRangePicker
              value={dateRange}
              onChange={setDateRange}
            />
          </div>
          <div className="space-y-2 sm:w-32">
            <Label htmlFor="limit">Result Limit</Label>
            <Input
              id="limit"
              type="number"
              min={1}
              max={1000}
              value={limit}
              onChange={(e) => setLimit(Math.min(1000, Math.max(1, parseInt(e.target.value) || 500)))}
              placeholder="500"
            />
          </div>
        </div>

        {/* Run Button */}
        <Button
          onClick={handleRunTest}
          disabled={isLoading || !dateRange?.from || !dateRange?.to}
          className="w-full md:w-auto"
        >
          {isLoading ? (
            <>
              <Clock className="mr-2 h-4 w-4 animate-spin" />
              Running Test...
            </>
          ) : (
            <>
              <Play className="mr-2 h-4 w-4" />
              Run Historical Test
            </>
          )}
        </Button>

        {/* Error Display */}
        {error && (
          <div className="flex items-center gap-2 p-3 text-sm text-destructive bg-destructive/10 rounded-md">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Results Section */}
        {results && (
          <div className="space-y-4 pt-4 border-t">
            {/* Results Header with Export Button */}
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium">Test Results</h4>
              {results.matches.length > 0 && (
                <Button variant="outline" size="sm" onClick={exportToCsv}>
                  <Download className="h-4 w-4 mr-2" />
                  Export CSV
                </Button>
              )}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-muted rounded-md">
                <div className="text-2xl font-bold">{results.total_scanned.toLocaleString()}</div>
                <div className="text-xs text-muted-foreground">Documents Scanned</div>
              </div>
              <div className="text-center p-3 bg-muted rounded-md">
                <div className="text-2xl font-bold text-green-600">{results.total_matches.toLocaleString()}</div>
                <div className="text-xs text-muted-foreground">Matches Found</div>
              </div>
              <div className="text-center p-3 bg-muted rounded-md">
                <div className="text-2xl font-bold">
                  {results.total_scanned > 0
                    ? ((results.total_matches / results.total_scanned) * 100).toFixed(2)
                    : 0}%
                </div>
                <div className="text-xs text-muted-foreground">Match Rate</div>
              </div>
            </div>

            {/* Truncation Warning */}
            {results.truncated && (
              <div className="flex items-center gap-2 p-3 text-sm text-amber-600 bg-amber-50 dark:bg-amber-950/20 rounded-md">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>Results truncated to {limit} matches. Increase the limit to see more.</span>
              </div>
            )}

            {/* Results Table */}
            {results.matches.length > 0 && (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10"></TableHead>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Index</TableHead>
                      <TableHead>Document ID</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {paginatedMatches.map((match) => (
                      <Collapsible key={match._id} asChild open={expandedRows.has(match._id)}>
                        <>
                          <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => toggleRowExpand(match._id)}>
                            <TableCell>
                              <CollapsibleTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={(e) => {
                                  e.stopPropagation()
                                  toggleRowExpand(match._id)
                                }}>
                                  {expandedRows.has(match._id) ? (
                                    <ChevronUp className="h-4 w-4" />
                                  ) : (
                                    <ChevronDown className="h-4 w-4" />
                                  )}
                                </Button>
                              </CollapsibleTrigger>
                            </TableCell>
                            <TableCell className="font-mono text-sm">
                              {getTimestampFromSource(match._source) || (
                                <span className="text-muted-foreground">N/A</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className="font-mono">
                                <Database className="h-3 w-3 mr-1" />
                                {match._index}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-sm text-muted-foreground">
                              {match._id.length > 20 ? `${match._id.slice(0, 20)}...` : match._id}
                            </TableCell>
                          </TableRow>
                          <CollapsibleContent asChild>
                            <TableRow className="bg-muted/30 hover:bg-muted/30">
                              <TableCell colSpan={4} className="p-0">
                                <div className="p-4">
                                  <div className="text-xs font-medium text-muted-foreground mb-2">
                                    Document Source
                                  </div>
                                  <pre className="text-xs bg-muted p-3 rounded-md overflow-auto max-h-64">
                                    {JSON.stringify(match._source, null, 2)}
                                  </pre>
                                </div>
                              </TableCell>
                            </TableRow>
                          </CollapsibleContent>
                        </>
                      </Collapsible>
                    ))}
                  </TableBody>
                </Table>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between p-4 border-t">
                    <div className="text-sm text-muted-foreground">
                      Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, results.matches.length)} of {results.matches.length} matches
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                      >
                        Previous
                      </Button>
                      <span className="text-sm text-muted-foreground">
                        Page {currentPage} of {totalPages}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                        disabled={currentPage === totalPages}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* No Matches Message */}
            {results.matches.length === 0 && results.total_scanned > 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <FileSearch className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No matches found in the selected date range.</p>
                <p className="text-sm">
                  {results.total_scanned.toLocaleString()} documents were scanned.
                </p>
              </div>
            )}

            {/* No Documents Message */}
            {results.total_scanned === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <Database className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No documents found in the selected date range.</p>
                <p className="text-sm">
                  Try expanding the date range or check the index pattern configuration.
                </p>
              </div>
            )}
          </div>
        )}
    </div>
  )
}
