import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { mispApi, type MISPEventSummary, type MISPAttribute, type IndexPattern } from '@/lib/api'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Loader2,
  Search,
  Calendar,
  Shield,
  ExternalLink,
  Plus,
  RefreshCw,
  Filter,
} from 'lucide-react'
import { LoadingState } from '@/components/ui/loading-state'

const IOCS_PER_PAGE = 100

export default function MISPPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [searchTerm, setSearchTerm] = useState('')
  const [threatLevels, setThreatLevels] = useState<number[]>([1, 2, 3, 4])
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [selectedIOCs, setSelectedIOCs] = useState<Record<string, Set<string>>>({})
  const [selectedIndexPattern, setSelectedIndexPattern] = useState<string>('')
  const [selectedIOCType, setSelectedIOCType] = useState<string | null>(null)
  const [iocSearchTerm, setIocSearchTerm] = useState('')
  const [showAllIOCs, setShowAllIOCs] = useState(false)

  // Check MISP connection status
  const { data: mispStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
  })

  // Fetch index patterns
  const { data: indexPatterns } = useQuery({
    queryKey: ['index-patterns'],
    queryFn: () => api.get<IndexPattern[]>('/index-patterns'),
    enabled: mispStatus?.configured && mispStatus?.connected,
  })

  // Fetch events
  const {
    data: events,
    isLoading: eventsLoading,
    error: eventsError,
    refetch: refetchEvents,
  } = useQuery({
    queryKey: ['misp-events', searchTerm, threatLevels],
    queryFn: () =>
      mispApi.searchEvents({
        limit: 50,
        threat_levels: threatLevels.join(','),
        search_term: searchTerm || undefined,
      }),
    enabled: mispStatus?.configured && mispStatus?.connected,
  })

  // Fetch IOCs when event is expanded
  const { data: eventIOCs, isLoading: iocsLoading } = useQuery({
    queryKey: ['misp-event-iocs', expandedEvent],
    queryFn: () => mispApi.getEventIOCs(expandedEvent!),
    enabled: !!expandedEvent,
  })

  // Fetch supported IOC types
  const { data: supportedTypes } = useQuery({
    queryKey: ['misp-supported-types'],
    queryFn: () => mispApi.getSupportedTypes(),
    enabled: mispStatus?.configured && mispStatus?.connected,
  })

  // Import mutation
  const importMutation = useMutation({
    mutationFn: mispApi.importRule,
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      navigate(`/rules/${response.rule_id}`)
    },
  })

  // Get sorted IOC types for tabs
  const sortedIOCTypes = useMemo(() => {
    if (!eventIOCs?.iocs_by_type) return []
    return Object.entries(eventIOCs.iocs_by_type)
      .sort((a, b) => b[1].length - a[1].length)
      .map(([type, iocs]) => ({ type, count: iocs.length }))
  }, [eventIOCs])

  // Reset IOC type selection when event changes
  const handleEventToggle = (eventId: string) => {
    if (expandedEvent === eventId) {
      setExpandedEvent(null)
      setSelectedIOCType(null)
      setIocSearchTerm('')
      setShowAllIOCs(false)
    } else {
      setExpandedEvent(eventId)
      setSelectedIOCType(null)
      setIocSearchTerm('')
      setShowAllIOCs(false)
    }
  }

  // Auto-select first IOC type when IOCs load
  useMemo(() => {
    if (sortedIOCTypes.length > 0 && !selectedIOCType) {
      setSelectedIOCType(sortedIOCTypes[0].type)
    }
  }, [sortedIOCTypes, selectedIOCType])

  const handleIOCToggle = (eventId: string, iocType: string, iocValue: string) => {
    setSelectedIOCs((prev) => {
      const key = `${eventId}:${iocType}`
      const current = prev[key] || new Set()
      const updated = new Set(current)
      if (updated.has(iocValue)) {
        updated.delete(iocValue)
      } else {
        updated.add(iocValue)
      }
      return { ...prev, [key]: updated }
    })
  }

  const handleImport = (eventId: string, iocType: string) => {
    const key = `${eventId}:${iocType}`
    const values = Array.from(selectedIOCs[key] || [])

    if (values.length === 0 || !selectedIndexPattern) return

    importMutation.mutate({
      event_id: eventId,
      ioc_type: iocType,
      ioc_values: values,
      index_pattern_id: selectedIndexPattern,
    })
  }

  const handleSelectAll = (eventId: string, iocType: string, iocs: MISPAttribute[]) => {
    const key = `${eventId}:${iocType}`
    const validIOCs = iocs.filter((ioc) => !ioc.on_warning_list && isTypeSupported(iocType))
    setSelectedIOCs((prev) => ({
      ...prev,
      [key]: new Set(validIOCs.map((ioc) => ioc.value)),
    }))
  }

  const handleDeselectAll = (eventId: string, iocType: string) => {
    const key = `${eventId}:${iocType}`
    setSelectedIOCs((prev) => ({
      ...prev,
      [key]: new Set(),
    }))
  }

  const isTypeSupported = (type: string) => {
    return supportedTypes?.types.includes(type) ?? false
  }

  const getSelectedCount = (eventId: string, iocType: string) => {
    const key = `${eventId}:${iocType}`
    return selectedIOCs[key]?.size || 0
  }

  const getThreatLevelBadge = (level: string) => {
    switch (level) {
      case 'High':
        return <Badge variant="destructive">{level}</Badge>
      case 'Medium':
        return <Badge>{level}</Badge>
      default:
        return <Badge variant="secondary">{level}</Badge>
    }
  }

  // Filter and paginate IOCs
  const getFilteredIOCs = (iocs: MISPAttribute[]) => {
    let filtered = iocs
    if (iocSearchTerm) {
      const search = iocSearchTerm.toLowerCase()
      filtered = iocs.filter((ioc) => ioc.value.toLowerCase().includes(search))
    }
    if (!showAllIOCs && filtered.length > IOCS_PER_PAGE) {
      return { iocs: filtered.slice(0, IOCS_PER_PAGE), hasMore: true, total: filtered.length }
    }
    return { iocs: filtered, hasMore: false, total: filtered.length }
  }

  // Loading state
  if (statusLoading) {
    return <LoadingState message="Checking MISP connection..." />
  }

  // Not configured state
  if (!mispStatus?.configured) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold">MISP Integration</h1>
          <p className="text-muted-foreground">
            Import threat intelligence from MISP events as detection rules
          </p>
        </div>

        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              MISP Not Configured
            </CardTitle>
            <CardDescription>
              Connect to your MISP instance to browse events and import IOCs as Sigma detection
              rules.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Configure your MISP connection in Settings → Threat Intel to enable this feature.
            </p>
            <Button onClick={() => navigate('/settings')}>
              <ExternalLink className="h-4 w-4 mr-2" />
              Go to Settings
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Connection error state
  if (!mispStatus?.connected) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold">MISP Integration</h1>
          <p className="text-muted-foreground">
            Import threat intelligence from MISP events as detection rules
          </p>
        </div>

        <Card className="max-w-2xl border-destructive">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Connection Failed
            </CardTitle>
            <CardDescription>Unable to connect to your MISP instance.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {mispStatus?.error && (
              <div className="bg-destructive/10 text-destructive p-3 rounded-md text-sm font-mono">
                {mispStatus.error}
              </div>
            )}
            <p className="text-sm text-muted-foreground">
              Check your MISP URL, API key, and network connectivity in Settings → Threat Intel.
            </p>
            <Button onClick={() => navigate('/settings')}>
              <ExternalLink className="h-4 w-4 mr-2" />
              Go to Settings
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Main content - connected state
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">MISP Integration</h1>
          <p className="text-muted-foreground">
            Import threat intelligence from MISP events as detection rules
          </p>
        </div>
        <div className="flex items-center gap-4">
          {mispStatus?.instance_url && (
            <span className="text-sm text-muted-foreground">{mispStatus.instance_url}</span>
          )}
          <Button variant="outline" size="sm" onClick={() => refetchEvents()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Warning banner */}
      <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800">
        <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-500 shrink-0" />
        <p className="text-sm text-yellow-800 dark:text-yellow-200">
          Auto-generated rules may produce false positives. Review field mappings and test before
          deploying.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 items-center">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search events..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>

        <div className="flex gap-4 items-center text-sm">
          <span className="text-muted-foreground">Threat Level:</span>
          {[
            { id: 1, label: 'High' },
            { id: 2, label: 'Medium' },
            { id: 3, label: 'Low' },
            { id: 4, label: 'Undefined' },
          ].map(({ id, label }) => (
            <label key={id} className="flex items-center gap-1.5 cursor-pointer">
              <Checkbox
                checked={threatLevels.includes(id)}
                onCheckedChange={(checked) => {
                  setThreatLevels((prev) =>
                    checked ? [...prev, id] : prev.filter((l) => l !== id)
                  )
                }}
              />
              {label}
            </label>
          ))}
        </div>
      </div>

      {/* Index Pattern Selector */}
      <div className="flex items-center gap-4">
        <span className="text-sm font-medium">Target Index Pattern:</span>
        <Select value={selectedIndexPattern} onValueChange={setSelectedIndexPattern}>
          <SelectTrigger className="w-[300px]">
            <SelectValue placeholder="Select index pattern for rules" />
          </SelectTrigger>
          <SelectContent>
            {indexPatterns?.map((pattern) => (
              <SelectItem key={pattern.id} value={pattern.id}>
                {pattern.name} ({pattern.pattern})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {!selectedIndexPattern && (
          <span className="text-sm text-muted-foreground">
            Required to create rules
          </span>
        )}
      </div>

      {/* Events List */}
      <div className="border rounded-lg">
        <div className="p-3 border-b bg-muted/50">
          <h3 className="font-medium text-sm">Events {events && `(${events.length})`}</h3>
        </div>

        {eventsLoading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        )}

        {eventsError && (
          <div className="p-4 text-destructive text-sm">
            Failed to load events: {(eventsError as Error).message}
          </div>
        )}

        {events && events.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            No events found matching your criteria
          </div>
        )}

        <div className="divide-y">
          {events?.map((event: MISPEventSummary) => (
            <div key={event.id} className="hover:bg-muted/30">
              {/* Event header */}
              <button
                className="w-full text-left p-4 flex items-center gap-3"
                onClick={() => handleEventToggle(event.id)}
              >
                {expandedEvent === event.id ? (
                  <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="font-medium truncate">{event.info}</div>
                  <div className="text-sm text-muted-foreground flex items-center gap-4 mt-1">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      {event.date}
                    </span>
                    <span>
                      {Object.entries(event.ioc_summary)
                        .map(([type, count]) => `${count.toLocaleString()} ${type}`)
                        .join(', ')}
                    </span>
                  </div>
                </div>
                {getThreatLevelBadge(event.threat_level)}
              </button>

              {/* Expanded IOCs */}
              {expandedEvent === event.id && (
                <div className="px-4 pb-4 pt-2 ml-7 space-y-4 border-t bg-muted/20">
                  {iocsLoading && (
                    <div className="flex items-center gap-2 py-4">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span className="text-sm text-muted-foreground">Loading IOCs...</span>
                    </div>
                  )}

                  {eventIOCs && sortedIOCTypes.length > 0 && (
                    <>
                      {/* IOC Type Tabs */}
                      <Tabs
                        value={selectedIOCType || sortedIOCTypes[0].type}
                        onValueChange={(value) => {
                          setSelectedIOCType(value)
                          setIocSearchTerm('')
                          setShowAllIOCs(false)
                        }}
                      >
                        <TabsList className="flex-wrap h-auto gap-1">
                          {sortedIOCTypes.map(({ type, count }) => (
                            <TabsTrigger
                              key={type}
                              value={type}
                              className="text-xs"
                              disabled={!isTypeSupported(type)}
                            >
                              {type}
                              <Badge
                                variant={isTypeSupported(type) ? 'secondary' : 'outline'}
                                className="ml-1.5 text-xs px-1.5"
                              >
                                {count.toLocaleString()}
                              </Badge>
                            </TabsTrigger>
                          ))}
                        </TabsList>
                      </Tabs>

                      {/* Selected IOC Type Content */}
                      {selectedIOCType && eventIOCs.iocs_by_type[selectedIOCType] && (() => {
                        const iocType = selectedIOCType
                        const allIOCs = eventIOCs.iocs_by_type[iocType] as MISPAttribute[]
                        const { iocs, hasMore, total } = getFilteredIOCs(allIOCs)

                        return (
                          <div className="border rounded-lg bg-background">
                            <div className="p-3 border-b flex items-center justify-between gap-4">
                              <div className="flex items-center gap-2">
                                <div className="font-medium text-sm">
                                  {iocType}
                                  {!isTypeSupported(iocType) && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      unsupported
                                    </Badge>
                                  )}
                                </div>
                                <span className="text-sm text-muted-foreground">
                                  ({getSelectedCount(event.id, iocType)} selected of{' '}
                                  {total.toLocaleString()})
                                </span>
                              </div>

                              {isTypeSupported(iocType) && (
                                <div className="flex gap-2">
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() =>
                                      getSelectedCount(event.id, iocType) > 0
                                        ? handleDeselectAll(event.id, iocType)
                                        : handleSelectAll(event.id, iocType, allIOCs)
                                    }
                                  >
                                    {getSelectedCount(event.id, iocType) > 0
                                      ? 'Deselect All'
                                      : 'Select All'}
                                  </Button>
                                  <Button
                                    size="sm"
                                    onClick={() => handleImport(event.id, iocType)}
                                    disabled={
                                      getSelectedCount(event.id, iocType) === 0 ||
                                      !selectedIndexPattern ||
                                      importMutation.isPending
                                    }
                                  >
                                    {importMutation.isPending ? (
                                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                                    ) : (
                                      <Plus className="h-4 w-4 mr-1" />
                                    )}
                                    Create Rule ({getSelectedCount(event.id, iocType)})
                                  </Button>
                                </div>
                              )}
                            </div>

                            {/* IOC Search */}
                            {allIOCs.length > 20 && (
                              <div className="p-2 border-b">
                                <div className="relative">
                                  <Filter className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                  <Input
                                    placeholder={`Filter ${iocType}s...`}
                                    value={iocSearchTerm}
                                    onChange={(e) => setIocSearchTerm(e.target.value)}
                                    className="pl-10 h-8 text-sm"
                                  />
                                </div>
                              </div>
                            )}

                            <div className="p-2 max-h-80 overflow-y-auto">
                              <div className="grid gap-1">
                                {iocs.map((ioc) => (
                                  <label
                                    key={ioc.id}
                                    className={`flex items-center gap-2 text-sm p-2 rounded cursor-pointer hover:bg-muted/50 ${
                                      ioc.on_warning_list
                                        ? 'bg-yellow-50 dark:bg-yellow-900/20'
                                        : ''
                                    }`}
                                  >
                                    <Checkbox
                                      checked={selectedIOCs[`${event.id}:${iocType}`]?.has(
                                        ioc.value
                                      )}
                                      onCheckedChange={() =>
                                        handleIOCToggle(event.id, iocType, ioc.value)
                                      }
                                      disabled={!isTypeSupported(iocType) || ioc.on_warning_list}
                                    />
                                    <span className="font-mono text-xs break-all flex-1">
                                      {ioc.value}
                                    </span>
                                    {ioc.on_warning_list && (
                                      <Badge
                                        variant="outline"
                                        className="text-xs shrink-0 text-yellow-600"
                                      >
                                        {ioc.warning_list_name || 'warning list'}
                                      </Badge>
                                    )}
                                  </label>
                                ))}
                              </div>

                              {hasMore && (
                                <div className="mt-2 pt-2 border-t text-center">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => setShowAllIOCs(true)}
                                  >
                                    Show all {total.toLocaleString()} {iocType}s
                                  </Button>
                                </div>
                              )}
                            </div>
                          </div>
                        )
                      })()}
                    </>
                  )}

                  {importMutation.isError && (
                    <div className="p-3 rounded bg-destructive/10 text-destructive text-sm">
                      Import failed: {(importMutation.error as Error).message}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
