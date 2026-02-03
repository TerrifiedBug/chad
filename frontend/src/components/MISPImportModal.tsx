import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { mispApi, type MISPEventSummary, type MISPAttribute, type IndexPattern } from '@/lib/api'
import { api } from '@/lib/api'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { ChevronRight, ChevronDown, AlertTriangle, Loader2 } from 'lucide-react'

type MISPImportModalProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function MISPImportModal({ open, onOpenChange }: MISPImportModalProps) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [searchTerm, setSearchTerm] = useState('')
  const [threatLevels, setThreatLevels] = useState<number[]>([1, 2])
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [selectedIOCs, setSelectedIOCs] = useState<Record<string, Set<string>>>({})
  const [selectedIndexPattern, setSelectedIndexPattern] = useState<string>('')

  // Fetch events
  const { data: events, isLoading: eventsLoading, error: eventsError } = useQuery({
    queryKey: ['misp-events', searchTerm, threatLevels],
    queryFn: () => mispApi.searchEvents({
      limit: 50,
      threat_levels: threatLevels.join(','),
      search_term: searchTerm || undefined,
    }),
    enabled: open,
  })

  // Fetch IOCs when event is expanded
  const { data: eventIOCs, isLoading: iocsLoading } = useQuery({
    queryKey: ['misp-event-iocs', expandedEvent],
    queryFn: () => mispApi.getEventIOCs(expandedEvent!),
    enabled: !!expandedEvent,
  })

  // Fetch index patterns
  const { data: indexPatterns } = useQuery({
    queryKey: ['index-patterns'],
    queryFn: () => api.get<IndexPattern[]>('/index-patterns'),
    enabled: open,
  })

  // Fetch supported IOC types
  const { data: supportedTypes } = useQuery({
    queryKey: ['misp-supported-types'],
    queryFn: () => mispApi.getSupportedTypes(),
    enabled: open,
  })

  // Import mutation
  const importMutation = useMutation({
    mutationFn: mispApi.importRule,
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      onOpenChange(false)
      navigate(`/rules/${response.rule_id}`)
    },
  })

  const handleEventToggle = (eventId: string) => {
    setExpandedEvent(expandedEvent === eventId ? null : eventId)
  }

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

  const isTypeSupported = (type: string) => {
    return supportedTypes?.types.includes(type) ?? false
  }

  const getSelectedCount = (eventId: string, iocType: string) => {
    const key = `${eventId}:${iocType}`
    return selectedIOCs[key]?.size || 0
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Import from MISP</DialogTitle>
        </DialogHeader>

        <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800">
          <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-500 shrink-0" />
          <p className="text-sm text-yellow-800 dark:text-yellow-200">
            Auto-generated rules may produce false positives. Review field mappings and test before deploying.
          </p>
        </div>

        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-4 items-center">
            <Input
              placeholder="Search events..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1"
            />
            <Select
              value={selectedIndexPattern}
              onValueChange={setSelectedIndexPattern}
            >
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Select index pattern" />
              </SelectTrigger>
              <SelectContent>
                {indexPatterns?.map((ip) => (
                  <SelectItem key={ip.id} value={ip.id}>
                    {ip.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex gap-4 items-center text-sm">
            <span>Threat Level:</span>
            {[
              { id: 1, label: 'High' },
              { id: 2, label: 'Medium' },
              { id: 3, label: 'Low' },
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

          {/* Events List */}
          {eventsLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}

          {eventsError && (
            <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm">
              Failed to load events: {(eventsError as Error).message}
            </div>
          )}

          {events && events.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              No events found matching your criteria
            </div>
          )}

          <div className="space-y-2">
            {events?.map((event: MISPEventSummary) => (
              <Collapsible
                key={event.id}
                open={expandedEvent === event.id}
                onOpenChange={() => handleEventToggle(event.id)}
              >
                <CollapsibleTrigger className="w-full">
                  <div className="flex items-center gap-2 p-3 border rounded-lg hover:bg-accent text-left">
                    {expandedEvent === event.id ? (
                      <ChevronDown className="h-4 w-4 shrink-0" />
                    ) : (
                      <ChevronRight className="h-4 w-4 shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="font-medium truncate">{event.info}</div>
                      <div className="text-sm text-muted-foreground truncate">
                        {Object.entries(event.ioc_summary)
                          .map(([type, count]) => `${count} ${type}`)
                          .join(', ')}
                      </div>
                    </div>
                    <div className="text-sm text-muted-foreground shrink-0">{event.date}</div>
                    <Badge
                      variant={
                        event.threat_level === 'High'
                          ? 'destructive'
                          : event.threat_level === 'Medium'
                          ? 'default'
                          : 'secondary'
                      }
                    >
                      {event.threat_level}
                    </Badge>
                  </div>
                </CollapsibleTrigger>

                <CollapsibleContent>
                  <div className="ml-6 mt-2 space-y-3 border-l pl-4">
                    {iocsLoading && (
                      <div className="flex items-center gap-2 py-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading IOCs...
                      </div>
                    )}

                    {eventIOCs &&
                      Object.entries(eventIOCs.iocs_by_type).map(([iocType, iocs]) => (
                        <div key={iocType} className="border rounded p-3">
                          <div className="flex items-center justify-between mb-2">
                            <div className="font-medium">
                              {iocType} ({iocs.length})
                              {!isTypeSupported(iocType) && (
                                <span className="text-muted-foreground text-sm ml-2">
                                  (unsupported)
                                </span>
                              )}
                            </div>
                            {isTypeSupported(iocType) && (
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
                                ) : null}
                                + Add as Rule ({getSelectedCount(event.id, iocType)})
                              </Button>
                            )}
                          </div>

                          <div className="space-y-1 max-h-40 overflow-y-auto">
                            {(iocs as MISPAttribute[]).map((ioc) => (
                              <label
                                key={ioc.id}
                                className={`flex items-center gap-2 text-sm p-1 rounded cursor-pointer ${
                                  ioc.on_warning_list
                                    ? 'bg-yellow-50 dark:bg-yellow-900/20'
                                    : ''
                                }`}
                              >
                                <Checkbox
                                  checked={selectedIOCs[
                                    `${event.id}:${iocType}`
                                  ]?.has(ioc.value)}
                                  onCheckedChange={() =>
                                    handleIOCToggle(event.id, iocType, ioc.value)
                                  }
                                  disabled={
                                    !isTypeSupported(iocType) || ioc.on_warning_list
                                  }
                                />
                                <span className="font-mono text-xs truncate flex-1">
                                  {ioc.value}
                                </span>
                                {ioc.on_warning_list && (
                                  <Badge variant="outline" className="text-xs shrink-0">
                                    {ioc.warning_list_name || 'warning list'}
                                  </Badge>
                                )}
                              </label>
                            ))}
                          </div>
                        </div>
                      ))}
                  </div>
                </CollapsibleContent>
              </Collapsible>
            ))}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
