import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { IOCMatch, mispFeedbackApi, mispApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Loader2, Eye, XCircle, ExternalLink, ShieldAlert, ChevronDown } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'

const threatLevelColors: Record<string, string> = {
  high: 'bg-red-500 text-white',
  medium: 'bg-orange-500 text-white',
  low: 'bg-yellow-500 text-black',
  unknown: 'bg-gray-500 text-white',
}

interface IOCMatchesCardProps {
  matches: IOCMatch[]
}

export function IOCMatchesCard({ matches }: IOCMatchesCardProps) {
  const { showToast } = useToast()
  const [isOpen, setIsOpen] = useState(false)
  const [feedbackGiven, setFeedbackGiven] = useState<Record<string, 'sighting' | 'false_positive'>>({})

  // Check MISP status for linking
  const { data: mispStatus } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
  })

  const sightingMutation = useMutation({
    mutationFn: (data: { attribute_uuid: string; is_false_positive: boolean }) =>
      mispFeedbackApi.recordSighting({
        attribute_uuid: data.attribute_uuid,
        is_false_positive: data.is_false_positive,
      }),
    onSuccess: (result, variables) => {
      if (result.success) {
        const type = variables.is_false_positive ? 'false_positive' : 'sighting'
        setFeedbackGiven(prev => ({
          ...prev,
          [variables.attribute_uuid]: type,
        }))
        showToast(variables.is_false_positive ? 'Marked as false positive' : 'Sighting recorded')
      } else {
        showToast(result.error || 'Failed to record feedback', 'error')
      }
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Failed to record feedback', 'error')
    },
  })

  // Sort by threat level (high first)
  const sortedMatches = [...matches].sort((a, b) => {
    const order = ['high', 'medium', 'low', 'unknown']
    return order.indexOf(a.threat_level) - order.indexOf(b.threat_level)
  })

  // Count high threat matches
  const highThreatCount = matches.filter((m) => m.threat_level === 'high').length

  const getMISPEventUrl = (match: IOCMatch): string | null => {
    if (!mispStatus?.instance_url || !match.misp_event_id) return null
    return `${mispStatus.instance_url}/events/view/${match.misp_event_id}`
  }

  return (
    <Card>
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CollapsibleTrigger className="w-full">
          <CardHeader className="pb-3 hover:bg-muted/50 rounded-t-lg transition-colors">
            <CardTitle className="text-sm font-medium flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-500" />
                IOC Matches
                <Badge variant="destructive">
                  {matches.length}
                </Badge>
                {highThreatCount > 0 && (
                  <span className="text-xs text-red-600 font-normal">
                    {highThreatCount} high threat
                  </span>
                )}
              </div>
              <ChevronDown
                className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
              />
            </CardTitle>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="space-y-3 pt-0">
        {sortedMatches.map((match, idx) => {
          const key = match.misp_attribute_uuid || `${match.ioc_type}-${match.value}-${idx}`
          const feedback = match.misp_attribute_uuid ? feedbackGiven[match.misp_attribute_uuid] : null
          const eventUrl = getMISPEventUrl(match)
          const isPending = sightingMutation.isPending &&
            sightingMutation.variables?.attribute_uuid === match.misp_attribute_uuid

          return (
            <div key={key} className="border rounded-lg p-3 space-y-2">
              <div className="flex items-start justify-between">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-mono break-all">{match.value}</code>
                    <Badge className={`text-xs shrink-0 ${threatLevelColors[match.threat_level] || threatLevelColors.unknown}`}>
                      {match.threat_level}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {match.ioc_type} • {match.field_name}
                  </div>
                </div>
              </div>

              {match.misp_event_info && (
                <div className="text-sm">
                  <span className="text-muted-foreground">MISP Event: </span>
                  {eventUrl ? (
                    <a
                      href={eventUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center gap-1"
                    >
                      {match.misp_event_info}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  ) : (
                    <span>{match.misp_event_info}</span>
                  )}
                </div>
              )}

              {match.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {match.tags.map((tag) => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              )}

              {/* Feedback buttons */}
              {match.misp_attribute_uuid && !feedback && (
                <div className="grid grid-cols-2 gap-2 pt-2 border-t">
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full"
                    onClick={() => sightingMutation.mutate({
                      attribute_uuid: match.misp_attribute_uuid!,
                      is_false_positive: false,
                    })}
                    disabled={isPending}
                  >
                    {isPending && !sightingMutation.variables?.is_false_positive ? (
                      <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    ) : (
                      <Eye className="h-3 w-3 mr-1" />
                    )}
                    Record Sighting
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full"
                    onClick={() => sightingMutation.mutate({
                      attribute_uuid: match.misp_attribute_uuid!,
                      is_false_positive: true,
                    })}
                    disabled={isPending}
                  >
                    {isPending && sightingMutation.variables?.is_false_positive ? (
                      <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    ) : (
                      <XCircle className="h-3 w-3 mr-1" />
                    )}
                    False Positive
                  </Button>
                </div>
              )}

              {feedback && (
                <div className="pt-2 border-t text-sm text-muted-foreground">
                  {feedback === 'sighting' ? '✓ Sighting recorded' : '✓ Marked as false positive'}
                </div>
              )}
            </div>
          )
        })}
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  )
}
