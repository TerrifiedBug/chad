import { useQuery } from '@tanstack/react-query'
import { mispApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'

type MISPOriginPanelProps = {
  ruleId: string
}

export function MISPOriginPanel({ ruleId }: MISPOriginPanelProps) {
  const { data: mispInfo, isLoading } = useQuery({
    queryKey: ['rule-misp-info', ruleId],
    queryFn: () => mispApi.getRuleMISPInfo(ruleId),
  })

  if (isLoading || !mispInfo) {
    return null
  }

  const mispEventUrl = `${mispInfo.misp_url}/events/view/${mispInfo.misp_event_id}`

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          MISP Origin
          {mispInfo.has_updates && (
            <Badge variant="outline" className="text-yellow-600">
              Updates Available
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div>
          <span className="text-muted-foreground">Event:</span>{' '}
          <span className="font-medium">{mispInfo.misp_event_info}</span>
        </div>

        <div className="flex items-center gap-4">
          <div>
            <span className="text-muted-foreground">Event ID:</span>{' '}
            {mispInfo.misp_event_id}
          </div>
          {mispInfo.misp_event_threat_level && (
            <Badge
              variant={
                mispInfo.misp_event_threat_level === 'High'
                  ? 'destructive'
                  : mispInfo.misp_event_threat_level === 'Medium'
                  ? 'default'
                  : 'secondary'
              }
            >
              {mispInfo.misp_event_threat_level}
            </Badge>
          )}
        </div>

        <div>
          <span className="text-muted-foreground">IOCs:</span>{' '}
          {mispInfo.ioc_count} {mispInfo.ioc_type}
        </div>

        <div>
          <span className="text-muted-foreground">Imported:</span>{' '}
          {format(new Date(mispInfo.imported_at), 'PPp')}
        </div>

        <div className="flex gap-2 pt-2">
          <Button variant="outline" size="sm" asChild>
            <a href={mispEventUrl} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="h-4 w-4 mr-1" />
              View in MISP
            </a>
          </Button>
          <Button variant="outline" size="sm" disabled>
            <RefreshCw className="h-4 w-4 mr-1" />
            Check for Updates
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
