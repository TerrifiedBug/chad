import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { TimestampTooltip } from './timestamp-tooltip'

interface CorrelationActivityPanelProps {
  correlationId: string
}

export function CorrelationActivityPanel({ correlationId }: CorrelationActivityPanelProps) {
  const { data: activities, isLoading } = useQuery({
    queryKey: ['correlation-activities', correlationId],
    queryFn: () => api.get<{ items: Array<any> }>(`/audit?entity_id=correlation_rule:${correlationId}&limit=10`),
    enabled: !!correlationId,
  })

  const items = activities?.items || []

  return (
    <div className="space-y-3">
      <h4 className="font-semibold">Activity Log</h4>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading activity...</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No activity yet</p>
      ) : (
        <div className="space-y-2">
          {items.map((activity) => (
            <div key={activity.id} className="text-sm p-3 bg-muted rounded">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium">{formatActivityAction(activity.action)}</span>
                <span className="text-muted-foreground">by {activity.username || 'Unknown'}</span>
              </div>
              <TimestampTooltip timestamp={activity.timestamp}>
                <span className="text-xs text-muted-foreground">
                  {activity.timestamp}
                </span>
              </TimestampTooltip>
            </div>
          ))}
        </div>
      )}

      {items.length > 0 && (
        <button
          onClick={() => (window.location.href = `/audit?entity_id=correlation_rule:${correlationId}`)}
          className="text-sm text-primary hover:underline"
        >
          Show full history →
        </button>
      )}
    </div>
  )
}

function formatActivityAction(action: string): string {
  const actions: Record<string, string> = {
    correlation_rule_created: 'Created this rule',
    correlation_rule_updated: 'Updated this rule',
    correlation_rule_deleted: 'Deleted this rule',
    correlation_rule_enabled: 'Enabled this rule',
    correlation_rule_disabled: 'Disabled this rule',
  }
  return actions[action] || action
}
