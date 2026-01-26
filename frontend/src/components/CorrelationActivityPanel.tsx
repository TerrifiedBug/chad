import { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import { TimestampTooltip } from './timestamp-tooltip'

interface CorrelationActivityPanelProps {
  correlationId: string
}

interface AuditItem {
  id: string
  action: string
  user_email: string | null
  created_at: string
  details: Record<string, unknown>
}

export function CorrelationActivityPanel({ correlationId }: CorrelationActivityPanelProps) {
  const [activities, setActivities] = useState<AuditItem[]>([])
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    const abortController = new AbortController()

    const loadActivity = async () => {
      if (!correlationId) return
      setIsLoading(true)
      try {
        const data = await api.get<{ items: AuditItem[] }>(
          `/audit?resource_type=correlation_rule&resource_id=${correlationId}&limit=10`
        )
        if (!abortController.signal.aborted) {
          setActivities(data.items || [])
        }
      } catch (err) {
        if (!abortController.signal.aborted) {
          console.error('Failed to load activity:', err)
        }
      } finally {
        if (!abortController.signal.aborted) {
          setIsLoading(false)
        }
      }
    }

    loadActivity()

    return () => abortController.abort()
  }, [correlationId])

  return (
    <div className="space-y-3">
      <h4 className="font-semibold">Activity Log</h4>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading activity...</p>
      ) : activities.length === 0 ? (
        <p className="text-sm text-muted-foreground">No activity yet</p>
      ) : (
        <div className="space-y-2">
          {activities.map((activity) => (
            <div key={activity.id} className="text-sm p-3 bg-muted rounded">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium">{formatActivityAction(activity.action)}</span>
                <span className="text-muted-foreground">by {activity.user_email || 'Unknown'}</span>
              </div>
              <TimestampTooltip timestamp={activity.created_at}>
                <span className="text-xs text-muted-foreground">
                  {activity.created_at}
                </span>
              </TimestampTooltip>
            </div>
          ))}
        </div>
      )}

      {activities.length > 0 && (
        <button
          onClick={() => (window.location.href = `/settings/audit?resource_type=correlation_rule&resource_id=${correlationId}`)}
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
