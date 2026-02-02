import { useState } from 'react'
import { useWebSocket } from '@/hooks/use-websocket'
import { useAuth } from '@/hooks/use-auth'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { RelativeTime } from '@/components/RelativeTime'
import { Activity, Wifi, WifiOff, Trash2, AlertCircle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { TooltipProvider } from '@/components/ui/tooltip'
import { SEVERITY_COLORS_SUBTLE } from '@/lib/constants'

export default function LiveAlertFeedPage() {
  const navigate = useNavigate()
  const { user, backendReady } = useAuth()
  const { isConnected, alerts, error, clearAlerts } = useWebSocket({
    notificationPreferences: user?.notification_preferences,
    enabled: backendReady,
  })
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null)

  const toggleExpand = (alertId: string) => {
    setExpandedAlert(expandedAlert === alertId ? null : alertId)
  }

  return (
    <TooltipProvider>
      <div className="space-y-6 w-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Activity className="h-6 w-6" />
            <div>
              <h1 className="text-2xl font-bold">Live Alert Feed</h1>
              <p className="text-sm text-muted-foreground">
                Real-time alerts as they are created
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <div className="flex items-center gap-2 text-sm text-green-600">
              <Wifi className="h-4 w-4" />
              <span>Connected</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm text-yellow-600">
              <WifiOff className="h-4 w-4" />
              <span>Disconnected</span>
            </div>
          )}
          {alerts.length > 0 && (
            <Button variant="outline" size="sm" onClick={clearAlerts}>
              <Trash2 className="h-4 w-4 mr-2" />
              Clear
            </Button>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {/* Alerts Feed */}
      {alerts.length === 0 ? (
        <Card>
          <CardContent className="flex items-center justify-center h-64">
            <div className="text-center text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium">No alerts yet</p>
              <p className="text-sm">
                {isConnected
                  ? 'Waiting for alerts to be created...'
                  : 'Connecting to alert stream...'}
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <Card
              key={alert.alert_id}
              className="cursor-pointer hover:shadow-md transition-shadow"
              onClick={() => navigate(`/alerts/${alert.alert_id}`)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <CardTitle className="text-base truncate">
                        {alert.rule_title}
                      </CardTitle>
                      <Badge
                        className={`${SEVERITY_COLORS_SUBTLE[alert.severity] || SEVERITY_COLORS_SUBTLE.medium} shrink-0`}
                      >
                        {alert.severity}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span className="font-mono">{alert.alert_id.slice(0, 8)}</span>
                      <span>•</span>
                      <RelativeTime date={alert.timestamp} />
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation()
                      toggleExpand(alert.alert_id)
                    }}
                  >
                    {expandedAlert === alert.alert_id ? 'Show Less' : 'Details'}
                  </Button>
                </div>
              </CardHeader>
              {expandedAlert === alert.alert_id && (
                <CardContent className="border-t">
                  <div className="space-y-3">
                    <div>
                      <h4 className="text-sm font-medium mb-2">Matched Log Data</h4>
                      <pre className="text-xs bg-muted p-3 rounded overflow-auto max-h-64">
                        {JSON.stringify(alert.matched_log, null, 2)}
                      </pre>
                    </div>
                  </div>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
    </TooltipProvider>
  )
}
