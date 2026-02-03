import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell } from 'lucide-react'
import { api } from '@/lib/api'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'
import { formatDistanceToNow } from 'date-fns'

interface RecentNotifications {
  security_alerts: Array<{
    id: string
    title: string
    severity: string
    created_at: string
  }>
  health_issues: Array<{
    index_pattern_id: string
    index_pattern_name: string
    status: string
    issues: string[]
  }>
}

export function NotificationBell() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [data, setData] = useState<RecentNotifications | null>(null)

  const loadNotifications = useCallback(async () => {
    try {
      const response = await api.get<RecentNotifications>('/notifications/recent')
      setData(response)
    } catch (err) {
      console.error('Failed to load notifications:', err)
    }
  }, [])

  useEffect(() => {
    loadNotifications()
    const interval = setInterval(loadNotifications, 30000)
    return () => clearInterval(interval)
  }, [loadNotifications])

  const alertCount = data?.security_alerts?.length || 0
  const healthCount = data?.health_issues?.length || 0
  const totalCount = alertCount + healthCount

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          {totalCount > 0 && (
            <Badge
              variant="destructive"
              className="absolute -top-1 -right-1 h-5 w-5 flex items-center justify-center p-0 text-xs"
            >
              {totalCount > 9 ? '9+' : totalCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-96 max-h-[500px] overflow-y-auto">
        <DropdownMenuLabel className="flex items-center justify-between">
          <span>Notifications</span>
          {totalCount > 0 && (
            <span className="text-xs text-muted-foreground">{totalCount} new</span>
          )}
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        {/* Security Alerts */}
        {alertCount > 0 && (
          <>
            <DropdownMenuLabel>
              🔴 Security Alerts ({alertCount})
            </DropdownMenuLabel>
            {data?.security_alerts.slice(0, 5).map((alert) => (
              <DropdownMenuItem
                key={alert.id}
                onClick={() => navigate(`/alerts/${alert.id}`)}
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      [{alert.severity}]
                    </span>
                    <span className="font-medium line-clamp-1">{alert.title}</span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {formatDistanceToNow(new Date(alert.created_at))} ago
                  </span>
                </div>
              </DropdownMenuItem>
            ))}
            {alertCount > 5 && (
              <DropdownMenuItem onClick={() => navigate('/alerts')}>
                View all {alertCount} alerts →
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
          </>
        )}

        {/* Health Issues */}
        {healthCount > 0 && (
          <>
            <DropdownMenuLabel>
              ⚠️ System Health ({healthCount})
            </DropdownMenuLabel>
            {data?.health_issues.slice(0, 3).map((issue, idx) => (
              <DropdownMenuItem
                key={`${issue.index_pattern_id}-${idx}`}
                onClick={() => navigate('/health')}
              >
                <div className="flex-1">
                  <span className="font-medium">{issue.index_pattern_name}</span>
                  <span className="text-xs text-muted-foreground block">
                    {issue.status === 'critical' ? 'Critical' : 'Warning'}
                    {issue.issues.length > 0 && `: ${issue.issues[0]}`}
                  </span>
                </div>
              </DropdownMenuItem>
            ))}
            {healthCount > 3 && (
              <DropdownMenuItem onClick={() => navigate('/health')}>
                View all health issues →
              </DropdownMenuItem>
            )}
          </>
        )}

        {totalCount === 0 && (
          <div className="p-4 text-center text-sm text-muted-foreground">
            No new notifications
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
