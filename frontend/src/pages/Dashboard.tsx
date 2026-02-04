import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { statsApi, DashboardStats } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { AlertTriangle, ChevronDown, Clock, FileText } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'
import { cn } from '@/lib/utils'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { LoadingState } from '@/components/ui/loading-state'
import { ErrorAlert } from '@/components/ui/error-alert'
import { ALERT_STATUS_LABELS, capitalize } from '@/lib/constants'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

type RecentAlert = DashboardStats['recent_alerts'][number]

interface RecentAlertsTableProps {
  alerts: RecentAlert[] | undefined
  severityFilter: string[]
}

function RecentAlertsTable({ alerts, severityFilter }: RecentAlertsTableProps): React.ReactElement {
  const filteredAlerts = severityFilter.length > 0
    ? alerts?.filter(a => severityFilter.includes(a.severity))
    : alerts

  if (!filteredAlerts || filteredAlerts.length === 0) {
    return (
      <p className="text-center text-muted-foreground py-8">
        {severityFilter.length > 0 ? 'No alerts matching the selected severity filters' : 'No alerts yet'}
      </p>
    )
  }

  return (
    <TooltipProvider>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Rule</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Time</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredAlerts.map((alert) => (
            <TableRow key={alert.alert_id}>
              <TableCell>
                <SeverityBadge severity={alert.severity} />
              </TableCell>
              <TableCell>
                <Link
                  to={`/alerts/${alert.alert_id}`}
                  className="hover:underline"
                >
                  {alert.rule_title}
                </Link>
              </TableCell>
              <TableCell>{ALERT_STATUS_LABELS[alert.status] || capitalize(alert.status)}</TableCell>
              <TableCell className="text-muted-foreground">
                <RelativeTime date={alert.created_at} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TooltipProvider>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string[]>([])

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev =>
      prev.includes(severity)
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    )
  }

  useEffect(() => {
    loadStats()
    // Refresh every 30 seconds
    const interval = setInterval(loadStats, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadStats = async () => {
    try {
      const data = await statsApi.getDashboard()
      setStats(data)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load stats')
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return <LoadingState message="Loading dashboard..." />
  }

  if (error) {
    return <ErrorAlert message={error} onRetry={loadStats} />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your detection system
          </p>
        </div>
        <Button
          variant="outline"
          className="gap-2 border-red-200 hover:bg-red-50 dark:border-red-800 dark:hover:bg-red-950"
          onClick={() => navigate('/live')}
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
          </span>
          Live Feed
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Rules</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.rules.total || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.rules.deployed || 0} deployed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Alerts Today</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.alerts.today || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.alerts.total || 0} total
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">New Alerts</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.alerts.by_status?.new || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats?.alerts.by_status?.acknowledged || 0} acknowledged
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Alerts */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle>Recent Alerts</CardTitle>
          <div className="flex items-center gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                  Severity
                  {severityFilter.length > 0 && (
                    <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs">
                      {severityFilter.length}
                    </Badge>
                  )}
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>Filter by Severity</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {SEVERITIES.map((severity) => (
                  <DropdownMenuCheckboxItem
                    key={severity}
                    checked={severityFilter.includes(severity)}
                    onCheckedChange={() => toggleSeverityFilter(severity)}
                    onSelect={(e) => e.preventDefault()}
                  >
                    <span
                      className={cn(
                        'mr-2 inline-block w-2 h-2 rounded-full',
                        severity === 'critical' && 'bg-red-500',
                        severity === 'high' && 'bg-orange-500',
                        severity === 'medium' && 'bg-yellow-500',
                        severity === 'low' && 'bg-blue-500',
                        severity === 'informational' && 'bg-gray-500'
                      )}
                    />
                    {capitalize(severity)} ({stats?.alerts.by_severity?.[severity] || 0})
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Link to="/alerts" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </div>
        </CardHeader>
        <CardContent>
          <RecentAlertsTable
            alerts={stats?.recent_alerts}
            severityFilter={severityFilter}
          />
        </CardContent>
      </Card>
    </div>
  )
}
