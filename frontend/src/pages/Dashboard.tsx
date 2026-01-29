import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
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
import { AlertTriangle, ChevronDown, Clock, FileText, Shield } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'
import { cn } from '@/lib/utils'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const statusLabels: Record<string, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

export default function Dashboard() {
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
    return (
      <div className="flex items-center justify-center h-64">
        Loading dashboard...
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-destructive/10 text-destructive p-4 rounded-md">
        {error}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your detection system
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
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
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.rules.by_status?.enabled || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats?.rules.by_status?.disabled || 0} disabled
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
          {(() => {
            const filteredAlerts = severityFilter.length > 0
              ? stats?.recent_alerts?.filter(a => severityFilter.includes(a.severity))
              : stats?.recent_alerts
            return filteredAlerts && filteredAlerts.length > 0 ? (
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
                        <span
                          className={`px-2 py-1 rounded text-xs font-medium ${
                            severityColors[alert.severity] || 'bg-gray-500 text-white'
                          }`}
                        >
                          {capitalize(alert.severity)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Link
                          to={`/alerts/${alert.alert_id}`}
                          className="hover:underline"
                        >
                          {alert.rule_title}
                        </Link>
                      </TableCell>
                      <TableCell>{statusLabels[alert.status] || capitalize(alert.status)}</TableCell>
                      <TableCell className="text-muted-foreground">
                        <RelativeTime date={alert.created_at} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TooltipProvider>
          ) : (
            <p className="text-center text-muted-foreground py-8">
              {severityFilter.length > 0 ? 'No alerts matching the selected severity filters' : 'No alerts yet'}
            </p>
          )
          })()}
        </CardContent>
      </Card>
    </div>
  )
}
