import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { statsApi, DashboardStats } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { AlertTriangle, Clock, FileText, Shield } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

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
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)

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
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your detection system
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {['critical', 'high', 'medium', 'low', 'informational'].map(sev => {
            const count = stats?.alerts.by_severity?.[sev] || 0
            const isActive = severityFilter === sev
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(isActive ? null : sev)}
                className={`flex items-center gap-1.5 px-2 py-1 rounded-md transition-all ${
                  isActive
                    ? 'bg-primary/10 scale-105'
                    : 'hover:bg-muted'
                }`}
              >
                <Badge className={severityColors[sev]}>{capitalize(sev)}</Badge>
                <span className={`font-mono text-sm ${isActive ? 'font-semibold' : ''}`}>{count}</span>
              </button>
            )
          })}
        </div>
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
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <CardTitle>Recent Alerts</CardTitle>
            {severityFilter && (
              <Badge className={severityColors[severityFilter]}>
                {capitalize(severityFilter)}
              </Badge>
            )}
          </div>
          <Link to="/alerts" className="text-sm text-primary hover:underline">
            View all
          </Link>
        </CardHeader>
        <CardContent>
          {(() => {
            const filteredAlerts = severityFilter
              ? stats?.recent_alerts?.filter(a => a.severity === severityFilter)
              : stats?.recent_alerts
            return filteredAlerts && filteredAlerts.length > 0 ? (
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
                      <Badge className={severityColors[alert.severity]}>
                        {capitalize(alert.severity)}
                      </Badge>
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
                      {formatDistanceToNow(new Date(alert.created_at), {
                        addSuffix: true,
                      })}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-center text-muted-foreground py-8">
              {severityFilter ? `No ${capitalize(severityFilter)} alerts` : 'No alerts yet'}
            </p>
          )
          })()}
        </CardContent>
      </Card>
    </div>
  )
}
