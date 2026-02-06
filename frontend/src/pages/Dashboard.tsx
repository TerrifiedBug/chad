import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { statsApi, DashboardStats } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { AlertTriangle, Clock, ShieldAlert } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'
import { cn } from '@/lib/utils'
import { SEVERITY_CONFIG } from '@/lib/constants'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Skeleton, SkeletonTable } from '@/components/ui/skeleton'
import { ErrorAlert } from '@/components/ui/error-alert'
import { ALERT_STATUS_LABELS, capitalize } from '@/lib/constants'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/dashboard/StatCard'
import { SeverityPills } from '@/components/filters/SeverityPills'

type RecentAlert = DashboardStats['recent_alerts'][number]
type AlertTypeFilter = 'all' | 'alerts' | 'ioc'

interface RecentAlertsTableProps {
  alerts: RecentAlert[] | undefined
  severityFilter: string[]
  hasFilters: boolean
}

function RecentAlertsTable({ alerts, severityFilter, hasFilters }: RecentAlertsTableProps): React.ReactElement {
  const filteredAlerts = severityFilter.length > 0
    ? alerts?.filter(a => severityFilter.includes(a.severity))
    : alerts

  if (!filteredAlerts || filteredAlerts.length === 0) {
    return (
      <p className="text-center text-muted-foreground py-8">
        {hasFilters ? 'No alerts matching the selected filters' : 'No alerts yet'}
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
            <TableRow
              key={alert.alert_id}
              className={cn(
                "cursor-pointer hover:bg-muted/50",
                SEVERITY_CONFIG[alert.severity]?.rowClass
              )}
            >
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
  const [alertTypeFilter, setAlertTypeFilter] = useState<AlertTypeFilter>('all')

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
      <div className="space-y-6">
        {/* Skeleton page header */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-4 w-56" />
          </div>
          <Skeleton className="h-10 w-24" />
        </div>

        {/* Skeleton stat cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="rounded-lg border bg-card p-6 space-y-3">
              <div className="flex items-center justify-between">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-8 w-8 rounded-md" />
              </div>
              <Skeleton className="h-8 w-12" />
              <Skeleton className="h-3 w-24" />
            </div>
          ))}
        </div>

        {/* Skeleton recent alerts table */}
        <div className="rounded-lg border bg-card">
          <div className="p-6 border-b">
            <Skeleton className="h-6 w-32" />
          </div>
          <SkeletonTable rows={5} columns={4} />
        </div>
      </div>
    )
  }

  if (error) {
    return <ErrorAlert message={error} onRetry={loadStats} />
  }

  const alertTypeButtons: { value: AlertTypeFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'alerts', label: 'Alerts' },
    { value: 'ioc', label: 'IOC Matches' },
  ]

  // Severity counts based on active filter, using full backend stats
  const severityCounts = (() => {
    if (!stats) return undefined
    if (alertTypeFilter === 'alerts') {
      return stats.alerts.by_severity
    }
    if (alertTypeFilter === 'ioc') {
      // IOC stats use by_threat_level which maps to severity
      return stats.ioc_matches?.by_threat_level || {}
    }
    // "all" - combine alert severity counts with IOC threat levels
    const alertSev = { ...stats.alerts.by_severity }
    const tl = stats.ioc_matches?.by_threat_level || {}
    for (const [level, count] of Object.entries(tl)) {
      alertSev[level] = (alertSev[level] || 0) + count
    }
    return alertSev
  })()

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Overview of your detection system"
        actions={
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
        }
      />

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <StatCard
          title="Alerts Today"
          value={stats?.alerts.today || 0}
          subtext={`${stats?.alerts.total || 0} total`}
          icon={AlertTriangle}
          onClick={() => navigate('/alerts')}
          variant={(stats?.alerts.today || 0) > 10 ? 'warning' : 'default'}
          showUrgencyRing={(stats?.alerts.today || 0) > 10}
          pulseOnCritical
          criticalThreshold={10}
        />

        <StatCard
          title="New Alerts"
          value={stats?.alerts.by_status?.new || 0}
          subtext={`${stats?.alerts.by_status?.acknowledged || 0} acknowledged`}
          icon={Clock}
          onClick={() => navigate('/alerts?status=new')}
          variant={(stats?.alerts.by_status?.new || 0) > 5 ? 'danger' : 'default'}
          showUrgencyRing={(stats?.alerts.by_status?.new || 0) > 5}
          pulseOnCritical
          criticalThreshold={5}
        />

        <StatCard
          title="IOC Matches Today"
          value={stats?.ioc_matches?.today || 0}
          subtext={`${stats?.ioc_matches?.total || 0} total`}
          icon={ShieldAlert}
          onClick={() => navigate('/ioc-matches')}
          variant={(stats?.ioc_matches?.today || 0) > 5 ? 'danger' : (stats?.ioc_matches?.today || 0) > 0 ? 'warning' : 'default'}
        />
      </div>

      {/* Recent Alerts */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex flex-row items-center justify-between">
            <div className="flex items-center gap-3">
              <CardTitle>Recent Alerts</CardTitle>
              <div className="flex items-center rounded-md border">
                {alertTypeButtons.map((btn) => (
                  <button
                    key={btn.value}
                    onClick={() => setAlertTypeFilter(btn.value)}
                    className={cn(
                      "px-2.5 py-1 text-xs font-medium transition-colors",
                      "first:rounded-l-md last:rounded-r-md",
                      alertTypeFilter === btn.value
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                    )}
                  >
                    {btn.label}
                  </button>
                ))}
              </div>
            </div>
            <Link to="/alerts" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </div>
          <div className="pt-2">
            <SeverityPills
              selected={severityFilter}
              onChange={toggleSeverityFilter}
              showCounts={severityCounts}
              size="sm"
            />
          </div>
        </CardHeader>
        <CardContent>
          <RecentAlertsTable
            alerts={
              alertTypeFilter === 'ioc'
                ? stats?.recent_ioc_alerts
                : alertTypeFilter === 'alerts'
                  ? stats?.recent_alerts
                  : [...(stats?.recent_alerts || []), ...(stats?.recent_ioc_alerts || [])].sort(
                      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
                    )
            }
            severityFilter={severityFilter}
            hasFilters={severityFilter.length > 0 || alertTypeFilter !== 'all'}
          />
        </CardContent>
      </Card>
    </div>
  )
}
