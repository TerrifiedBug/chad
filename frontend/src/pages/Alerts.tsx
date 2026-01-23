import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { alertsApi, Alert, AlertStatus, AlertCountsResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Search, Bell, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RelativeTime } from '@/components/RelativeTime'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const statusColors: Record<AlertStatus, string> = {
  new: 'bg-blue-500 text-white',
  acknowledged: 'bg-yellow-500 text-black',
  resolved: 'bg-green-500 text-white',
  false_positive: 'bg-gray-500 text-white',
}

const statusLabels: Record<AlertStatus, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

export default function AlertsPage() {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [counts, setCounts] = useState<AlertCountsResponse | null>(null)
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  useEffect(() => {
    loadData()
  }, [statusFilter, severityFilter])

  const loadData = async () => {
    setIsLoading(true)
    setError('')
    try {
      const [alertsResponse, countsResponse] = await Promise.all([
        alertsApi.list({
          status: statusFilter === 'all' ? undefined : statusFilter,
          severity: severityFilter === 'all' ? undefined : severityFilter,
          limit: 100,
        }),
        alertsApi.getCounts(),
      ])
      setAlerts(alertsResponse.alerts)
      setTotal(alertsResponse.total)
      setCounts(countsResponse)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts')
    } finally {
      setIsLoading(false)
    }
  }

  const filteredAlerts = alerts.filter((alert) =>
    alert.rule_title.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Alerts</h1>
      </div>

      {/* Stats Cards */}
      {counts && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
              <Bell className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.total}</div>
              <p className="text-xs text-muted-foreground">
                {counts.last_24h} in last 24h
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">New</CardTitle>
              <AlertTriangle className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_status['new'] || 0}</div>
              <p className="text-xs text-muted-foreground">Requires attention</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical</CardTitle>
              <XCircle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_severity['critical'] || 0}</div>
              <p className="text-xs text-muted-foreground">High priority</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Resolved</CardTitle>
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{counts.by_status['resolved'] || 0}</div>
              <p className="text-xs text-muted-foreground">Investigated</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select
          value={statusFilter}
          onValueChange={(value) => setStatusFilter(value as AlertStatus | 'all')}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="z-50 bg-popover">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={severityFilter}
          onValueChange={setSeverityFilter}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="z-50 bg-popover">
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" onClick={loadData}>
          Refresh
        </Button>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : filteredAlerts.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          {search || statusFilter !== 'all' || severityFilter !== 'all'
            ? 'No alerts match your filters'
            : 'No alerts yet. Alerts will appear when rules match incoming logs.'}
        </div>
      ) : (
        <TooltipProvider>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.map((alert) => (
                  <TableRow
                    key={alert.alert_id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                  >
                    <TableCell className="font-medium">{alert.rule_title}</TableCell>
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
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${statusColors[alert.status]}`}
                      >
                        {statusLabels[alert.status]}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {alert.tags.slice(0, 3).map((tag, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 bg-muted rounded text-xs"
                          >
                            {tag}
                          </span>
                        ))}
                        {alert.tags.length > 3 && (
                          <span className="text-xs text-muted-foreground">
                            +{alert.tags.length - 3}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <RelativeTime date={alert.created_at} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </TooltipProvider>
      )}

      {total > 100 && (
        <div className="text-center text-sm text-muted-foreground">
          Showing {filteredAlerts.length} of {total} alerts
        </div>
      )}
    </div>
  )
}
