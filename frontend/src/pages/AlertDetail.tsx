import { useEffect, useState } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { alertsApi, Alert, AlertStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ArrowLeft, AlertTriangle, Clock, User, FileText } from 'lucide-react'

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

export default function AlertDetailPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const [alert, setAlert] = useState<Alert | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isUpdating, setIsUpdating] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (id) {
      loadAlert()
    }
  }, [id])

  const loadAlert = async () => {
    if (!id) return
    setIsLoading(true)
    setError('')
    try {
      const data = await alertsApi.get(id)
      setAlert(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alert')
    } finally {
      setIsLoading(false)
    }
  }

  const handleStatusChange = async (status: AlertStatus) => {
    if (!id || !alert) return
    setIsUpdating(true)
    try {
      await alertsApi.updateStatus(id, status)
      setAlert({ ...alert, status })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status')
    } finally {
      setIsUpdating(false)
    }
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (error || !alert) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/alerts')}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error || 'Alert not found'}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/alerts')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">{alert.rule_title}</h1>
            <p className="text-sm text-muted-foreground">
              Alert ID: {alert.alert_id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span
            className={`px-3 py-1 rounded text-sm font-medium ${
              severityColors[alert.severity] || 'bg-gray-500 text-white'
            }`}
          >
            {capitalize(alert.severity)}
          </span>
          <Select
            value={alert.status}
            onValueChange={(v) => handleStatusChange(v as AlertStatus)}
            disabled={isUpdating}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="z-50 bg-popover">
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="acknowledged">Acknowledged</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Info Cards */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <span
                className={`px-2 py-1 rounded text-xs font-medium ${statusColors[alert.status]}`}
              >
                {statusLabels[alert.status]}
              </span>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Timeline
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">Created:</span>
                <div>{formatDate(alert.created_at)}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Updated:</span>
                <div>{formatDate(alert.updated_at)}</div>
              </div>
              {alert.acknowledged_at && (
                <div>
                  <span className="text-muted-foreground">Acknowledged:</span>
                  <div>{formatDate(alert.acknowledged_at)}</div>
                </div>
              )}
            </CardContent>
          </Card>

          {alert.acknowledged_by && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Acknowledged By
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm">
                {alert.acknowledged_by}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Rule
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Link
                to={`/rules/${alert.rule_id}`}
                className="text-sm text-primary hover:underline"
              >
                View Rule
              </Link>
              {alert.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap mt-2">
                  {alert.tags.map((tag, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.5 bg-muted rounded text-xs"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Log Document */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-medium">
              Triggering Log Document
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="p-4 bg-muted rounded-lg overflow-auto max-h-[600px] text-xs font-mono">
              {JSON.stringify(alert.log_document, null, 2)}
            </pre>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
