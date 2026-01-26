import { useEffect, useState } from 'react'
import { healthApi, type HealthIntervals } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Loader2 } from 'lucide-react'

const DEFAULT_INTERVALS: HealthIntervals = {
  jira_interval_seconds: 900,
  sigmahq_interval_seconds: 3600,
  mitre_attack_interval_seconds: 3600,
  opensearch_interval_seconds: 300,
  ti_interval_seconds: 1800,
}

export function HealthCheckSettings() {
  const { showToast } = useToast()
  const [intervals, setIntervals] = useState<HealthIntervals>(DEFAULT_INTERVALS)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    loadIntervals()
  }, [])

  const loadIntervals = async () => {
    try {
      const response = await healthApi.getIntervals()
      setIntervals(response)
    } catch (err) {
      console.error('Failed to load health intervals:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await healthApi.updateIntervals(intervals)
      showToast('Health check intervals updated', 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update intervals', 'error')
    } finally {
      setSaving(false)
    }
  }

  const formatInterval = (seconds: number) => {
    if (seconds < 60) return `${seconds} seconds`
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`
    return `${Math.floor(seconds / 3600)} hours`
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        {/* Jira Interval */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Jira Cloud</CardTitle>
            <CardDescription>Health check interval for Jira integration</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="jira-interval">Interval (seconds)</Label>
              <Input
                id="jira-interval"
                type="number"
                min="60"
                max="3600"
                value={intervals.jira_interval_seconds}
                onChange={(e) =>
                  setIntervals((prev) => ({
                    ...prev,
                    jira_interval_seconds: parseInt(e.target.value) || 900,
                  }))
                }
              />
              <p className="text-xs text-muted-foreground">
                Current: {formatInterval(intervals.jira_interval_seconds)}
                {intervals.jira_interval_seconds === 900 && ' (default)'}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* SigmaHQ Interval */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">SigmaHQ</CardTitle>
            <CardDescription>Health check interval for SigmaHQ sync</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="sigmahq-interval">Interval (seconds)</Label>
              <Input
                id="sigmahq-interval"
                type="number"
                min="60"
                max="3600"
                value={intervals.sigmahq_interval_seconds}
                onChange={(e) =>
                  setIntervals((prev) => ({
                    ...prev,
                    sigmahq_interval_seconds: parseInt(e.target.value) || 3600,
                  }))
                }
              />
              <p className="text-xs text-muted-foreground">
                Current: {formatInterval(intervals.sigmahq_interval_seconds)}
                {intervals.sigmahq_interval_seconds === 3600 && ' (default)'}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* MITRE ATT&CK Interval */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">MITRE ATT&CK</CardTitle>
            <CardDescription>Health check interval for ATT&CK sync</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="mitre-interval">Interval (seconds)</Label>
              <Input
                id="mitre-interval"
                type="number"
                min="60"
                max="3600"
                value={intervals.mitre_attack_interval_seconds}
                onChange={(e) =>
                  setIntervals((prev) => ({
                    ...prev,
                    mitre_attack_interval_seconds: parseInt(e.target.value) || 3600,
                  }))
                }
              />
              <p className="text-xs text-muted-foreground">
                Current: {formatInterval(intervals.mitre_attack_interval_seconds)}
                {intervals.mitre_attack_interval_seconds === 3600 && ' (default)'}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* OpenSearch Interval */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">OpenSearch</CardTitle>
            <CardDescription>Health check interval for OpenSearch connectivity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="opensearch-interval">Interval (seconds)</Label>
              <Input
                id="opensearch-interval"
                type="number"
                min="30"
                max="600"
                value={intervals.opensearch_interval_seconds}
                onChange={(e) =>
                  setIntervals((prev) => ({
                    ...prev,
                    opensearch_interval_seconds: parseInt(e.target.value) || 300,
                  }))
                }
              />
              <p className="text-xs text-muted-foreground">
                Current: {formatInterval(intervals.opensearch_interval_seconds)}
                {intervals.opensearch_interval_seconds === 300 && ' (default)'}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* TI Sources Interval */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Threat Intelligence</CardTitle>
            <CardDescription>Health check interval for all TI sources</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label htmlFor="ti-interval">Interval (seconds)</Label>
              <Input
                id="ti-interval"
                type="number"
                min="60"
                max="3600"
                value={intervals.ti_interval_seconds}
                onChange={(e) =>
                  setIntervals((prev) => ({
                    ...prev,
                    ti_interval_seconds: parseInt(e.target.value) || 1800,
                  }))
                }
              />
              <p className="text-xs text-muted-foreground">
                Current: {formatInterval(intervals.ti_interval_seconds)}
                {intervals.ti_interval_seconds === 1800 && ' (default)'}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={loadIntervals} disabled={loading || saving}>
          Reset
        </Button>
        <Button onClick={handleSave} disabled={saving}>
          {saving ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Saving...
            </>
          ) : (
            'Save Changes'
          )}
        </Button>
      </div>
    </div>
  )
}
