import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { slaApi, type SlaPolicy, type SlaSeverity } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'

const SEVERITIES: SlaSeverity[] = ['critical', 'high', 'medium', 'low', 'informational']

/**
 * Admin control for the alert SLA policy (per-severity time-to-resolution in
 * minutes; 0 disables a severity). Self-contained: loads, edits and persists
 * via /api/sla-policy. Mounted in the Security settings tab.
 */
export function SlaPolicyCard() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const { data } = useQuery({ queryKey: ['sla-policy'], queryFn: () => slaApi.get() })

  const [policy, setPolicy] = useState<SlaPolicy | null>(null)
  useEffect(() => {
    if (data) setPolicy(data)
  }, [data])

  const save = useMutation({
    mutationFn: (p: SlaPolicy) => slaApi.update(p),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sla-policy'] })
      showToast('SLA policy saved', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to save SLA policy', 'error'),
  })

  if (!policy) return null

  const setTarget = (sev: SlaSeverity, minutes: number) =>
    setPolicy({ ...policy, targets_minutes: { ...policy.targets_minutes, [sev]: Math.max(0, minutes) } })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Alert SLA Policy</CardTitle>
            <CardDescription>
              Time-to-resolution targets per severity. Breaches are flagged on open alerts. 0 = no SLA.
            </CardDescription>
          </div>
          <Switch
            checked={policy.enabled}
            onCheckedChange={(enabled) => setPolicy({ ...policy, enabled })}
          />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          {SEVERITIES.map((sev) => (
            <div key={sev} className="flex items-center justify-between gap-3">
              <Label className="capitalize" htmlFor={`sla-${sev}`}>{sev}</Label>
              <div className="flex items-center gap-2">
                <Input
                  id={`sla-${sev}`}
                  type="number"
                  min={0}
                  className="w-28"
                  disabled={!policy.enabled}
                  value={policy.targets_minutes[sev]}
                  onChange={(e) => setTarget(sev, parseInt(e.target.value || '0', 10))}
                />
                <span className="text-xs text-muted-foreground">min</span>
              </div>
            </div>
          ))}
        </div>
        <div className="flex justify-end">
          <Button onClick={() => save.mutate(policy)} disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save SLA policy'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
