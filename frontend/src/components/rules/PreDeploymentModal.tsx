import { useState, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Loader2, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { rulesApi } from '@/lib/api'

interface PreDeploymentModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  ruleId: string
  ruleName: string
  threshold: number
  onProceed: () => void
}

interface DryRunResult {
  total_scanned: number
  total_matches: number
  matches: Array<{ _id: string; _index: string; _source: Record<string, unknown> }>
  truncated: boolean
  error?: string
}

export function PreDeploymentModal({
  open,
  onOpenChange,
  ruleId,
  ruleName,
  threshold,
  onProceed,
}: PreDeploymentModalProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<DryRunResult | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) {
      setResult(null)
      setError('')
      return
    }

    const runDryRun = async () => {
      setLoading(true)
      setError('')
      try {
        const now = new Date()
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
        const data = await rulesApi.testHistorical(ruleId, oneDayAgo, now, 10)
        setResult(data)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Dry-run failed')
      } finally {
        setLoading(false)
      }
    }

    runDryRun()
  }, [open, ruleId])

  const isOverThreshold = result ? result.total_matches > threshold : false
  const isSeverelyOver = result ? result.total_matches > threshold * 10 : false

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Pre-Deployment Check</DialogTitle>
          <DialogDescription>
            Running dry-run for &ldquo;{ruleName}&rdquo; against last 24 hours of logs.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {loading && (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Running historical dry-run...
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}

          {result && !error && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-lg border p-3">
                  <div className="text-sm text-muted-foreground">Logs Scanned (24h)</div>
                  <div className="text-2xl font-bold">
                    {result.total_scanned.toLocaleString()}
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-sm text-muted-foreground">Matches</div>
                  <div
                    className={`text-2xl font-bold ${isSeverelyOver ? 'text-red-500' : isOverThreshold ? 'text-amber-500' : ''}`}
                  >
                    {result.total_matches.toLocaleString()}
                    {result.truncated && '+'}
                  </div>
                </div>
              </div>

              {isOverThreshold && (
                <div
                  className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${isSeverelyOver ? 'border-red-500 bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400' : 'border-amber-500 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400'}`}
                >
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>
                    {isSeverelyOver
                      ? `This rule matched ${result.total_matches.toLocaleString()} logs in the last 24 hours — ${Math.round(result.total_matches / threshold)}x your threshold of ${threshold}. Deploying will likely generate a large volume of alerts.`
                      : `This rule matched ${result.total_matches.toLocaleString()} logs in the last 24 hours, exceeding your threshold of ${threshold}. Consider tuning the rule before deployment.`}
                  </span>
                </div>
              )}

              {!isOverThreshold && (
                <div className="flex items-start gap-2 rounded-lg border border-green-500 bg-green-50 dark:bg-green-950/20 p-3 text-sm text-green-700 dark:text-green-400">
                  <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>
                    Match count ({result.total_matches.toLocaleString()}) is within your threshold
                    of {threshold}.
                  </span>
                </div>
              )}

              {result.matches.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Sample Matches</div>
                  <div className="max-h-48 overflow-auto rounded border bg-muted">
                    <pre className="p-3 text-xs">
                      {JSON.stringify(result.matches.slice(0, 5), null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={onProceed}
            disabled={loading || !!error}
            variant={isSeverelyOver ? 'destructive' : 'default'}
          >
            {isOverThreshold ? 'Deploy Anyway' : 'Proceed to Deploy'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
