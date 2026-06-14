import { CheckCircle2, XCircle, Loader2, Clock, X, Rocket } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import {
  useDeployProgress,
  clearProgress,
  countByStatus,
  isBatchComplete,
  type DeployProgressRow,
} from './deploy-progress-store'

function StatusIcon({ status }: { status: DeployProgressRow['status'] }) {
  switch (status) {
    case 'success':
      return <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400 shrink-0" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" />
    case 'deploying':
      return <Loader2 className="h-4 w-4 text-blue-600 dark:text-blue-400 animate-spin shrink-0" />
    case 'queued':
    default:
      return <Clock className="h-4 w-4 text-muted-foreground shrink-0" />
  }
}

/**
 * Persistent bulk-deploy progress panel. Subscribes to the deploy-progress
 * store (fed by deploy_progress /ws messages) and renders per-rule live rows
 * plus a progress bar. Renders nothing when no bulk deploy is active.
 *
 * Mounted once at the app root so it persists across navigation.
 */
export function DeployProgress() {
  const state = useDeployProgress()

  if (!state.active || state.rows.length === 0) return null

  const { success, failed, total } = countByStatus(state)
  const done = success + failed
  const complete = isBatchComplete(state)
  const pct = total > 0 ? Math.round((done / total) * 100) : 0

  return (
    <div
      className="fixed bottom-4 right-4 z-50 w-80 rounded-lg border bg-background shadow-lg"
      role="status"
      aria-live="polite"
      aria-label="Bulk deploy progress"
    >
      <div className="flex items-center justify-between border-b px-3 py-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Rocket className="h-4 w-4 text-muted-foreground" />
          {complete ? 'Deploy complete' : 'Deploying rules…'}
        </div>
        {complete && (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={clearProgress}
            aria-label="Dismiss deploy progress"
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      <div className="px-3 py-2">
        {/* Progress bar */}
        <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
          <span>
            {done} / {total}
          </span>
          <span>
            {success} ok
            {failed > 0 && <span className="text-red-600 dark:text-red-400"> · {failed} failed</span>}
          </span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className={cn(
              'h-full rounded-full transition-all duration-300',
              failed > 0 && complete ? 'bg-amber-500' : 'bg-green-500'
            )}
            style={{ width: `${pct}%` }}
          />
        </div>

        {/* Per-rule rows */}
        <div className="mt-2 max-h-48 space-y-1 overflow-auto">
          {state.rows.map((row) => (
            <div
              key={row.ruleId}
              className="flex items-center gap-2 rounded px-1 py-0.5 text-xs"
              title={row.error || undefined}
            >
              <StatusIcon status={row.status} />
              <span className="truncate">{row.ruleTitle}</span>
              {row.status === 'failed' && row.error && (
                <span className="ml-auto truncate text-red-600 dark:text-red-400">{row.error}</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
