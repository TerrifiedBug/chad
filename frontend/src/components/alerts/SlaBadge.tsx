import { AlertTriangle, Clock } from 'lucide-react'
import type { Alert, SlaPolicy, SlaSeverity } from '@/lib/api'

interface SlaBadgeProps {
  alert: Pick<Alert, 'created_at' | 'severity' | 'status' | 'sla_breached' | 'sla_due_at'>
  policy: SlaPolicy | undefined
}

const CLOSED_STATUSES = new Set(['resolved', 'false_positive'])

/**
 * SLA chip for an alert. Renders nothing when the policy is disabled, the
 * severity has no target, or the alert is already closed. Shows "Overdue" once
 * past due (server-confirmed via sla_breached, or derived client-side), else a
 * countdown. Derived client-side so it stays live between breach-scan runs.
 */
export function SlaBadge({ alert, policy }: SlaBadgeProps) {
  if (!policy?.enabled || CLOSED_STATUSES.has(alert.status)) return null

  const target = policy.targets_minutes[(alert.severity || '').toLowerCase() as SlaSeverity]
  if (!target || target <= 0) return null

  const due = alert.sla_due_at
    ? new Date(alert.sla_due_at).getTime()
    : new Date(alert.created_at).getTime() + target * 60_000
  const remainingMs = due - Date.now()
  const breached = alert.sla_breached || remainingMs <= 0

  if (breached) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-600 dark:text-red-400">
        <AlertTriangle className="h-3 w-3" />
        SLA overdue
      </span>
    )
  }

  const mins = Math.round(remainingMs / 60_000)
  const label = mins >= 60 ? `${Math.round(mins / 60)}h` : `${mins}m`
  // Amber within 25% of the window remaining, otherwise muted.
  const urgent = remainingMs < target * 60_000 * 0.25
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
        urgent
          ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
          : 'bg-muted text-muted-foreground'
      }`}
    >
      <Clock className="h-3 w-3" />
      SLA {label}
    </span>
  )
}
