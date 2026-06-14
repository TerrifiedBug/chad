import { useMemo } from 'react'
import { Copy } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { YamlDiff } from '@/components/YamlDiff'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import { useToast } from '@/components/ui/toast-provider'
import { AuditLogEntry } from '@/lib/api'

interface AuditDetailDrawerProps {
  entry: AuditLogEntry | null
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Human-friendly action label, computed by the parent (matches table copy). */
  formatAction: (action: string, details?: Record<string, unknown>) => string
  /** Human-friendly resource-type label, computed by the parent. */
  formatResourceType: (type: string) => string
}

/**
 * Extracts the before/after pair from an audit row's `details`. Supports both
 * the `before`/`after` and `old`/`new` naming conventions. Returns null when no
 * such pair is present, so the Diff section is omitted.
 */
function extractDiff(
  details: Record<string, unknown> | null
): { before: unknown; after: unknown } | null {
  if (!details) return null
  if ('before' in details || 'after' in details) {
    return { before: details.before, after: details.after }
  }
  if ('old' in details || 'new' in details) {
    return { before: details.old, after: details.new }
  }
  return null
}

/** Render any value as a stable, line-diffable string. */
function toDiffString(value: unknown): string {
  if (value == null) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function ObjectField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <span className="text-muted-foreground text-sm">{label}</span>
      <p className={mono ? 'font-mono text-sm break-all' : 'font-medium text-sm'}>{value}</p>
    </div>
  )
}

export function AuditDetailDrawer({
  entry,
  open,
  onOpenChange,
  formatAction,
  formatResourceType,
}: AuditDetailDrawerProps) {
  const { showToast } = useToast()

  const diff = useMemo(() => extractDiff(entry?.details ?? null), [entry])

  const rawJson = useMemo(
    () => (entry ? JSON.stringify(entry, null, 2) : ''),
    [entry]
  )

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rawJson)
      showToast('Copied to clipboard', 'success')
    } catch {
      showToast('Failed to copy', 'error')
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
        {entry && (
          <>
            <SheetHeader className="text-left">
              <SheetTitle className="flex items-center gap-3">
                <span>Audit Event</span>
                <Badge variant="secondary">
                  {formatAction(entry.action, entry.details ?? undefined)}
                </Badge>
              </SheetTitle>
              <SheetDescription>
                <TimestampTooltip timestamp={entry.created_at}>
                  <span>{new Date(entry.created_at).toLocaleString()}</span>
                </TimestampTooltip>
                {' · '}
                {entry.user_email || (entry.user_id ? 'Unknown User' : 'System')}
              </SheetDescription>
            </SheetHeader>

            <div className="mt-6 space-y-6">
              {/* Object section */}
              <section>
                <h3 className="text-sm font-semibold mb-3">Object</h3>
                <div className="grid grid-cols-2 gap-4">
                  <ObjectField label="Resource Type" value={formatResourceType(entry.resource_type)} />
                  <ObjectField label="Action" value={entry.action} mono />
                  <ObjectField label="Resource ID" value={entry.resource_id || '-'} mono />
                  <ObjectField
                    label="IP Address"
                    value={
                      entry.ip_address ||
                      (entry.details?.ip_address ? String(entry.details.ip_address) : '-')
                    }
                    mono
                  />
                </div>
              </section>

              {/* Diff section — only when before/after (or old/new) present */}
              {diff && (
                <section>
                  <h3 className="text-sm font-semibold mb-3">Diff</h3>
                  <YamlDiff
                    current={toDiffString(diff.before)}
                    proposed={toDiffString(diff.after)}
                    className="max-h-72"
                  />
                </section>
              )}

              {/* Raw JSON section */}
              <section>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold">Raw JSON</h3>
                  <Button variant="outline" size="sm" onClick={handleCopy}>
                    <Copy className="h-4 w-4 mr-2" />
                    Copy
                  </Button>
                </div>
                <pre className="p-4 bg-muted rounded-md text-xs overflow-auto max-h-80">
                  {rawJson}
                </pre>
              </section>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
