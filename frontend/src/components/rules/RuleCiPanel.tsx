import { useState } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, MinusCircle, Play, Loader2, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ruleCiApi, type RuleCIReport, type RuleCICheck } from '@/lib/api'

interface RuleCiPanelProps {
  /** YAML of the rule currently in the editor (used for unsaved/ad-hoc runs). */
  yamlContent: string
  /** Index pattern the rule targets — drives field validation + backtest. */
  indexPatternId?: string
  /** Stored rule id; when present we run the persisted-rule endpoint so the
   *  coverage check can read saved ATT&CK mappings. */
  ruleId?: string
}

// Map each check status to an icon + a Badge variant, matching the VF console
// status grammar (success / warning / destructive / outline).
const STATUS_META: Record<
  string,
  { icon: typeof CheckCircle2; badge: 'success' | 'warning' | 'destructive' | 'outline'; label: string; className: string }
> = {
  pass: { icon: CheckCircle2, badge: 'success', label: 'Pass', className: 'text-green-600' },
  warn: { icon: AlertTriangle, badge: 'warning', label: 'Warn', className: 'text-amber-600' },
  fail: { icon: XCircle, badge: 'destructive', label: 'Fail', className: 'text-destructive' },
  skipped: { icon: MinusCircle, badge: 'outline', label: 'Skipped', className: 'text-muted-foreground' },
}

// Human-friendly labels for each check name returned by the backend.
const CHECK_LABELS: Record<string, string> = {
  lint: 'Sigma lint',
  field_validation: 'Field validation',
  fp_backtest: 'False-positive backtest',
  coverage: 'ATT&CK coverage',
}

export function RuleCiPanel({ yamlContent, indexPatternId, ruleId }: RuleCiPanelProps) {
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [report, setReport] = useState<RuleCIReport | null>(null)

  const handleRunCi = async () => {
    setIsRunning(true)
    setError(null)
    setReport(null)
    try {
      const result = ruleId
        ? await ruleCiApi.checkStored(ruleId, { index_pattern_id: indexPatternId })
        : await ruleCiApi.check({ yaml_content: yamlContent, index_pattern_id: indexPatternId })
      setReport(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run CI checks')
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          Lint, false-positive backtest and ATT&amp;CK coverage gate for this rule.
        </p>
        {report && (
          <Badge variant={report.passed ? 'success' : 'destructive'}>
            {report.passed ? 'CI passed' : 'CI failed'}
          </Badge>
        )}
      </div>

      <Button
        size="sm"
        variant="secondary"
        onClick={handleRunCi}
        disabled={isRunning || !yamlContent}
        className="w-full"
      >
        {isRunning ? (
          <>
            <Loader2 className="h-3 w-3 mr-2 animate-spin" />
            Running CI...
          </>
        ) : (
          <>
            <Play className="h-3 w-3 mr-2" />
            Run CI
          </>
        )}
      </Button>

      {error && (
        <div className="flex items-center gap-2 p-2 text-sm text-destructive bg-destructive/10 rounded-md">
          <XCircle className="h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {report && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>{report.summary}</span>
          </div>

          <ul className="space-y-1.5">
            {report.checks.map((check: RuleCICheck) => {
              const meta = STATUS_META[check.status] ?? STATUS_META.skipped
              const Icon = meta.icon
              return (
                <li key={check.name} className="flex items-start gap-2 text-sm">
                  <Icon className={`h-4 w-4 mt-0.5 flex-shrink-0 ${meta.className}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{CHECK_LABELS[check.name] ?? check.name}</span>
                      <Badge variant={meta.badge}>{meta.label}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground break-words">{check.detail}</p>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
