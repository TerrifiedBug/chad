import { useState, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { YamlDiff } from '@/components/YamlDiff'
import { useToast } from '@/components/ui/toast-provider'
import {
  Loader2,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  ArrowLeft,
  ArrowRight,
  ArrowUpToLine,
  Layers,
} from 'lucide-react'
import {
  environmentsApi,
  rulesApi,
  type Environment,
  type IneligibleRule,
} from '@/lib/api'
import { ENVIRONMENTS_QUERY_KEY } from '@/components/EnvironmentSelector'
import { cn } from '@/lib/utils'

type Step = 'target' | 'preflight' | 'diff' | 'reason' | 'result'
const STEP_ORDER: Step[] = ['target', 'preflight', 'diff', 'reason', 'result']
const STEP_LABELS: Record<Step, string> = {
  target: 'Target',
  preflight: 'Preflight',
  diff: 'Diff',
  reason: 'Reason',
  result: 'Confirm',
}

// One rule being promoted (id + title for display).
export interface PromoteRuleRef {
  id: string
  title: string
}

interface PromoteDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Rules to promote (one for RuleEditor, many for the Rules bulk bar). */
  rules: PromoteRuleRef[]
  /** The env the pinned version is taken FROM (the active env). */
  sourceEnvironmentId: string | null
  /** Called after a promotion applied immediately (target gate off) so the parent can refresh. */
  onPromoted?: () => void
  /** Called after a promotion was filed for approval (target gate on / 202). */
  onSubmittedForApproval?: () => void
}

// Per-rule source-vs-target diff, lazily loaded from the deploy-preview seam.
interface RuleDiff {
  ruleId: string
  title: string
  current: string
  proposed: string
  error?: string
}

/**
 * Guided promotion flow: pick target env → preflight (eligible rules) →
 * source-vs-target diff (reuses YamlDiff + the deploy-preview seam) → reason →
 * confirm/result. Calls POST /environments/{targetId}/promote with the active
 * env as source. Handles the 202 pending-approval result (target env requires
 * approval) the same way DeployDialog handles its gate.
 */
export function PromoteDialog({
  open,
  onOpenChange,
  rules,
  sourceEnvironmentId,
  onPromoted,
  onSubmittedForApproval,
}: PromoteDialogProps) {
  const { showToast } = useToast()
  const [step, setStep] = useState<Step>('target')

  const [targetEnvId, setTargetEnvId] = useState<string>('')

  // Preflight (eligibility) state
  const [ineligible, setIneligible] = useState<IneligibleRule[]>([])
  const [eligibleIds, setEligibleIds] = useState<string[]>([])
  const [preflightLoading, setPreflightLoading] = useState(false)
  const [preflightError, setPreflightError] = useState('')

  // Diff state (per eligible rule)
  const [diffs, setDiffs] = useState<RuleDiff[]>([])
  const [diffLoading, setDiffLoading] = useState(false)

  // Reason + submit state
  const [changeReason, setChangeReason] = useState('')
  const [isPromoting, setIsPromoting] = useState(false)
  const [promoteError, setPromoteError] = useState('')

  // Environment list — target options exclude the source/active env.
  const { data: environments } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY],
    queryFn: () => environmentsApi.list(),
    enabled: open,
    retry: false,
  })

  const targetOptions: Environment[] = (environments ?? []).filter(
    (e) => e.id !== sourceEnvironmentId
  )
  const targetEnv = (environments ?? []).find((e) => e.id === targetEnvId) ?? null
  const sourceEnv = (environments ?? []).find((e) => e.id === sourceEnvironmentId) ?? null
  // Target env approval gate (advisory; the 202 result is authoritative).
  const requiresApproval = !!targetEnv?.require_deploy_approval

  // Reset state each time the dialog opens.
  useEffect(() => {
    if (!open) return
    setStep('target')
    setTargetEnvId('')
    setIneligible([])
    setEligibleIds([])
    setPreflightError('')
    setDiffs([])
    setChangeReason('')
    setPromoteError('')
  }, [open])

  // Preflight: which selected rules are eligible to deploy/promote.
  const runPreflight = useCallback(async () => {
    setPreflightLoading(true)
    setPreflightError('')
    try {
      const result = await rulesApi.checkDeploymentEligibility(rules.map((r) => r.id))
      setEligibleIds(result.eligible)
      setIneligible(result.ineligible)
    } catch (err) {
      setPreflightError(err instanceof Error ? err.message : 'Preflight check failed')
    } finally {
      setPreflightLoading(false)
    }
  }, [rules])

  // Diff: source-vs-target for each eligible rule, from the deploy-preview seam.
  const loadDiffs = useCallback(async () => {
    setDiffLoading(true)
    const eligibleRules = rules.filter((r) => eligibleIds.includes(r.id))
    const loaded: RuleDiff[] = await Promise.all(
      eligibleRules.map(async (r) => {
        try {
          const preview = await rulesApi.deployPreview(r.id)
          return {
            ruleId: r.id,
            title: r.title,
            current: preview.current_deployed_query ?? '',
            proposed: preview.proposed_query,
          }
        } catch (err) {
          return {
            ruleId: r.id,
            title: r.title,
            current: '',
            proposed: '',
            error: err instanceof Error ? err.message : 'Failed to load diff',
          }
        }
      })
    )
    setDiffs(loaded)
    setDiffLoading(false)
  }, [rules, eligibleIds])

  const handleConfirm = async () => {
    if (!changeReason.trim() || !targetEnvId || !sourceEnvironmentId) return
    setIsPromoting(true)
    setPromoteError('')
    try {
      const result = await environmentsApi.promote(targetEnvId, {
        rule_ids: eligibleIds,
        source_environment_id: sourceEnvironmentId,
        change_reason: changeReason.trim(),
      })
      if (result.pendingApproval) {
        showToast('Promotion submitted for approval', 'info')
        onSubmittedForApproval?.()
        onOpenChange(false)
        return
      }
      showToast(`Promoted to ${targetEnv?.name ?? 'target'}`, 'success')
      onPromoted?.()
      onOpenChange(false)
    } catch (err) {
      setPromoteError(err instanceof Error ? err.message : 'Promotion failed')
    } finally {
      setIsPromoting(false)
    }
  }

  // Advancing off a step kicks the next step's async load when needed.
  const goNext = async () => {
    const idx = STEP_ORDER.indexOf(step)
    const next = STEP_ORDER[idx + 1]
    if (!next) return
    if (next === 'preflight') await runPreflight()
    if (next === 'diff') await loadDiffs()
    setStep(next)
  }
  const goBack = () => {
    const idx = STEP_ORDER.indexOf(step)
    if (idx > 0) setStep(STEP_ORDER[idx - 1])
  }

  // No eligible rule (or hard preflight error) blocks advancing to the diff.
  const preflightBlocked =
    preflightLoading || !!preflightError || eligibleIds.length === 0
  const canPromote = eligibleIds.length > 0 && !!changeReason.trim() && !isPromoting

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowUpToLine className="h-5 w-5" />
            Promote {rules.length === 1 ? `“${rules[0].title}”` : `${rules.length} rules`}
          </DialogTitle>
          <DialogDescription>
            Advance the target environment to the version currently deployed in{' '}
            {sourceEnv ? sourceEnv.name : 'the active environment'}.
          </DialogDescription>
        </DialogHeader>

        {/* Step indicator */}
        <div className="flex items-center gap-2" aria-label="Promote steps">
          {STEP_ORDER.map((s, i) => {
            const activeIdx = STEP_ORDER.indexOf(step)
            const isActive = s === step
            const isDone = i < activeIdx
            return (
              <div key={s} className="flex items-center gap-2">
                <div
                  className={cn(
                    'flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : isDone
                        ? 'bg-muted text-foreground'
                        : 'text-muted-foreground'
                  )}
                >
                  <span
                    className={cn(
                      'flex h-4 w-4 items-center justify-center rounded-full text-[10px]',
                      isActive ? 'bg-primary-foreground text-primary' : 'bg-muted-foreground/20'
                    )}
                  >
                    {i + 1}
                  </span>
                  {STEP_LABELS[s]}
                </div>
                {i < STEP_ORDER.length - 1 && (
                  <div className="h-px w-4 bg-border" aria-hidden="true" />
                )}
              </div>
            )
          })}
        </div>

        <div className="flex-1 overflow-auto py-2">
          {/* --- Target env --- */}
          {step === 'target' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="promote-target-env">Target environment</Label>
                <Select value={targetEnvId} onValueChange={setTargetEnvId}>
                  <SelectTrigger id="promote-target-env" aria-label="Target environment">
                    <SelectValue placeholder="Select a target environment" />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    {targetOptions.map((env) => (
                      <SelectItem key={env.id} value={env.id}>
                        <span className="flex items-center gap-2">
                          <Layers className="h-3.5 w-3.5" />
                          {env.name}
                          {env.require_deploy_approval && (
                            <Badge variant="warning-subtle" className="ml-1">
                              approval
                            </Badge>
                          )}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {targetOptions.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No other environment to promote into.
                  </p>
                )}
              </div>

              {sourceEnv && targetEnv && (
                <div className="flex items-center gap-2 text-sm">
                  <Badge variant="outline" className="gap-1">
                    <Layers className="h-3 w-3" />
                    {sourceEnv.name}
                  </Badge>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  <Badge variant="outline" className="gap-1">
                    <Layers className="h-3 w-3" />
                    {targetEnv.name}
                  </Badge>
                </div>
              )}
            </div>
          )}

          {/* --- Preflight --- */}
          {step === 'preflight' && (
            <div className="space-y-4">
              {preflightLoading && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running preflight checks…
                </div>
              )}

              {preflightError && (
                <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
                  {preflightError}
                </div>
              )}

              {!preflightLoading && !preflightError && (
                <>
                  <div
                    className={cn(
                      'flex items-start gap-2 rounded-lg border p-3 text-sm',
                      eligibleIds.length > 0
                        ? 'border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400'
                        : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400'
                    )}
                  >
                    {eligibleIds.length > 0 ? (
                      <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <div className="font-medium">
                        {eligibleIds.length} of {rules.length} rule
                        {rules.length > 1 ? 's' : ''} eligible to promote
                      </div>
                      {eligibleIds.length === 0 && (
                        <div className="mt-0.5">
                          No eligible rules — resolve the issues below and retry.
                        </div>
                      )}
                    </div>
                  </div>

                  {ineligible.length > 0 && (
                    <div className="rounded-lg border p-3 text-sm space-y-1">
                      <div className="text-muted-foreground">Ineligible rules</div>
                      <ul className="list-disc pl-4">
                        {ineligible.map((r) => (
                          <li key={r.id}>{r.reason}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* --- Diff --- */}
          {step === 'diff' && (
            <div className="space-y-4">
              {diffLoading && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading source-vs-target diff…
                </div>
              )}
              {!diffLoading &&
                diffs.map((d) => (
                  <div key={d.ruleId} className="space-y-2">
                    <div className="text-sm font-medium">{d.title}</div>
                    {d.error ? (
                      <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
                        {d.error}
                      </div>
                    ) : (
                      <YamlDiff
                        current={d.current}
                        proposed={d.proposed}
                        className="max-h-64"
                      />
                    )}
                  </div>
                ))}
            </div>
          )}

          {/* --- Reason --- */}
          {step === 'reason' && (
            <div className="space-y-4">
              {requiresApproval && (
                <div className="flex items-start gap-2 rounded-lg border border-blue-500/40 bg-blue-500/10 p-3 text-sm text-blue-700 dark:text-blue-400">
                  <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>
                    {targetEnv?.name} requires approval. Submitting will file a promotion
                    request for a second reviewer instead of promoting immediately.
                  </span>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="promote-change-reason">Reason for promotion *</Label>
                <Textarea
                  id="promote-change-reason"
                  placeholder="e.g., Validated in staging, ready for production…"
                  value={changeReason}
                  onChange={(e) => setChangeReason(e.target.value)}
                  rows={3}
                  className="resize-none"
                />
              </div>
            </div>
          )}

          {/* --- Confirm/Result --- */}
          {step === 'result' && (
            <div className="space-y-4">
              {promoteError && (
                <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
                  {promoteError}
                </div>
              )}
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Promote: </span>
                  <Badge variant="outline" className="gap-1">
                    <Layers className="h-3 w-3" />
                    {sourceEnv?.name ?? 'source'}
                  </Badge>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  <Badge variant="outline" className="gap-1">
                    <Layers className="h-3 w-3" />
                    {targetEnv?.name ?? 'target'}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Rules: </span>
                  {eligibleIds.length}
                </div>
                <div>
                  <span className="text-muted-foreground">Reason: </span>
                  {changeReason}
                </div>
                {requiresApproval && (
                  <div className="flex items-center gap-1.5 text-blue-700 dark:text-blue-400">
                    <ShieldAlert className="h-4 w-4" />
                    Will be submitted for approval.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="flex items-center justify-between sm:justify-between">
          <div>
            {step !== 'target' && (
              <Button variant="ghost" onClick={goBack} disabled={isPromoting}>
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back
              </Button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isPromoting}>
              Cancel
            </Button>
            {step === 'target' && (
              <Button onClick={goNext} disabled={!targetEnvId}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
            {step === 'preflight' && (
              <Button onClick={goNext} disabled={preflightBlocked}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
            {step === 'diff' && (
              <Button onClick={goNext} disabled={diffLoading}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
            {step === 'reason' && (
              <Button onClick={goNext} disabled={!changeReason.trim()}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
            {step === 'result' && (
              <Button onClick={handleConfirm} disabled={!canPromote}>
                {isPromoting
                  ? 'Submitting…'
                  : requiresApproval
                    ? 'Submit for approval'
                    : 'Promote'}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
