import { useState, useEffect, useCallback } from 'react'
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
import { YamlDiff } from '@/components/YamlDiff'
import { useToast } from '@/components/ui/toast-provider'
import {
  Loader2,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ShieldAlert,
  ArrowLeft,
  ArrowRight,
} from 'lucide-react'
import {
  rulesApi,
  DeploymentUnmappedFieldsError,
  type DeployPreviewResponse,
  type RuleDeployResponse,
} from '@/lib/api'
import { cn } from '@/lib/utils'

type Step = 'preflight' | 'diff' | 'reason' | 'result'
const STEP_ORDER: Step[] = ['preflight', 'diff', 'reason', 'result']
const STEP_LABELS: Record<Step, string> = {
  preflight: 'Preflight',
  diff: 'Diff',
  reason: 'Reason',
  result: 'Confirm',
}

interface DeployDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  ruleId: string
  ruleTitle: string
  /**
   * Whether the dual-control approval gate is on. When true the Reason step
   * shows a "this deploy needs approval" notice. The actual outcome is still
   * driven by the 202 result, so this is purely advisory.
   */
  requiresApproval?: boolean
  /** Called after a successful direct deploy (gate off) so the parent can refresh. */
  onDeployed?: (result: RuleDeployResponse) => void
  /** Called after a deploy is filed for approval (gate on / 202). */
  onSubmittedForApproval?: () => void
}

/**
 * Multi-step deploy modal: Preflight → Diff → Reason → Confirm/Result.
 * Consolidates the previous eligibility/validate/dry-run modals and the inline
 * change-reason dialog into one flow. Reuses YamlDiff for current-vs-proposed.
 */
export function DeployDialog({
  open,
  onOpenChange,
  ruleId,
  ruleTitle,
  requiresApproval = false,
  onDeployed,
  onSubmittedForApproval,
}: DeployDialogProps) {
  const { showToast } = useToast()
  const [step, setStep] = useState<Step>('preflight')

  // Preview state
  const [preview, setPreview] = useState<DeployPreviewResponse | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState('')

  // Reason + submit state
  const [changeReason, setChangeReason] = useState('')
  const [isDeploying, setIsDeploying] = useState(false)
  const [deployError, setDeployError] = useState('')

  const loadPreview = useCallback(async () => {
    setPreviewLoading(true)
    setPreviewError('')
    try {
      const data = await rulesApi.deployPreview(ruleId)
      setPreview(data)
    } catch (err) {
      setPreviewError(err instanceof Error ? err.message : 'Failed to load deploy preview')
    } finally {
      setPreviewLoading(false)
    }
  }, [ruleId])

  // Reset + (re)load preview each time the dialog opens.
  useEffect(() => {
    if (!open) return
    setStep('preflight')
    setChangeReason('')
    setDeployError('')
    setPreview(null)
    loadPreview()
  }, [open, loadPreview])

  // Hard failures block advancing past Preflight.
  const hasValidationFailure = preview ? !preview.validation.success : false
  const hasEligibilityFailure = preview ? !preview.eligibility.eligible : false
  const preflightBlocked = previewLoading || !!previewError || !preview || hasValidationFailure || hasEligibilityFailure

  const handleConfirm = async () => {
    if (!changeReason.trim()) return
    setIsDeploying(true)
    setDeployError('')
    try {
      const deployResult = await rulesApi.deploy(ruleId, changeReason.trim())
      if (deployResult.pendingApproval) {
        showToast('Submitted for approval', 'info')
        onSubmittedForApproval?.()
        onOpenChange(false)
        return
      }
      showToast('Deployed', 'success')
      onDeployed?.(deployResult.result)
      onOpenChange(false)
    } catch (err) {
      if (err instanceof DeploymentUnmappedFieldsError) {
        setDeployError(
          `Deployment blocked — unmapped fields: ${err.unmapped_fields.join(', ')}. Map these fields and retry.`
        )
      } else {
        setDeployError(err instanceof Error ? err.message : 'Deploy failed')
      }
    } finally {
      setIsDeploying(false)
    }
  }

  const goNext = () => {
    const idx = STEP_ORDER.indexOf(step)
    if (idx < STEP_ORDER.length - 1) setStep(STEP_ORDER[idx + 1])
  }
  const goBack = () => {
    const idx = STEP_ORDER.indexOf(step)
    if (idx > 0) setStep(STEP_ORDER[idx - 1])
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Deploy &ldquo;{ruleTitle}&rdquo;</DialogTitle>
          <DialogDescription>
            Review the preflight checks and changes before deploying.
          </DialogDescription>
        </DialogHeader>

        {/* Step indicator */}
        <div className="flex items-center gap-2" aria-label="Deploy steps">
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
          {/* --- Preflight --- */}
          {step === 'preflight' && (
            <div className="space-y-4">
              {previewLoading && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running preflight checks…
                </div>
              )}

              {previewError && (
                <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
                  {previewError}
                </div>
              )}

              {preview && !previewLoading && (
                <>
                  {/* Validation */}
                  <div
                    className={cn(
                      'flex items-start gap-2 rounded-lg border p-3 text-sm',
                      preview.validation.success
                        ? 'border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400'
                        : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400'
                    )}
                  >
                    {preview.validation.success ? (
                      <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <div className="font-medium">
                        {preview.validation.success ? 'Validation passed' : 'Validation failed'}
                      </div>
                      {preview.validation.errors.length > 0 && (
                        <ul className="mt-1 list-disc pl-4">
                          {preview.validation.errors.map((e, i) => (
                            <li key={i}>{e.message}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>

                  {/* Eligibility */}
                  <div
                    className={cn(
                      'flex items-start gap-2 rounded-lg border p-3 text-sm',
                      preview.eligibility.eligible
                        ? 'border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-400'
                        : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400'
                    )}
                  >
                    {preview.eligibility.eligible ? (
                      <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <div className="font-medium">
                        {preview.eligibility.eligible
                          ? 'Eligible for deployment'
                          : 'Not eligible for deployment'}
                      </div>
                      {preview.eligibility.reason && (
                        <div className="mt-0.5">{preview.eligibility.reason}</div>
                      )}
                      {preview.eligibility.unmapped_fields &&
                        preview.eligibility.unmapped_fields.length > 0 && (
                          <div className="mt-0.5">
                            Unmapped fields: {preview.eligibility.unmapped_fields.join(', ')}
                          </div>
                        )}
                    </div>
                  </div>

                  {/* Optional dry-run */}
                  {preview.dry_run && (
                    <div className="rounded-lg border p-3 text-sm">
                      <div className="text-muted-foreground">Dry-run (last 24h)</div>
                      {preview.dry_run.error ? (
                        <div className="mt-1 flex items-center gap-2 text-amber-600 dark:text-amber-400">
                          <AlertTriangle className="h-4 w-4" />
                          {preview.dry_run.error}
                        </div>
                      ) : (
                        <div className="mt-1 flex gap-6">
                          <div>
                            <div className="text-xs text-muted-foreground">Scanned</div>
                            <div className="text-lg font-semibold">
                              {preview.dry_run.total_scanned.toLocaleString()}
                            </div>
                          </div>
                          <div>
                            <div className="text-xs text-muted-foreground">Matches</div>
                            <div className="text-lg font-semibold">
                              {preview.dry_run.total_matches.toLocaleString()}
                              {preview.dry_run.truncated && '+'}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* --- Diff --- */}
          {step === 'diff' && preview && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">
                {preview.current_deployed_query == null
                  ? 'This rule is not currently deployed — showing the full proposed query.'
                  : 'Current (deployed) query → proposed query.'}
              </div>
              <YamlDiff
                current={preview.current_deployed_query ?? ''}
                proposed={preview.proposed_query ?? ''}
                className="max-h-[45vh]"
              />
            </div>
          )}

          {/* --- Reason --- */}
          {step === 'reason' && (
            <div className="space-y-4">
              {requiresApproval && (
                <div className="flex items-start gap-2 rounded-lg border border-blue-500/40 bg-blue-500/10 p-3 text-sm text-blue-700 dark:text-blue-400">
                  <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>
                    This deploy needs approval. Submitting will file a deployment request for a
                    second reviewer instead of deploying immediately.
                  </span>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="deploy-change-reason">Reason for deploy *</Label>
                <Textarea
                  id="deploy-change-reason"
                  placeholder="e.g., Ready for production, completed testing…"
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
              {deployError && (
                <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
                  {deployError}
                </div>
              )}
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <div>
                  <span className="text-muted-foreground">Rule: </span>
                  {ruleTitle}
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
            {step !== 'preflight' && (
              <Button variant="ghost" onClick={goBack} disabled={isDeploying}>
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back
              </Button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isDeploying}>
              Cancel
            </Button>
            {step === 'preflight' && (
              <Button onClick={goNext} disabled={preflightBlocked}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
            {step === 'diff' && (
              <Button onClick={goNext}>
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
              <Button onClick={handleConfirm} disabled={isDeploying || !changeReason.trim()}>
                {isDeploying
                  ? 'Submitting…'
                  : requiresApproval
                    ? 'Submit for approval'
                    : 'Deploy'}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
