import { Badge } from '@/components/ui/badge'
import type { BadgeProps } from '@/components/ui/badge'

// Minimal shape needed to derive a deploy-status badge. Accepts a full Rule or
// the equivalent fields from the editor so both call sites can reuse it.
export type DeployBadgeRule = {
  status: string
  deployed_version?: number | null
  needs_redeploy?: boolean
  snooze_indefinite?: boolean
  // Optional: present when the backend flags an open dual-control request.
  has_open_request?: boolean
}

export type DeployBadgeKind =
  | 'pending_approval'
  | 'snoozed'
  | 'needs_redeploy'
  | 'deployed'
  | 'undeployed'

export type DeployBadgeDescriptor = {
  kind: DeployBadgeKind
  label: string
  variant: BadgeProps['variant']
}

/**
 * Pure derivation of the deployment-status badge for a rule. Precedence:
 *   pending approval  → open dual-control request (cannot also be acting)
 *   snoozed           → snoozed status
 *   needs redeploy    → deployed but current version differs
 *   deployed vN       → live, current
 *   undeployed        → not deployed
 * Exported separately so it can be unit-tested without rendering.
 */
export function getDeployBadge(rule: DeployBadgeRule): DeployBadgeDescriptor {
  if (rule.has_open_request) {
    return { kind: 'pending_approval', label: 'Pending approval', variant: 'info-subtle' }
  }
  if (rule.status === 'snoozed') {
    return {
      kind: 'snoozed',
      label: rule.snooze_indefinite ? 'Snoozed (indefinite)' : 'Snoozed',
      variant: 'warning-subtle',
    }
  }
  if (rule.needs_redeploy) {
    return { kind: 'needs_redeploy', label: 'Needs redeploy', variant: 'warning-subtle' }
  }
  if (rule.status === 'deployed') {
    const v = rule.deployed_version
    return {
      kind: 'deployed',
      label: v != null ? `Deployed v${v}` : 'Deployed',
      variant: 'success-subtle',
    }
  }
  return { kind: 'undeployed', label: 'Undeployed', variant: 'secondary' }
}

interface DeployStatusBadgeProps {
  rule: DeployBadgeRule
  className?: string
}

/**
 * Consistent deployment-status badge used in Rules.tsx rows and the
 * RuleEditor.tsx header. Reuses the shared Badge variants.
 */
export function DeployStatusBadge({ rule, className }: DeployStatusBadgeProps) {
  const { label, variant } = getDeployBadge(rule)
  return (
    <Badge variant={variant} className={className}>
      {label}
    </Badge>
  )
}
