import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  deploymentRequestsApi,
  environmentsApi,
  DeploymentRequestResponse,
  DeploymentRequestDetailResponse,
  DeploymentRequestItemDetail,
  DeploymentRequestStatus,
} from '@/lib/api'
import { ENVIRONMENTS_QUERY_KEY } from '@/components/EnvironmentSelector'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { PageHeader } from '@/components/PageHeader'
import { KpiStrip, KpiTile } from '@/components/ui/kpi-tile'
import { YamlDiff } from '@/components/YamlDiff'
import { RelativeTime } from '@/components/RelativeTime'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Tabs,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'
import { CheckCheck, Check, X, Loader2, Ban, Layers, ArrowRight } from 'lucide-react'
import { capitalize } from '@/lib/constants'

const DEPLOYMENT_REQUESTS_KEY = 'deployment-requests'

// Tabs surfaced in the queue, mapped to the status_filter value.
const STATUS_TABS: { value: DeploymentRequestStatus; label: string }[] = [
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'applied', label: 'Applied' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'stale', label: 'Stale' },
  { value: 'failed', label: 'Failed' },
]

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info' | 'success-subtle' | 'warning-subtle' | 'info-subtle' | 'destructive-subtle'

function statusBadgeVariant(status: string): BadgeVariant {
  switch (status) {
    case 'pending':
      return 'warning-subtle'
    case 'approved':
      return 'info-subtle'
    case 'applied':
      return 'success-subtle'
    case 'rejected':
    case 'failed':
      return 'destructive-subtle'
    case 'stale':
      return 'warning'
    case 'cancelled':
    default:
      return 'secondary'
  }
}

function formatAvgReview(seconds: number | null): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${(seconds / 3600).toFixed(1)}h`
}

/**
 * Badge shown on requests that carry a target_environment_id — i.e. promotions.
 * Resolves the env name from the cached environment list and renders
 * "promote → {env}" so a reviewer sees the promotion target at a glance.
 * Renders nothing for plain (non-promotion) deploy requests.
 */
function TargetEnvBadge({ targetEnvironmentId }: { targetEnvironmentId?: string | null }) {
  const { data: environments } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY],
    queryFn: () => environmentsApi.list(),
    retry: false,
    enabled: !!targetEnvironmentId,
  })

  if (!targetEnvironmentId) return null
  const env = environments?.find((e) => e.id === targetEnvironmentId)
  const name = env?.name ?? 'environment'

  return (
    <Badge variant="info-subtle" className="gap-1" aria-label={`Promote to ${name}`}>
      <ArrowRight className="h-3 w-3" />
      <Layers className="h-3 w-3" />
      {name}
    </Badge>
  )
}

export default function ApprovalsPage() {
  const { user, hasPermission } = useAuth()
  const { showToast } = useToast()
  const queryClient = useQueryClient()

  const [activeTab, setActiveTab] = useState<DeploymentRequestStatus>('pending')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [rejectNote, setRejectNote] = useState('')

  const canApprove = hasPermission('approve_deployments')

  const statsQuery = useQuery({
    queryKey: [DEPLOYMENT_REQUESTS_KEY, 'stats'],
    queryFn: () => deploymentRequestsApi.getStats(),
  })

  const listQuery = useQuery({
    queryKey: [DEPLOYMENT_REQUESTS_KEY, 'list', activeTab],
    queryFn: () => deploymentRequestsApi.list(activeTab),
  })

  const detailQuery = useQuery({
    queryKey: [DEPLOYMENT_REQUESTS_KEY, 'detail', selectedId],
    queryFn: () => deploymentRequestsApi.get(selectedId as string),
    enabled: !!selectedId,
  })

  const refetchAll = () => {
    queryClient.invalidateQueries({ queryKey: [DEPLOYMENT_REQUESTS_KEY] })
  }

  const approveMutation = useMutation({
    mutationFn: (id: string) => deploymentRequestsApi.approve(id),
    onSuccess: () => {
      showToast('Deployment request approved', 'success')
      setSelectedId(null)
      refetchAll()
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Approve failed', 'error')
    },
  })

  const rejectMutation = useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      deploymentRequestsApi.reject(id, note),
    onSuccess: () => {
      showToast('Deployment request rejected', 'success')
      setRejectOpen(false)
      setRejectNote('')
      setSelectedId(null)
      refetchAll()
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Reject failed', 'error')
    },
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => deploymentRequestsApi.cancel(id),
    onSuccess: () => {
      showToast('Deployment request cancelled', 'success')
      setSelectedId(null)
      refetchAll()
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Cancel failed', 'error')
    },
  })

  const detail = detailQuery.data
  const isOwnRequest = !!detail && !!user && detail.requested_by === user.id
  const isPending = detail?.status === 'pending'
  // Approve/reject are blocked for the requester (self-review) and for users
  // lacking the approve_deployments permission.
  const reviewDisabled = !canApprove || isOwnRequest
  const reviewDisabledReason = isOwnRequest
    ? 'You cannot approve your own request'
    : !canApprove
      ? 'You lack the approve_deployments permission'
      : ''

  const stats = statsQuery.data

  return (
    <TooltipProvider>
      <div className="space-y-6">
        <PageHeader
          title="Deployment Approvals"
          description="Review and approve rule deployments under dual-control."
        />

        {/* VF console KPI strip — matches the Dashboard's metric presentation.
            Open carries a degraded tone while there's a pending-review backlog. */}
        <KpiStrip>
          <KpiTile
            label="Open"
            value={stats?.pending ?? 0}
            sublabel="Pending review"
            tone={stats && stats.pending > 0 ? 'degraded' : 'accent'}
          />
          <KpiTile
            label="Approved"
            value={stats?.approved ?? 0}
            sublabel="Awaiting apply"
            tone="healthy"
          />
          <KpiTile
            label="Rejected"
            value={stats?.rejected ?? 0}
            sublabel="Declined requests"
            tone={(stats?.rejected ?? 0) > 0 ? 'error' : 'default'}
          />
          <KpiTile
            label="Avg review time"
            value={formatAvgReview(stats?.avg_review_seconds ?? null)}
            sublabel="Time to decision"
          />
        </KpiStrip>

        {/* Status tabs */}
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as DeploymentRequestStatus)}>
          <TabsList className="flex-wrap h-auto">
            {STATUS_TABS.map((tab) => (
              <TabsTrigger key={tab.value} value={tab.value}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>

        {/* Request queue */}
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rules</TableHead>
                <TableHead>Requested by</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Age</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {listQuery.isLoading ? (
                <TableRow>
                  <TableCell colSpan={4}>
                    <LoadingState message="Loading deployment requests..." />
                  </TableCell>
                </TableRow>
              ) : !listQuery.data || listQuery.data.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4}>
                    <EmptyState
                      icon={<CheckCheck className="h-12 w-12" />}
                      title="No deployment requests"
                      description="Requests in this state will appear here."
                    />
                  </TableCell>
                </TableRow>
              ) : (
                listQuery.data.map((req: DeploymentRequestResponse) => (
                  <TableRow
                    key={req.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedId(req.id)}
                  >
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <span>
                          {req.rule_titles[0] || 'Untitled rule'}
                          {req.item_count > 1 && (
                            <span className="text-muted-foreground">
                              {' '}+{req.item_count - 1} more
                            </span>
                          )}
                        </span>
                        <TargetEnvBadge targetEnvironmentId={req.target_environment_id} />
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {req.requester_email || 'Unknown'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusBadgeVariant(req.status)}>
                        {capitalize(req.status)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      <RelativeTime date={req.created_at} />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Detail dialog */}
        <Dialog open={!!selectedId} onOpenChange={(open) => !open && setSelectedId(null)}>
          <DialogContent className="max-w-4xl max-h-[85vh] overflow-auto">
            <DialogHeader>
              <DialogTitle>Deployment Request</DialogTitle>
              <DialogDescription>
                Review the proposed changes before approving.
              </DialogDescription>
            </DialogHeader>

            {detailQuery.isLoading || !detail ? (
              <LoadingState message="Loading request details..." />
            ) : (
              <DeploymentRequestDetail detail={detail} />
            )}

            <DialogFooter className="flex-col sm:flex-row sm:justify-between gap-2">
              {detail && isOwnRequest && isPending && (
                <Button
                  variant="ghost"
                  onClick={() => cancelMutation.mutate(detail.id)}
                  disabled={cancelMutation.isPending}
                >
                  {cancelMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Ban className="h-4 w-4 mr-2" />
                  )}
                  Cancel request
                </Button>
              )}
              {detail && isPending && (
                <div className="flex items-center gap-2 sm:ml-auto">
                  <ReviewButton
                    disabled={reviewDisabled || rejectMutation.isPending}
                    disabledReason={reviewDisabledReason}
                    variant="outline"
                    onClick={() => setRejectOpen(true)}
                    label="Reject"
                    icon={X}
                  />
                  <ReviewButton
                    disabled={reviewDisabled || approveMutation.isPending}
                    disabledReason={reviewDisabledReason}
                    onClick={() => approveMutation.mutate(detail.id)}
                    label="Approve"
                    icon={Check}
                    loading={approveMutation.isPending}
                  />
                </div>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Reject reason dialog */}
        <Dialog open={rejectOpen} onOpenChange={(open) => { setRejectOpen(open); if (!open) setRejectNote('') }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Reject Deployment Request</DialogTitle>
              <DialogDescription>
                Provide a reason for rejecting this deployment request.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2 py-2">
              <Label htmlFor="reject-note">Reason *</Label>
              <Textarea
                id="reject-note"
                placeholder="Explain why this deployment is being rejected..."
                value={rejectNote}
                onChange={(e) => setRejectNote(e.target.value)}
                rows={3}
              />
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => { setRejectOpen(false); setRejectNote('') }}
                disabled={rejectMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => detail && rejectMutation.mutate({ id: detail.id, note: rejectNote })}
                disabled={!rejectNote.trim() || rejectMutation.isPending}
              >
                {rejectMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Rejecting...
                  </>
                ) : (
                  'Reject'
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  )
}

interface ReviewButtonProps {
  disabled: boolean
  disabledReason: string
  onClick: () => void
  label: string
  icon: typeof Check
  variant?: 'default' | 'outline'
  loading?: boolean
}

// Approve/Reject button that shows a tooltip explaining why it is disabled
// (self-review or missing permission).
function ReviewButton({ disabled, disabledReason, onClick, label, icon: Icon, variant = 'default', loading }: ReviewButtonProps) {
  const button = (
    <Button variant={variant} onClick={onClick} disabled={disabled}>
      {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Icon className="h-4 w-4 mr-2" />}
      {label}
    </Button>
  )

  if (disabled && disabledReason) {
    return (
      <Tooltip>
        {/* span wrapper keeps the tooltip working while the button is disabled */}
        <TooltipTrigger asChild>
          <span tabIndex={0}>{button}</span>
        </TooltipTrigger>
        <TooltipContent>{disabledReason}</TooltipContent>
      </Tooltip>
    )
  }

  return button
}

function DeploymentRequestDetail({ detail }: { detail: DeploymentRequestDetailResponse }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Requested by</span>
          <p className="font-medium">{detail.requester_email || 'Unknown'}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Status</span>
          <div className="flex items-center gap-2">
            <Badge variant={statusBadgeVariant(detail.status)}>{capitalize(detail.status)}</Badge>
            <TargetEnvBadge targetEnvironmentId={detail.target_environment_id} />
          </div>
        </div>
        {detail.reviewer_email && (
          <div>
            <span className="text-muted-foreground">Reviewed by</span>
            <p className="font-medium">{detail.reviewer_email}</p>
          </div>
        )}
        <div>
          <span className="text-muted-foreground">Created</span>
          <p className="font-medium">
            <RelativeTime date={detail.created_at} />
          </p>
        </div>
        <div className="col-span-2">
          <span className="text-muted-foreground">Change reason</span>
          <p className="font-medium whitespace-pre-wrap">{detail.change_reason}</p>
        </div>
        {detail.review_note && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Review note</span>
            <p className="font-medium whitespace-pre-wrap">{detail.review_note}</p>
          </div>
        )}
      </div>

      <div className="space-y-4">
        {detail.items.map((item: DeploymentRequestItemDetail) => (
          <div key={item.id} className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium">{item.rule_title || 'Untitled rule'}</span>
              <Badge variant="outline">{item.kind}</Badge>
              <Badge variant="secondary">v{item.version_number}</Badge>
              {item.is_stale && <Badge variant="warning">Stale</Badge>}
              {item.apply_status === 'failed' && <Badge variant="destructive-subtle">Failed</Badge>}
              {item.apply_status === 'ok' && <Badge variant="success-subtle">Applied</Badge>}
              {item.apply_status === 'skipped' && <Badge variant="secondary">Skipped</Badge>}
            </div>
            {item.apply_error && (
              <p className="text-sm text-destructive">{item.apply_error}</p>
            )}
            <YamlDiff
              current={item.deployed_yaml || ''}
              proposed={item.proposed_yaml || ''}
              className="max-h-64"
            />
          </div>
        ))}
      </div>
    </div>
  )
}
