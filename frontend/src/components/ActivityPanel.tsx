import { useState, useEffect, useMemo } from 'react'
import { X, GitCommit, Rocket, MessageSquare, RotateCcw, ShieldAlert, TrendingUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TooltipProvider } from '@/components/ui/tooltip'
import { rulesApi, ActivityItem } from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'
import { RestoreDiffModal } from './RestoreDiffModal'
import { TimestampTooltip } from './timestamp-tooltip'

interface ActivityPanelProps {
  ruleId: string
  currentYaml: string
  currentVersion: number
  isOpen: boolean
  onClose: () => void
  onRestore: (versionNumber: number) => void
  canManageRules?: boolean
}

export function ActivityPanel({ ruleId, currentYaml, currentVersion, isOpen, onClose, onRestore, canManageRules = true }: ActivityPanelProps) {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [restoreTarget, setRestoreTarget] = useState<{ versionNumber: number; yaml: string; changeReason?: string } | null>(null)
  const [isRestoring, setIsRestoring] = useState(false)
  const [ruleVersionsMap, setRuleVersionsMap] = useState<Record<number, { change_reason: string }>>({})

  const activityItems = useMemo(
    () => activities.filter(a => a.type !== 'version'),
    [activities]
  )

  const versionItems = useMemo(
    () => activities.filter(a => a.type === 'version'),
    [activities]
  )

  useEffect(() => {
    const abortController = new AbortController()

    const loadActivityData = async () => {
      if (!isOpen || !ruleId) return
      setIsLoading(true)
      try {
        const data = await rulesApi.getActivity(ruleId)
        if (!abortController.signal.aborted) {
          setActivities(data)
        }
      } catch (err) {
        if (!abortController.signal.aborted) {
          console.error('Failed to load activity:', err)
        }
      } finally {
        if (!abortController.signal.aborted) {
          setIsLoading(false)
        }
      }
    }

    const loadRuleVersions = async () => {
      if (!isOpen || !ruleId) return
      try {
        const ruleDetail = await rulesApi.get(ruleId)
        if (!abortController.signal.aborted && ruleDetail.versions) {
          // Create map: version_number -> change_reason
          const versionMap: Record<number, { change_reason: string }> = {}
          ruleDetail.versions.forEach((v) => {
            versionMap[v.version_number] = { change_reason: v.change_reason }
          })
          setRuleVersionsMap(versionMap)
        }
      } catch (err) {
        if (!abortController.signal.aborted) {
          console.error('Failed to load rule versions:', err)
        }
      }
    }

    loadActivityData()
    loadRuleVersions()

    return () => abortController.abort()
  }, [isOpen, ruleId])

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [isOpen, onClose])

  const loadActivity = async () => {
    setIsLoading(true)
    try {
      const data = await rulesApi.getActivity(ruleId)
      setActivities(data)
    } catch (err) {
      console.error('Failed to load activity:', err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleAddComment = async () => {
    if (!newComment.trim()) return
    setIsSubmitting(true)
    try {
      await rulesApi.addComment(ruleId, newComment)
      setNewComment('')
      loadActivity()
    } catch (err) {
      console.error('Failed to add comment:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleRestoreClick = (versionNumber: number, yaml: string) => {
    // Get change_reason from the rule versions map we fetched
    const versionData = ruleVersionsMap[versionNumber]
    const actualChangeReason = versionData?.change_reason

    setRestoreTarget({
      versionNumber,
      yaml,
      changeReason: actualChangeReason
    })
  }

  const handleRestoreConfirm = async () => {
    if (!restoreTarget) return
    setIsRestoring(true)
    try {
      await onRestore(restoreTarget.versionNumber)
      setRestoreTarget(null)
    } finally {
      setIsRestoring(false)
    }
  }

  if (!isOpen) return null

  return (
    <TooltipProvider>
      {/* Overlay for click-to-close */}
      <div
        className="fixed inset-0 bg-black/20 z-40"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        className="fixed right-0 top-16 h-[calc(100%-4rem)] w-96 bg-background border-l shadow-lg z-40 flex flex-col"
        role="dialog"
        aria-modal="true"
        aria-label="Rule activity panel"
      >
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="font-semibold">Activity & History</h2>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close activity panel">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <Tabs defaultValue="activity" className="flex-1 flex flex-col min-h-0">
        <TabsList className="mx-4 mt-2 shrink-0">
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="versions">Versions</TabsTrigger>
        </TabsList>

        <TabsContent value="activity" className="flex-1 flex flex-col min-h-0 mt-2 data-[state=inactive]:hidden">
          <div className="flex-1 overflow-auto p-4 space-y-4">
            {isLoading ? (
              <div className="text-center text-muted-foreground">Loading...</div>
            ) : activityItems.length === 0 ? (
              <div className="text-center text-muted-foreground">No activity yet</div>
            ) : (
              activityItems.map((activity) => (
                <div key={`${activity.type}-${activity.timestamp}`} className="flex gap-3">
                  <div className="flex-shrink-0 mt-1">
                    {activity.type === 'deploy' && <Rocket className="h-4 w-4 text-green-500" />}
                    {activity.type === 'undeploy' && <Rocket className="h-4 w-4 text-orange-500" />}
                    {activity.type === 'comment' && <MessageSquare className="h-4 w-4 text-purple-500" />}
                    {activity.type === 'exception' && <ShieldAlert className="h-4 w-4 text-yellow-500" />}
                    {activity.type === 'threshold' && <TrendingUp className="h-4 w-4 text-blue-500" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 text-sm">
                      {activity.type === 'deploy' && (
                        <span className="text-green-600">Deployed</span>
                      )}
                      {activity.type === 'undeploy' && (
                        <span className="text-orange-600">Undeployed</span>
                      )}
                      {activity.type === 'comment' && (
                        <span className="font-medium">{activity.user_email}</span>
                      )}
                      {activity.type === 'exception' && (
                        <span className="text-yellow-600 font-medium">
                          Exception {(() => {
                            const action = String(activity.data.action || '')
                            if (action === 'create') return 'Created'
                            if (action === 'delete') return 'Deleted'
                            if (action === 'update') {
                              // Check if it's being enabled/disabled based on is_active
                              const isActive = activity.data.is_active === true
                              return isActive ? 'Enabled' : 'Disabled'
                            }
                            return 'Changed'
                          })()}
                        </span>
                      )}
                      {activity.type === 'threshold' && (
                        <span className="text-blue-600 font-medium">
                          Threshold Alerting {(() => {
                            const action = String(activity.data.action || '')
                            if (action === 'enabled') return 'Enabled'
                            if (action === 'disabled') return 'Disabled'
                            return 'Updated'
                          })()}
                        </span>
                      )}
                    </div>

                    {activity.type === 'comment' && (
                      <p className="text-sm mt-1">{String(activity.data.content)}</p>
                    )}

                    {activity.type === 'exception' && !!activity.data.reason && (
                      <p className="text-sm mt-1 italic text-muted-foreground">Reason: {String(activity.data.reason)}</p>
                    )}

                    {activity.type === 'exception' && (
                      <p className="text-sm mt-1">
                        {String(activity.data.field)} {String(activity.data.operator)} {String(activity.data.value)}
                      </p>
                    )}

                    {activity.type === 'threshold' && !!activity.data.changes && (
                      <p className="text-sm mt-1 text-muted-foreground">
                        {Object.entries(activity.data.changes as Record<string, {old: unknown, new: unknown}>).map(([field, values]) => {
                          // Format field names nicely
                          const fieldName = field.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
                          return `${fieldName}: ${String(values.old)} → ${String(values.new)}`
                        }).join(', ')}
                      </p>
                    )}

                    <div className="text-xs text-muted-foreground mt-1">
                      <TimestampTooltip timestamp={activity.timestamp}>
                        <span>{formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}</span>
                      </TimestampTooltip>
                      {activity.user_email && activity.type !== 'comment' && (
                        <span> by {activity.user_email}</span>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="p-4 border-t">
            <Textarea
              placeholder="Add a comment..."
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              className="mb-2"
              rows={2}
            />
            <Button
              onClick={handleAddComment}
              disabled={isSubmitting || !newComment.trim()}
              className="w-full"
            >
              {isSubmitting ? 'Adding...' : 'Add Comment'}
            </Button>
          </div>
        </TabsContent>

        <TabsContent value="versions" className="flex-1 overflow-auto p-4 space-y-3 mt-2 data-[state=inactive]:hidden">
          {isLoading ? (
            <div className="text-center text-muted-foreground">Loading...</div>
          ) : versionItems.length === 0 ? (
            <div className="text-center text-muted-foreground">No versions yet</div>
          ) : (
            versionItems.map((activity) => (
              <div key={`version-${activity.data.version_number}`} className="flex gap-3 items-start">
                <div className="flex-shrink-0 mt-1">
                  <GitCommit className="h-4 w-4 text-blue-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="font-medium">v{String(activity.data.version_number)}</span>
                    <span className="text-muted-foreground">created</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    <TimestampTooltip timestamp={activity.timestamp}>
                      <span>{formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}</span>
                    </TimestampTooltip>
                    {activity.user_email && <span> by {activity.user_email}</span>}
                  </div>
                </div>
                {Number(activity.data.version_number) === currentVersion ? (
                  <span className="text-xs text-muted-foreground px-2">(Current)</span>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    disabled={!canManageRules}
                    onClick={() => handleRestoreClick(
                      Number(activity.data.version_number),
                      String(activity.data.yaml_content)
                    )}
                  >
                    <RotateCcw className="h-3 w-3 mr-1" />
                    Restore
                  </Button>
                )}
              </div>
            ))
          )}
        </TabsContent>
      </Tabs>
    </div>

      {restoreTarget && (
        <RestoreDiffModal
          isOpen={!!restoreTarget}
          onClose={() => setRestoreTarget(null)}
          onConfirm={handleRestoreConfirm}
          currentYaml={currentYaml}
          targetYaml={restoreTarget.yaml}
          targetVersion={restoreTarget.versionNumber}
          currentVersion={currentVersion}
          isRestoring={isRestoring}
          targetChangeReason={restoreTarget.changeReason}
        />
      )}
    </TooltipProvider>
  )
}
