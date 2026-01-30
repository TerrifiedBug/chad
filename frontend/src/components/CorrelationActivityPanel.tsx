import { useState, useEffect, useMemo } from 'react'
import { X, GitCommit, Rocket, MessageSquare, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { correlationRulesApi, CorrelationActivityItem } from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'
import { CorrelationRestoreDiffModal } from './CorrelationRestoreDiffModal'

interface CorrelationActivityPanelProps {
  correlationId: string
  isOpen: boolean
  onClose: () => void
  currentVersion: number
  currentData: {
    name: string
    rule_a_id: string
    rule_b_id: string
    entity_field: string
    entity_field_type: string
    time_window_minutes: number
    severity: string
  }
  onRestore: (versionNumber: number, reason: string) => Promise<void>
}

export function CorrelationActivityPanel({
  correlationId,
  isOpen,
  onClose,
  currentVersion,
  currentData,
  onRestore,
}: CorrelationActivityPanelProps) {
  const [activities, setActivities] = useState<CorrelationActivityItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [restoreTarget, setRestoreTarget] = useState<{
    versionNumber: number
    data: {
      name: string
      rule_a_id: string
      rule_b_id: string
      entity_field: string
      time_window_minutes: number
      severity: string
    }
    changeReason?: string
  } | null>(null)
  const [isRestoring, setIsRestoring] = useState(false)

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
      if (!isOpen || !correlationId) return
      setIsLoading(true)
      try {
        const data = await correlationRulesApi.getActivity(correlationId)
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

    loadActivityData()

    return () => abortController.abort()
  }, [isOpen, correlationId])

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
      const data = await correlationRulesApi.getActivity(correlationId)
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
      await correlationRulesApi.addComment(correlationId, newComment)
      setNewComment('')
      loadActivity()
    } catch (err) {
      console.error('Failed to add comment:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleRestoreClick = (versionNumber: number, data: CorrelationActivityItem['data'], changeReason?: string) => {
    setRestoreTarget({
      versionNumber,
      data: {
        name: String(data.name || ''),
        rule_a_id: String(data.rule_a_id || ''),
        rule_b_id: String(data.rule_b_id || ''),
        entity_field: String(data.entity_field || ''),
        time_window_minutes: Number(data.time_window_minutes) || 0,
        severity: String(data.severity || ''),
      },
      changeReason,
    })
  }

  const handleRestoreConfirm = async (reason: string) => {
    if (!restoreTarget) return
    setIsRestoring(true)
    try {
      await onRestore(restoreTarget.versionNumber, reason)
      setRestoreTarget(null)
      loadActivity()
    } finally {
      setIsRestoring(false)
    }
  }

  if (!isOpen) return null

  return (
    <>
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
        aria-label="Correlation rule activity panel"
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
                activityItems.map((activity, index) => (
                  <div key={`${activity.type}-${activity.timestamp}-${index}`} className="flex gap-3">
                    <div className="flex-shrink-0 mt-1">
                      {activity.type === 'deploy' && <Rocket className="h-4 w-4 text-green-500" />}
                      {activity.type === 'undeploy' && <Rocket className="h-4 w-4 text-orange-500" />}
                      {activity.type === 'comment' && <MessageSquare className="h-4 w-4 text-purple-500" />}
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
                      </div>

                      {activity.type === 'comment' && (
                        <p className="text-sm mt-1">{String(activity.data.content)}</p>
                      )}

                      {(activity.type === 'deploy' || activity.type === 'undeploy') && activity.data.change_reason ? (
                        <p className="text-sm text-muted-foreground mt-1">{String(activity.data.change_reason)}</p>
                      ) : null}

                      <div className="text-xs text-muted-foreground mt-1">
                        {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
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
                      {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
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
                      onClick={() => {
                        handleRestoreClick(
                          Number(activity.data.version_number),
                          activity.data,
                          activity.data.change_reason && typeof activity.data.change_reason === 'string' ? activity.data.change_reason : undefined
                        )
                      }}
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
        <CorrelationRestoreDiffModal
          isOpen={!!restoreTarget}
          onClose={() => setRestoreTarget(null)}
          onConfirm={handleRestoreConfirm}
          currentData={currentData}
          targetData={restoreTarget.data}
          targetVersion={restoreTarget.versionNumber}
          currentVersion={currentVersion}
          isRestoring={isRestoring}
          targetChangeReason={restoreTarget.changeReason}
        />
      )}
    </>
  )
}
