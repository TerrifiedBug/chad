import { useState, useEffect } from 'react'
import { X, GitCommit, Rocket, MessageSquare, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { rulesApi, ActivityItem } from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'

interface ActivityPanelProps {
  ruleId: string
  isOpen: boolean
  onClose: () => void
  onRestore: (versionNumber: number) => void
}

export function ActivityPanel({ ruleId, isOpen, onClose, onRestore }: ActivityPanelProps) {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

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

    loadActivityData()

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

  if (!isOpen) return null

  return (
    <div
      className="fixed right-0 top-0 h-full w-96 bg-background border-l shadow-lg z-50 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="Rule activity panel"
    >
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="font-semibold">Activity</h2>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close activity panel">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {isLoading ? (
          <div className="text-center text-muted-foreground">Loading...</div>
        ) : activities.length === 0 ? (
          <div className="text-center text-muted-foreground">No activity yet</div>
        ) : (
          activities.map((activity, idx) => (
            <div key={idx} className="flex gap-3">
              <div className="flex-shrink-0 mt-1">
                {activity.type === 'version' && <GitCommit className="h-4 w-4 text-blue-500" />}
                {activity.type === 'deploy' && <Rocket className="h-4 w-4 text-green-500" />}
                {activity.type === 'undeploy' && <Rocket className="h-4 w-4 text-orange-500" />}
                {activity.type === 'comment' && <MessageSquare className="h-4 w-4 text-purple-500" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 text-sm">
                  {activity.type === 'version' && (
                    <>
                      <span className="font-medium">v{String(activity.data.version_number)}</span>
                      <span className="text-muted-foreground">created</span>
                    </>
                  )}
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

                {activity.type === 'version' && (
                  <div className="mt-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={() => onRestore(Number(activity.data.version_number))}
                    >
                      <RotateCcw className="h-3 w-3 mr-1" />
                      Restore
                    </Button>
                  </div>
                )}

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
    </div>
  )
}
