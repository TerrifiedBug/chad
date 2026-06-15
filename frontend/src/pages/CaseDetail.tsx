import { useState } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Trash2, Plus, MessageSquare, Clock } from 'lucide-react'
import { casesApi, alertsApi, type CaseStatus } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { RelativeTime } from '@/components/RelativeTime'
import { SeverityBadge } from '@/components/ui/severity-badge'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

const STATUS_OPTIONS: CaseStatus[] = ['open', 'investigating', 'contained', 'closed']

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { hasPermission, user } = useAuth()
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const canManage = hasPermission('manage_alerts')

  const [newAlertId, setNewAlertId] = useState('')
  const [comment, setComment] = useState('')

  const { data: c, isLoading } = useQuery({
    queryKey: ['case', id],
    queryFn: () => casesApi.get(id!),
    enabled: !!id,
  })

  const { data: assignable = [] } = useQuery({
    queryKey: ['assignable-users'],
    queryFn: () => alertsApi.assignableUsers(),
    enabled: canManage,
    staleTime: 5 * 60_000,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['case', id] })
  const onErr = (err: unknown) => showToast(err instanceof Error ? err.message : 'Action failed', 'error')

  const statusMutation = useMutation({
    mutationFn: (s: CaseStatus) => casesApi.setStatus(id!, s),
    onSuccess: invalidate, onError: onErr,
  })
  const assignMutation = useMutation({
    mutationFn: (ownerId: string | null) => casesApi.assign(id!, ownerId),
    onSuccess: invalidate, onError: onErr,
  })
  const addAlertMutation = useMutation({
    mutationFn: (alertId: string) => casesApi.addAlerts(id!, [alertId]),
    onSuccess: () => { setNewAlertId(''); invalidate() }, onError: onErr,
  })
  const removeAlertMutation = useMutation({
    mutationFn: (alertId: string) => casesApi.removeAlert(id!, alertId),
    onSuccess: invalidate, onError: onErr,
  })
  const commentMutation = useMutation({
    mutationFn: (content: string) => casesApi.addComment(id!, content),
    onSuccess: () => { setComment(''); invalidate() }, onError: onErr,
  })
  const deleteCommentMutation = useMutation({
    mutationFn: (commentId: string) => casesApi.deleteComment(id!, commentId),
    onSuccess: invalidate, onError: onErr,
  })

  if (isLoading || !c) {
    return <div className="p-8 text-muted-foreground">Loading case…</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <button onClick={() => navigate('/cases')} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> Cases
          </button>
          <h1 className="text-xl font-semibold flex items-center gap-3">
            <span className="font-mono text-sm text-muted-foreground">CASE-{c.number}</span>
            {c.title}
            {c.sla_breached && c.status !== 'closed' && <Badge variant="destructive">SLA overdue</Badge>}
          </h1>
          {c.description && <p className="text-sm text-muted-foreground max-w-2xl">{c.description}</p>}
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={c.severity} />
          <Select
            value={c.status}
            onValueChange={(v) => statusMutation.mutate(v as CaseStatus)}
            disabled={!canManage}
          >
            <SelectTrigger className="w-40 h-9 capitalize"><SelectValue /></SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((s) => (
                <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-6">
        {/* Main: alerts + comments */}
        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Linked alerts ({c.alerts.length})</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {c.alerts.length === 0 && <p className="text-sm text-muted-foreground">No alerts linked yet.</p>}
              {c.alerts.map((a) => (
                <div key={a.id} className="flex items-center justify-between gap-2 rounded border p-2">
                  <Link to={`/alerts/${a.alert_id}`} className="min-w-0 truncate text-sm hover:underline">
                    {a.alert_title || a.alert_id}
                  </Link>
                  <div className="flex items-center gap-2">
                    {a.alert_severity && <SeverityBadge severity={a.alert_severity} />}
                    {canManage && (
                      <button
                        className="text-muted-foreground hover:text-destructive"
                        onClick={() => removeAlertMutation.mutate(a.alert_id)}
                        aria-label="Unlink alert"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {canManage && (
                <div className="flex items-center gap-2 pt-2">
                  <Input
                    placeholder="Alert ID to link…"
                    value={newAlertId}
                    onChange={(e) => setNewAlertId(e.target.value)}
                    className="h-8"
                  />
                  <Button size="sm" variant="outline" disabled={!newAlertId.trim() || addAlertMutation.isPending}
                    onClick={() => addAlertMutation.mutate(newAlertId.trim())}>
                    <Plus className="h-3.5 w-3.5" />
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <MessageSquare className="h-4 w-4" /> Comments
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {c.comments.length === 0 && <p className="text-sm text-muted-foreground">No comments.</p>}
              {c.comments.map((cm) => (
                <div key={cm.id} className="rounded border p-2">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{cm.user_email || 'Unknown'}</span>
                    <span className="flex items-center gap-2">
                      <RelativeTime date={cm.created_at} />
                      {(cm.user_id === user?.id) && (
                        <button className="hover:text-destructive" onClick={() => deleteCommentMutation.mutate(cm.id)} aria-label="Delete comment">
                          <Trash2 className="h-3 w-3" />
                        </button>
                      )}
                    </span>
                  </div>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{cm.content}</p>
                </div>
              ))}
              {canManage && (
                <div className="space-y-2">
                  <Textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2} placeholder="Add a comment…" />
                  <div className="flex justify-end">
                    <Button size="sm" disabled={!comment.trim() || commentMutation.isPending}
                      onClick={() => commentMutation.mutate(comment.trim())}>
                      Comment
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Sidebar: owner + timeline */}
        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-sm font-medium">Details</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Owner</span>
                {canManage ? (
                  <Select
                    value={c.owner_id ?? 'unassigned'}
                    onValueChange={(v) => assignMutation.mutate(v === 'unassigned' ? null : v)}
                  >
                    <SelectTrigger className="w-44 h-8"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="unassigned">Unassigned</SelectItem>
                      {assignable.map((u) => (
                        <SelectItem key={u.id} value={u.id}>{u.email}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <span>{c.owner_email || 'Unassigned'}</span>
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Created</span>
                <RelativeTime date={c.created_at} />
              </div>
              {c.closed_at && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Closed</span>
                  <RelativeTime date={c.closed_at} />
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4" /> Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="relative border-l pl-4 space-y-3">
                {c.events.map((e) => (
                  <li key={e.id} className="text-sm">
                    <div className="absolute -left-1.5 mt-1 h-3 w-3 rounded-full bg-muted-foreground/40" />
                    <p>{e.message}</p>
                    <p className="text-xs text-muted-foreground">
                      {e.actor_email ? `${e.actor_email} · ` : ''}<RelativeTime date={e.created_at} />
                    </p>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
