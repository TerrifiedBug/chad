import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { GitPullRequest, AlertTriangle } from 'lucide-react'
import { gitopsApi, type GitImportItem } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'

const STATUS_VARIANT: Record<string, 'secondary' | 'default' | 'outline'> = {
  new: 'default',
  modified: 'secondary',
  unchanged: 'outline',
}

/**
 * Gated inbound GitOps (I6). Inbound is OFF until an admin flips the sign-off
 * switch. Even then, importing only stages git rule changes as UNDEPLOYED draft
 * versions — it never changes what is live (that still needs deploy approval).
 */
export function GitImportPanel({ envId }: { envId: string }) {
  const { isAdmin, hasPermission } = useAuth()
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [items, setItems] = useState<GitImportItem[] | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const { data: flag } = useQuery({ queryKey: ['gitops-inbound'], queryFn: () => gitopsApi.getInbound() })
  const enabled = !!flag?.enabled

  const setFlag = useMutation({
    mutationFn: (v: boolean) => gitopsApi.setInbound(v),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['gitops-inbound'] }); setItems(null) },
    onError: (e) => showToast(e instanceof Error ? e.message : 'Failed', 'error'),
  })
  const preview = useMutation({
    mutationFn: () => gitopsApi.importPreview(envId),
    onSuccess: (res) => {
      setItems(res.items)
      setSelected(new Set(res.items.filter((i) => i.status === 'modified').map((i) => i.path)))
    },
    onError: (e) => showToast(e instanceof Error ? e.message : 'Preview failed', 'error'),
  })
  const apply = useMutation({
    mutationFn: () => gitopsApi.importApply(envId, [...selected]),
    onSuccess: (res) => {
      showToast(`Staged ${res.updated.length} draft change(s), skipped ${res.skipped.length}`, 'success')
      setItems(null)
    },
    onError: (e) => showToast(e instanceof Error ? e.message : 'Import failed', 'error'),
  })

  const toggle = (path: string) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <GitPullRequest className="h-4 w-4" /> Inbound import (GitOps)
            </h3>
            <p className="text-xs text-muted-foreground">
              Import rule changes from this environment's git repo. Off by default
              — even when on, imports stage <strong>undeployed drafts</strong>; nothing
              goes live without the normal deploy approval.
            </p>
          </div>
          {isAdmin && (
            <div className="flex items-center gap-2">
              <Label htmlFor="inbound-flag" className="text-xs">Enable</Label>
              <Switch id="inbound-flag" checked={enabled} onCheckedChange={(v) => setFlag.mutate(v)} />
            </div>
          )}
        </div>

        {!enabled ? (
          <div className="flex items-center gap-2 rounded border border-dashed p-3 text-xs text-muted-foreground">
            <AlertTriangle className="h-4 w-4" />
            Inbound GitOps is disabled. {isAdmin ? 'Enable it above to import.' : 'An admin must enable it.'}
          </div>
        ) : (
          <>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => preview.mutate()} disabled={preview.isPending}>
                {preview.isPending ? 'Reading repo…' : 'Preview changes'}
              </Button>
              {items && items.length > 0 && hasPermission('manage_rules') && (
                <Button size="sm" onClick={() => apply.mutate()} disabled={apply.isPending || selected.size === 0}>
                  {apply.isPending ? 'Staging…' : `Stage ${selected.size} as draft`}
                </Button>
              )}
            </div>
            {items && (
              <div className="space-y-1">
                {items.length === 0 && <p className="text-xs text-muted-foreground">No rule files found in the repo.</p>}
                {items.map((i) => (
                  <div key={i.path} className="flex items-center gap-2 rounded border p-2 text-sm">
                    {i.status === 'modified' ? (
                      <Checkbox checked={selected.has(i.path)} onCheckedChange={() => toggle(i.path)} />
                    ) : (
                      <span className="w-4" />
                    )}
                    <span className="min-w-0 flex-1 truncate font-mono text-xs">{i.path}</span>
                    <Badge variant={STATUS_VARIANT[i.status]}>{i.status}</Badge>
                  </div>
                ))}
                <p className="pt-1 text-[11px] text-muted-foreground">
                  Only <strong>modified</strong> existing rules can be staged. New rules are imported manually (they need an index pattern).
                </p>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
