import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { environmentsApi, type Environment, type EnvironmentUpdate } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { ENVIRONMENTS_QUERY_KEY } from '@/components/EnvironmentSelector'
import { setActiveEnvironmentId } from '@/stores/environment-store'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardContent } from '@/components/ui/card'
import { KpiStrip, KpiTile } from '@/components/ui/kpi-tile'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { LoadingState } from '@/components/ui/loading-state'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ArrowLeft, Star, Trash2 } from 'lucide-react'

function OverviewTab({ env }: { env: Environment }) {
  return (
    <div className="space-y-6">
      <KpiStrip>
        <KpiTile label="Rules" value={env.rule_count} />
        <KpiTile label="Deployed" value={env.deployed_count} tone="accent" />
        <KpiTile
          label="Approval"
          value={env.require_deploy_approval ? 'On' : 'Off'}
          tone={env.require_deploy_approval ? 'degraded' : 'default'}
        />
        <KpiTile label="Default" value={env.is_default ? 'Yes' : 'No'} />
      </KpiStrip>

      <Card>
        <CardContent className="space-y-3 p-6">
          <div className="flex justify-between gap-4">
            <span className="text-sm text-fg-2">Description</span>
            <span className="text-sm text-fg">{env.description || '—'}</span>
          </div>
          <div className="flex justify-between gap-4">
            <span className="text-sm text-fg-2">Index prefix</span>
            <span className="font-mono text-sm text-fg">
              {env.opensearch_index_prefix || '—'}
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function SettingsTab({ env }: { env: Environment }) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { showToast } = useToast()
  const { isAdmin, hasPermission } = useAuth()
  const canManage = isAdmin || hasPermission('manage_environments')

  const [indexPrefix, setIndexPrefix] = useState(env.opensearch_index_prefix ?? '')
  const [showDelete, setShowDelete] = useState(false)
  const [deleteError, setDeleteError] = useState('')

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: [ENVIRONMENTS_QUERY_KEY] })

  const updateMutation = useMutation({
    mutationFn: (data: EnvironmentUpdate) => environmentsApi.update(env.id, data),
    onSuccess: () => {
      invalidate()
      queryClient.invalidateQueries({ queryKey: [ENVIRONMENTS_QUERY_KEY, env.id] })
      showToast('Environment updated', 'success')
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Update failed', 'error')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => environmentsApi.delete(env.id),
    onSuccess: () => {
      invalidate()
      showToast('Environment deleted', 'success')
      navigate('/environments')
    },
    onError: (err) => {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    },
  })

  return (
    <div className="max-w-2xl space-y-6">
      {/* Require deploy approval (admin / manage_environments only) */}
      <div className="flex items-center justify-between rounded-[3px] border border-line p-4">
        <div className="space-y-0.5">
          <Label htmlFor="require-approval">Require deploy approval</Label>
          <p className="text-xs text-muted-foreground">
            Deployments into this env go through dual-control review.
          </p>
        </div>
        <Switch
          id="require-approval"
          checked={env.require_deploy_approval}
          disabled={!canManage || updateMutation.isPending}
          onCheckedChange={(checked) =>
            updateMutation.mutate({ require_deploy_approval: checked })
          }
        />
      </div>

      {/* Default toggle */}
      <div className="flex items-center justify-between rounded-[3px] border border-line p-4">
        <div className="space-y-0.5">
          <Label className="flex items-center gap-1.5">
            <Star
              className={
                env.is_default ? 'h-3.5 w-3.5 fill-accent-brand text-accent-brand' : 'h-3.5 w-3.5'
              }
            />
            Team default
          </Label>
          <p className="text-xs text-muted-foreground">
            New sessions scope to the team default when no env is selected.
          </p>
        </div>
        <Switch
          checked={env.is_default}
          disabled={!canManage || env.is_default || updateMutation.isPending}
          onCheckedChange={(checked) => {
            if (checked) updateMutation.mutate({ is_default: true })
          }}
        />
      </div>

      {/* Index prefix */}
      <div className="space-y-2 rounded-[3px] border border-line p-4">
        <Label htmlFor="index-prefix">Index prefix</Label>
        <p className="text-xs text-muted-foreground">
          Namespaces this env's percolator indices. Leave blank for the default namespace.
        </p>
        <div className="flex gap-2">
          <Input
            id="index-prefix"
            value={indexPrefix}
            onChange={(e) => setIndexPrefix(e.target.value)}
            disabled={!canManage}
            className="font-mono"
          />
          <Button
            variant="outline"
            disabled={
              !canManage ||
              updateMutation.isPending ||
              indexPrefix === (env.opensearch_index_prefix ?? '')
            }
            onClick={() =>
              updateMutation.mutate({ opensearch_index_prefix: indexPrefix.trim() || null })
            }
          >
            Save
          </Button>
        </div>
      </div>

      {/* Danger zone: delete */}
      {canManage && (
        <div className="flex items-center justify-between rounded-[3px] border border-destructive/30 p-4">
          <div className="space-y-0.5">
            <Label className="text-destructive">Delete environment</Label>
            <p className="text-xs text-muted-foreground">
              Removes this environment. The default environment cannot be deleted.
            </p>
          </div>
          <Button
            variant="destructive"
            disabled={env.is_default}
            onClick={() => {
              setDeleteError('')
              setShowDelete(true)
            }}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      )}

      <Dialog open={showDelete} onOpenChange={setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete environment</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{env.name}"? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          {deleteError && (
            <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              {deleteError}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate()}
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default function EnvironmentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: env, isLoading, error } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY, id],
    queryFn: () => environmentsApi.get(id!),
    enabled: !!id,
  })

  if (isLoading) {
    return <LoadingState message="Loading environment..." />
  }

  if (error || !env) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate('/environments')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Environments
        </Button>
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {error instanceof Error ? error.message : 'Environment not found'}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => navigate('/environments')}>
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Environments
      </Button>

      <PageHeader
        title={env.name}
        description={env.description || undefined}
        actions={
          <Button variant="outline" onClick={() => setActiveEnvironmentId(env.id)}>
            Switch to this environment
          </Button>
        }
      >
        <div className="flex items-center gap-2">
          {env.is_default && (
            <Badge variant="info" className="gap-1">
              <Star className="h-3 w-3 fill-current" />
              Default
            </Badge>
          )}
          {env.require_deploy_approval && <Badge variant="warning">Approval required</Badge>}
        </div>
      </PageHeader>

      <Tabs defaultValue="overview">
        <TabsList variant="line">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="mt-6">
          <OverviewTab env={env} />
        </TabsContent>
        <TabsContent value="settings" className="mt-6">
          <SettingsTab env={env} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
