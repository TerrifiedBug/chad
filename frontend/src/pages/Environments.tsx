import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { environmentsApi, type Environment, type EnvironmentCreate } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { ENVIRONMENTS_QUERY_KEY } from '@/components/EnvironmentSelector'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Layers, Plus, Star } from 'lucide-react'

function formatRelativeTime(dateString: string | null | undefined): string {
  if (!dateString) return 'never'
  const date = new Date(dateString)
  const diffMs = Date.now() - date.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)
  if (diffMin < 1) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHour < 24) return `${diffHour}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return date.toLocaleDateString()
}

function EnvironmentCard({ env }: { env: Environment }) {
  const navigate = useNavigate()
  return (
    <Card
      interactive
      onClick={() => navigate(`/environments/${env.id}`)}
      className="h-full"
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Layers className="h-4 w-4 text-fg-3" />
            <span className="truncate">{env.name}</span>
          </CardTitle>
          <div className="flex flex-shrink-0 items-center gap-1.5">
            {env.is_default && (
              <Badge variant="info" className="gap-1">
                <Star className="h-3 w-3 fill-current" />
                Default
              </Badge>
            )}
            {env.require_deploy_approval && (
              <Badge variant="warning">Approval</Badge>
            )}
          </div>
        </div>
        {env.description && (
          <p className="text-[13px] text-fg-2 line-clamp-2">{env.description}</p>
        )}
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex items-center gap-4 text-[13px] text-fg-2">
          <span>
            <span className="font-mono font-semibold text-fg">{env.rule_count}</span> rules
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{env.deployed_count}</span> deployed
          </span>
          <span className="text-fg-3">last deploy {formatRelativeTime(env.last_deploy_at)}</span>
        </div>
      </CardContent>
    </Card>
  )
}

interface NewEnvironmentDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

function NewEnvironmentDialog({ open, onOpenChange }: NewEnvironmentDialogProps) {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [requireApproval, setRequireApproval] = useState(false)
  const [indexPrefix, setIndexPrefix] = useState('')
  const [error, setError] = useState('')

  const reset = () => {
    setName('')
    setDescription('')
    setRequireApproval(false)
    setIndexPrefix('')
    setError('')
  }

  const createMutation = useMutation({
    mutationFn: (data: EnvironmentCreate) => environmentsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ENVIRONMENTS_QUERY_KEY] })
      showToast('Environment created', 'success')
      reset()
      onOpenChange(false)
    },
    onError: (err) => {
      setError(err instanceof Error ? err.message : 'Failed to create environment')
    },
  })

  const handleSubmit = () => {
    setError('')
    if (!name.trim()) {
      setError('Name is required')
      return
    }
    createMutation.mutate({
      name: name.trim(),
      description: description.trim() || null,
      require_deploy_approval: requireApproval,
      opensearch_index_prefix: indexPrefix.trim() || null,
    })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New environment</DialogTitle>
          <DialogDescription>
            Environments scope rule deployments into separate percolator namespaces.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {error && (
            <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <div className="space-y-1.5">
            <Label htmlFor="env-name">Name</Label>
            <Input
              id="env-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Staging"
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="env-description">Description</Label>
            <Textarea
              id="env-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What is this environment for?"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="env-index-prefix">Index prefix</Label>
            <Input
              id="env-index-prefix"
              value={indexPrefix}
              onChange={(e) => setIndexPrefix(e.target.value)}
              placeholder="Optional — namespaces this env's percolator indices"
              className="font-mono"
            />
          </div>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="env-require-approval">Require deploy approval</Label>
              <p className="text-xs text-muted-foreground">
                Deployments into this env go through dual-control review.
              </p>
            </div>
            <Switch
              id="env-require-approval"
              checked={requireApproval}
              onCheckedChange={setRequireApproval}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={createMutation.isPending}>
            {createMutation.isPending ? 'Creating...' : 'Create environment'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function EnvironmentsPage() {
  const { isAdmin, hasPermission } = useAuth()
  const [showNewDialog, setShowNewDialog] = useState(false)

  const canManage = isAdmin || hasPermission('manage_environments')

  const { data: environments, isLoading, error } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY],
    queryFn: () => environmentsApi.list(),
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Environments"
        description="Team-owned scopes for rule deployments (e.g. Production, Staging)."
        actions={
          canManage ? (
            <Button onClick={() => setShowNewDialog(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New environment
            </Button>
          ) : undefined
        }
      />

      {error && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {error instanceof Error ? error.message : 'Failed to load environments'}
        </div>
      )}

      {isLoading ? (
        <LoadingState message="Loading environments..." />
      ) : !environments || environments.length === 0 ? (
        <EmptyState
          icon={<Layers className="h-12 w-12" />}
          title="No environments"
          description="Create your first environment to scope rule deployments."
          action={
            canManage
              ? {
                  label: 'New environment',
                  icon: Plus,
                  onClick: () => setShowNewDialog(true),
                }
              : undefined
          }
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {environments.map((env) => (
            <EnvironmentCard key={env.id} env={env} />
          ))}
        </div>
      )}

      <NewEnvironmentDialog open={showNewDialog} onOpenChange={setShowNewDialog} />
    </div>
  )
}
