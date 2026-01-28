import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { correlationRulesApi, CorrelationRule } from '@/lib/api'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { ChevronLeft, Plus, MoreVertical, Power, PowerOff, Trash2, Edit, Rocket, CircleOff } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { TimestampTooltip } from '@/components/timestamp-tooltip'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

function formatDate(timestamp: string): string {
  const date = new Date(timestamp)
  return date.toLocaleString()
}

export default function CorrelationRulesPage() {
  const navigate = useNavigate()
  const { canManageRules } = useAuth()
  const [rules, setRules] = useState<CorrelationRule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null)

  // Deploy/Undeploy state
  const [showDeployDialog, setShowDeployDialog] = useState<string | null>(null)
  const [showUndeployDialog, setShowUndeployDialog] = useState<string | null>(null)
  const [deployReason, setDeployReason] = useState('')
  const [isDeploying, setIsDeploying] = useState(false)

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setIsLoading(true)
    setError('')
    try {
      const response = await correlationRulesApi.list(true)
      setRules(response.correlation_rules)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load correlation rules')
    } finally {
      setIsLoading(false)
    }
  }

  const handleToggleEnabled = async (rule: CorrelationRule) => {
    try {
      const action = rule.is_enabled ? 'Disabled' : 'Enabled'
      await correlationRulesApi.update(rule.id, {
        is_enabled: !rule.is_enabled,
        change_reason: `${action} correlation rule from list view`
      })
      await loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule')
    }
  }

  const handleDeploy = async () => {
    if (!showDeployDialog || !deployReason.trim()) return
    setIsDeploying(true)
    try {
      await correlationRulesApi.deploy(showDeployDialog, deployReason)
      await loadRules()
      setShowDeployDialog(null)
      setDeployReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deploy rule')
    } finally {
      setIsDeploying(false)
    }
  }

  const handleUndeploy = async () => {
    if (!showUndeployDialog || !deployReason.trim()) return
    setIsDeploying(true)
    try {
      await correlationRulesApi.undeploy(showUndeployDialog, deployReason)
      await loadRules()
      setShowUndeployDialog(null)
      setDeployReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to undeploy rule')
    } finally {
      setIsDeploying(false)
    }
  }

  const handleDelete = async () => {
    if (!showDeleteConfirm) return

    try {
      await correlationRulesApi.delete(showDeleteConfirm)
      await loadRules()
      setShowDeleteConfirm(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/settings')}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">Correlation Rules</h1>
            <p className="text-sm text-muted-foreground">
              Detect patterns across multiple rules
            </p>
          </div>
        </div>
        {canManageRules() && (
          <Button onClick={() => navigate('/correlation/new')}>
            <Plus className="h-4 w-4 mr-2" />
            Create Correlation Rule
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rules</CardTitle>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md mb-4">
              {error}
            </div>
          )}

          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : rules.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No correlation rules found. Create one to detect patterns across multiple rules.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Rules</TableHead>
                  <TableHead>Entity Field</TableHead>
                  <TableHead>Time Window</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Deploy Status</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Updated</TableHead>
                  <TableHead>Updated By</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <div className="text-xs">
                        <div className="truncate max-w-[200px">{rule.rule_a_title || rule.rule_a_id}</div>
                        <div className="text-muted-foreground">and</div>
                        <div className="truncate max-w-[200px]">{rule.rule_b_title || rule.rule_b_id}</div>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{rule.entity_field}</TableCell>
                    <TableCell>{rule.time_window_minutes} min</TableCell>
                    <TableCell>
                      <Badge className={severityColors[rule.severity]}>
                        {rule.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {rule.deployed_at ? (
                        rule.needs_redeploy ? (
                          <Badge variant="outline" className="border-yellow-500 text-yellow-600">
                            Needs Redeploy
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-green-500 text-green-600">
                            Deployed
                          </Badge>
                        )
                      ) : (
                        <Badge variant="secondary">Not Deployed</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={rule.is_enabled ? 'default' : 'secondary'}>
                        {rule.is_enabled ? 'Active' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      <TimestampTooltip timestamp={rule.updated_at}>
                        <span>{formatDate(rule.updated_at)}</span>
                      </TimestampTooltip>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {rule.last_edited_by || '-'}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => navigate(`/correlation/${rule.id}`)}>
                            <Edit className="h-4 w-4 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleToggleEnabled(rule)}>
                            {rule.is_enabled ? (
                              <>
                                <PowerOff className="h-4 w-4 mr-2" />
                                Disable
                              </>
                            ) : (
                              <>
                                <Power className="h-4 w-4 mr-2" />
                                Enable
                              </>
                            )}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {rule.deployed_at ? (
                            <DropdownMenuItem onClick={() => setShowUndeployDialog(rule.id)}>
                              <CircleOff className="h-4 w-4 mr-2" />
                              Undeploy
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem onClick={() => setShowDeployDialog(rule.id)}>
                              <Rocket className="h-4 w-4 mr-2" />
                              Deploy
                            </DropdownMenuItem>
                          )}
                          {rule.needs_redeploy && (
                            <DropdownMenuItem onClick={() => setShowDeployDialog(rule.id)}>
                              <Rocket className="h-4 w-4 mr-2" />
                              Redeploy
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => setShowDeleteConfirm(rule.id)}
                            className="text-destructive focus:text-destructive"
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <DeleteConfirmModal
        open={showDeleteConfirm !== null}
        onOpenChange={(open) => !open && setShowDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Correlation Rule"
        description="Are you sure you want to delete this correlation rule? This action cannot be undone."
      />

      {/* Deploy Reason Dialog */}
      <Dialog open={showDeployDialog !== null} onOpenChange={(open) => {
        if (!open) {
          setShowDeployDialog(null)
          setDeployReason('')
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy Correlation Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're deploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="deploy-reason">Reason for Deploy *</Label>
              <Textarea
                id="deploy-reason"
                placeholder="e.g., Ready for production, completed testing..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowDeployDialog(null)
                setDeployReason('')
              }}
              disabled={isDeploying}
            >
              Cancel
            </Button>
            <Button
              onClick={handleDeploy}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Deploying...' : 'Deploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Undeploy Reason Dialog */}
      <Dialog open={showUndeployDialog !== null} onOpenChange={(open) => {
        if (!open) {
          setShowUndeployDialog(null)
          setDeployReason('')
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Undeploy Correlation Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're undeploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="undeploy-reason">Reason for Undeploy *</Label>
              <Textarea
                id="undeploy-reason"
                placeholder="e.g., False positives, needs revision, no longer needed..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowUndeployDialog(null)
                setDeployReason('')
              }}
              disabled={isDeploying}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleUndeploy}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Undeploying...' : 'Undeploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
