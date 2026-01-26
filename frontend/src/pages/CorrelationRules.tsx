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
} from '@/components/ui/dropdown-menu'
import { ChevronLeft, Plus, MoreVertical, Power, PowerOff, Trash2, Edit } from 'lucide-react'
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
      await correlationRulesApi.update(rule.id, { is_enabled: !rule.is_enabled })
      await loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule')
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
                      -
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
    </div>
  )
}
