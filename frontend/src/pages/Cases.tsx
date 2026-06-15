import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, FolderOpen } from 'lucide-react'
import { casesApi, type CaseStatus } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { PageHeader } from '@/components/PageHeader'
import { RelativeTime } from '@/components/RelativeTime'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { SeverityBadge } from '@/components/ui/severity-badge'

const CASE_STATUS_COLORS: Record<CaseStatus, string> = {
  open: 'bg-blue-500/15 text-blue-600 dark:text-blue-400',
  investigating: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
  contained: 'bg-purple-500/15 text-purple-600 dark:text-purple-400',
  closed: 'bg-muted text-muted-foreground',
}

const STATUS_OPTIONS: CaseStatus[] = ['open', 'investigating', 'contained', 'closed']

export default function Cases() {
  const navigate = useNavigate()
  const { hasPermission } = useAuth()
  const { showToast } = useToast()
  const queryClient = useQueryClient()

  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')

  const canManage = hasPermission('manage_alerts')

  const { data, isLoading } = useQuery({
    queryKey: ['cases', statusFilter, search],
    queryFn: () =>
      casesApi.list({
        status: statusFilter === 'all' ? undefined : statusFilter,
        search: search || undefined,
        limit: 100,
      }),
  })

  const createMutation = useMutation({
    mutationFn: () =>
      casesApi.create({ title: newTitle.trim(), description: newDescription || null, severity: newSeverity }),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      setCreateOpen(false)
      setNewTitle('')
      setNewDescription('')
      setNewSeverity('medium')
      navigate(`/cases/${created.id}`)
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to create case', 'error'),
  })

  const cases = data?.cases ?? []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cases"
        description="Investigations grouping related alerts with owner, timeline, and SLA."
        actions={
          canManage ? (
            <Button onClick={() => setCreateOpen(true)} className="gap-1.5">
              <Plus className="h-4 w-4" /> New case
            </Button>
          ) : undefined
        }
      />

      <div className="flex flex-wrap items-center gap-3">
        <Input
          placeholder="Search cases…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUS_OPTIONS.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">Case</TableHead>
              <TableHead>Title</TableHead>
              <TableHead className="w-28">Severity</TableHead>
              <TableHead className="w-32">Status</TableHead>
              <TableHead className="w-20">Alerts</TableHead>
              <TableHead className="w-40">Owner</TableHead>
              <TableHead className="w-32">Updated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-8">Loading…</TableCell></TableRow>
            )}
            {!isLoading && cases.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground py-10">
                  <FolderOpen className="mx-auto mb-2 h-6 w-6 opacity-50" />
                  No cases yet.
                </TableCell>
              </TableRow>
            )}
            {cases.map((c) => (
              <TableRow
                key={c.id}
                className="cursor-pointer hover:bg-muted/50"
                onClick={() => navigate(`/cases/${c.id}`)}
              >
                <TableCell className="font-mono text-xs">CASE-{c.number}</TableCell>
                <TableCell className="font-medium">
                  {c.title}
                  {c.sla_breached && c.status !== 'closed' && (
                    <Badge variant="destructive" className="ml-2 text-[10px]">SLA</Badge>
                  )}
                </TableCell>
                <TableCell><SeverityBadge severity={c.severity} /></TableCell>
                <TableCell>
                  <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${CASE_STATUS_COLORS[c.status]}`}>
                    {c.status}
                  </span>
                </TableCell>
                <TableCell>{c.alert_count}</TableCell>
                <TableCell className="truncate text-sm text-muted-foreground">{c.owner_email || '—'}</TableCell>
                <TableCell className="text-sm text-muted-foreground"><RelativeTime date={c.updated_at} /></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New case</DialogTitle>
            <DialogDescription>Open an investigation. Link alerts to it from the case or an alert.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="case-title">Title</Label>
              <Input id="case-title" autoFocus value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="e.g. Suspected credential theft" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="case-desc">Description</Label>
              <Textarea id="case-desc" value={newDescription} onChange={(e) => setNewDescription(e.target.value)} rows={3} />
            </div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={newSeverity} onValueChange={setNewSeverity}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {['critical', 'high', 'medium', 'low', 'informational'].map((s) => (
                    <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => createMutation.mutate()} disabled={!newTitle.trim() || createMutation.isPending}>
              {createMutation.isPending ? 'Creating…' : 'Create case'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
