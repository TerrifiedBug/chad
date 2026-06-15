import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Building2, Trash2 } from 'lucide-react'
import { organizationsApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001'

/**
 * Tenant (organization) management for multi-tenant / MSSP deployments. Admin
 * only. OSS installs see just the default org; this is where an operator adds,
 * suspends, and removes customer tenants.
 */
export default function Organizations() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')

  const { data: orgs = [] } = useQuery({ queryKey: ['organizations'], queryFn: () => organizationsApi.list() })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['organizations'] })
  const onErr = (err: unknown) => showToast(err instanceof Error ? err.message : 'Action failed', 'error')

  const create = useMutation({
    mutationFn: () => organizationsApi.create({ name: name.trim(), slug: slug.trim() }),
    onSuccess: () => { invalidate(); setCreateOpen(false); setName(''); setSlug(''); showToast('Organization created', 'success') },
    onError: onErr,
  })
  const toggleSuspend = useMutation({
    mutationFn: (o: { id: string; suspended: boolean }) => organizationsApi.update(o.id, { suspended: o.suspended }),
    onSuccess: invalidate, onError: onErr,
  })
  const remove = useMutation({
    mutationFn: (id: string) => organizationsApi.remove(id),
    onSuccess: () => { invalidate(); showToast('Organization deleted', 'success') }, onError: onErr,
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organizations"
        description="Tenants for multi-tenant / MSSP deployments. The default organization cannot be removed."
        actions={
          <Button onClick={() => setCreateOpen(true)} className="gap-1.5">
            <Plus className="h-4 w-4" /> New organization
          </Button>
        }
      />

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead className="w-40">Slug</TableHead>
              <TableHead className="w-32">Plan</TableHead>
              <TableHead className="w-28">Status</TableHead>
              <TableHead className="w-40 text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {orgs.length === 0 && (
              <TableRow><TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                <Building2 className="mx-auto mb-2 h-6 w-6 opacity-50" />No organizations.
              </TableCell></TableRow>
            )}
            {orgs.map((o) => {
              const isDefault = o.id === DEFAULT_ORG_ID
              const suspended = !!o.suspended_at
              return (
                <TableRow key={o.id}>
                  <TableCell className="font-medium">{o.name}{isDefault && <Badge variant="secondary" className="ml-2 text-[10px]">default</Badge>}</TableCell>
                  <TableCell className="font-mono text-xs">{o.slug}</TableCell>
                  <TableCell className="capitalize">{o.plan}</TableCell>
                  <TableCell>
                    <Badge variant={suspended ? 'destructive' : 'secondary'}>{suspended ? 'Suspended' : 'Active'}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {!isDefault && (
                      <div className="flex items-center justify-end gap-2">
                        <Button variant="outline" size="sm"
                          onClick={() => toggleSuspend.mutate({ id: o.id, suspended: !suspended })}>
                          {suspended ? 'Restore' : 'Suspend'}
                        </Button>
                        <Button variant="ghost" size="icon" aria-label="Delete organization"
                          onClick={() => remove.mutate(o.id)}>
                          <Trash2 className="h-4 w-4 text-muted-foreground hover:text-destructive" />
                        </Button>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New organization</DialogTitle>
            <DialogDescription>Slug is the tenant subdomain (lowercase, 3–31 chars, starts with a letter).</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="org-name">Name</Label>
              <Input id="org-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-slug">Slug</Label>
              <Input id="org-slug" value={slug} onChange={(e) => setSlug(e.target.value.toLowerCase())} placeholder="acme" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => create.mutate()} disabled={!name.trim() || !slug.trim() || create.isPending}>
              {create.isPending ? 'Creating…' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
