import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FolderPlus } from 'lucide-react'
import { casesApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

interface AddToCaseButtonProps {
  alertId: string
  /** Optional title used when creating a new case from this alert. */
  alertTitle?: string
  disabled?: boolean
}

/**
 * Link an alert to an existing case or spin up a new case seeded with it.
 * Reusable across the alert detail page and (later) bulk alert actions.
 */
export function AddToCaseButton({ alertId, alertTitle, disabled }: AddToCaseButtonProps) {
  const navigate = useNavigate()
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'existing' | 'new'>('existing')
  const [selectedCase, setSelectedCase] = useState<string>('')
  const [newTitle, setNewTitle] = useState('')

  const { data } = useQuery({
    queryKey: ['cases', 'open-for-link'],
    queryFn: () => casesApi.list({ status: undefined, limit: 100 }),
    enabled: open,
  })
  const cases = (data?.cases ?? []).filter((c) => c.status !== 'closed')

  const link = useMutation({
    mutationFn: async () => {
      if (mode === 'new') {
        const created = await casesApi.create({
          title: newTitle.trim() || alertTitle || `Case for alert ${alertId}`,
          alert_ids: [alertId],
        })
        return created.id
      }
      await casesApi.addAlerts(selectedCase, [alertId])
      return selectedCase
    },
    onSuccess: (caseId) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      setOpen(false)
      showToast('Alert linked to case', 'success')
      navigate(`/cases/${caseId}`)
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to link alert', 'error'),
  })

  const canSubmit = mode === 'new' ? true : !!selectedCase

  return (
    <>
      <Button variant="outline" size="sm" disabled={disabled} onClick={() => setOpen(true)} className="gap-1.5">
        <FolderPlus className="h-4 w-4" /> Add to case
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add alert to case</DialogTitle>
            <DialogDescription>Link this alert to an existing investigation or open a new one.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="flex gap-2">
              <Button variant={mode === 'existing' ? 'default' : 'outline'} size="sm" onClick={() => setMode('existing')}>Existing</Button>
              <Button variant={mode === 'new' ? 'default' : 'outline'} size="sm" onClick={() => setMode('new')}>New case</Button>
            </div>
            {mode === 'existing' ? (
              <div className="space-y-1.5">
                <Label>Case</Label>
                <Select value={selectedCase} onValueChange={setSelectedCase}>
                  <SelectTrigger><SelectValue placeholder="Select a case…" /></SelectTrigger>
                  <SelectContent>
                    {cases.length === 0 && <div className="px-2 py-1.5 text-xs text-muted-foreground">No open cases</div>}
                    {cases.map((c) => (
                      <SelectItem key={c.id} value={c.id}>CASE-{c.number} · {c.title}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ) : (
              <div className="space-y-1.5">
                <Label htmlFor="new-case-title">Title</Label>
                <Input id="new-case-title" value={newTitle} placeholder={alertTitle || 'New case'} onChange={(e) => setNewTitle(e.target.value)} />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => link.mutate()} disabled={!canSubmit || link.isPending}>
              {link.isPending ? 'Linking…' : 'Link'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
