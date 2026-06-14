import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, Check, Star, Trash2, Users } from 'lucide-react'
import {
  savedViewsApi,
  type SavedView,
  type SavedViewResource,
} from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'

interface SavedViewsMenuProps {
  resource: SavedViewResource
  /** The list filters currently applied — captured when saving a new view. */
  currentFilters: Record<string, unknown>
  /** Apply a saved view's filters back onto the page. */
  onApply: (filters: Record<string, unknown>) => void
}

/**
 * Dropdown for saving/applying named filter presets ("saved views") on a list
 * page. Views are owner-private by default and can be shared with the team.
 * Server-persisted (replaces the old localStorage-only "Assigned to me" hack).
 */
export function SavedViewsMenu({ resource, currentFilters, onApply }: SavedViewsMenuProps) {
  const { user } = useAuth()
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const queryKey = ['saved-views', resource]

  const [saveOpen, setSaveOpen] = useState(false)
  const [name, setName] = useState('')
  const [shareWithTeam, setShareWithTeam] = useState(false)

  const { data: views = [] } = useQuery({
    queryKey,
    queryFn: () => savedViewsApi.list(resource),
  })

  const createMutation = useMutation({
    mutationFn: () =>
      savedViewsApi.create({
        name: name.trim(),
        resource,
        filters: currentFilters,
        is_shared: shareWithTeam,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey })
      setSaveOpen(false)
      setName('')
      setShareWithTeam(false)
      showToast('View saved', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to save view', 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => savedViewsApi.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey })
      showToast('View deleted', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to delete view', 'error'),
  })

  const isOwner = (view: SavedView) => view.owner_id === user?.id

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-1.5">
            <Bookmark className="h-3.5 w-3.5" />
            Views
            {views.length > 0 && (
              <span className="ml-0.5 rounded-full bg-muted px-1.5 text-xs">{views.length}</span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel>Saved views</DropdownMenuLabel>
          {views.length === 0 && (
            <div className="px-2 py-1.5 text-xs text-muted-foreground">
              No saved views yet. Filter, then save the current view.
            </div>
          )}
          {views.map((view) => (
            <DropdownMenuItem
              key={view.id}
              className="flex items-center justify-between gap-2"
              onSelect={(e) => {
                e.preventDefault()
                onApply(view.filters)
              }}
            >
              <span className="flex min-w-0 items-center gap-1.5">
                {view.is_default ? (
                  <Star className="h-3.5 w-3.5 shrink-0 fill-current text-yellow-500" />
                ) : (
                  <Check className="h-3.5 w-3.5 shrink-0 opacity-0" />
                )}
                <span className="truncate">{view.name}</span>
                {view.is_shared && <Users className="h-3 w-3 shrink-0 text-muted-foreground" />}
              </span>
              {isOwner(view) && (
                <button
                  type="button"
                  className="shrink-0 text-muted-foreground hover:text-destructive"
                  aria-label={`Delete ${view.name}`}
                  onClick={(e) => {
                    e.stopPropagation()
                    deleteMutation.mutate(view.id)
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              )}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={(e) => {
              e.preventDefault()
              setSaveOpen(true)
            }}
          >
            <Bookmark className="mr-2 h-3.5 w-3.5" />
            Save current view…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save view</DialogTitle>
            <DialogDescription>
              Save the current filters as a named view you can re-apply with one click.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="saved-view-name">Name</Label>
              <Input
                id="saved-view-name"
                value={name}
                autoFocus
                placeholder="e.g. Critical, unassigned"
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && name.trim()) createMutation.mutate()
                }}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={shareWithTeam}
                onCheckedChange={(v) => setShareWithTeam(v === true)}
              />
              Share with my team
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={!name.trim() || createMutation.isPending}
            >
              {createMutation.isPending ? 'Saving…' : 'Save view'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
