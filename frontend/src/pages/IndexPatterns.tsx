import { useEffect, useState } from 'react'
import {
  indexPatternsApi,
  IndexPattern,
  IndexPatternValidateResponse,
} from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Plus, Pencil, Trash2, Check, X, Loader2 } from 'lucide-react'

export default function IndexPatternsPage() {
  const [patterns, setPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Dialog state
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingPattern, setEditingPattern] = useState<IndexPattern | null>(null)
  const [isSaving, setIsSaving] = useState(false)

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    percolator_index: '',
    description: '',
  })

  // Validation state
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] =
    useState<IndexPatternValidateResponse | null>(null)

  // Delete confirmation
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  useEffect(() => {
    loadPatterns()
  }, [])

  const loadPatterns = async () => {
    setIsLoading(true)
    setError('')
    try {
      const data = await indexPatternsApi.list()
      setPatterns(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load patterns')
    } finally {
      setIsLoading(false)
    }
  }

  const openCreateDialog = () => {
    setEditingPattern(null)
    setFormData({
      name: '',
      pattern: '',
      percolator_index: '',
      description: '',
    })
    setValidationResult(null)
    setIsDialogOpen(true)
  }

  const openEditDialog = (pattern: IndexPattern) => {
    setEditingPattern(pattern)
    setFormData({
      name: pattern.name,
      pattern: pattern.pattern,
      percolator_index: pattern.percolator_index,
      description: pattern.description || '',
    })
    setValidationResult(null)
    setIsDialogOpen(true)
  }

  const handleValidate = async () => {
    if (!formData.pattern) return

    setIsValidating(true)
    try {
      const result = await indexPatternsApi.validate(formData.pattern)
      setValidationResult(result)
    } catch (err) {
      setValidationResult({
        valid: false,
        indices: [],
        total_docs: 0,
        sample_fields: [],
        error: err instanceof Error ? err.message : 'Validation failed',
      })
    } finally {
      setIsValidating(false)
    }
  }

  const handleSave = async () => {
    if (!formData.name || !formData.pattern || !formData.percolator_index) {
      return
    }

    setIsSaving(true)
    try {
      if (editingPattern) {
        await indexPatternsApi.update(editingPattern.id, {
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: formData.percolator_index,
          description: formData.description || undefined,
        })
      } else {
        await indexPatternsApi.create({
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: formData.percolator_index,
          description: formData.description || undefined,
        })
      }
      setIsDialogOpen(false)
      loadPatterns()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return

    setIsDeleting(true)
    try {
      await indexPatternsApi.delete(deleteId)
      setDeleteId(null)
      loadPatterns()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setIsDeleting(false)
    }
  }

  // Auto-generate percolator index name from pattern
  const handlePatternChange = (value: string) => {
    setFormData((prev) => ({
      ...prev,
      pattern: value,
      percolator_index: prev.percolator_index || `percolator-${value.replace(/\*/g, '')}`,
    }))
    setValidationResult(null)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Index Patterns</h1>
        <Button onClick={openCreateDialog}>
          <Plus className="h-4 w-4 mr-2" />
          Create Pattern
        </Button>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : patterns.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          No index patterns found. Create your first pattern!
        </div>
      ) : (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Pattern</TableHead>
                <TableHead>Percolator Index</TableHead>
                <TableHead className="w-24">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {patterns.map((pattern) => (
                <TableRow key={pattern.id}>
                  <TableCell className="font-medium">{pattern.name}</TableCell>
                  <TableCell className="font-mono text-sm">
                    {pattern.pattern}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {pattern.percolator_index}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => openEditDialog(pattern)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setDeleteId(pattern.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingPattern ? 'Edit Index Pattern' : 'Create Index Pattern'}
            </DialogTitle>
            <DialogDescription>
              Index patterns define which OpenSearch indices rules will match against.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Windows Sysmon Logs"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pattern">Index Pattern</Label>
              <div className="flex gap-2">
                <Input
                  id="pattern"
                  value={formData.pattern}
                  onChange={(e) => handlePatternChange(e.target.value)}
                  placeholder="logs-windows-*"
                  className="font-mono"
                />
                <Button
                  type="button"
                  variant="secondary"
                  onClick={handleValidate}
                  disabled={isValidating || !formData.pattern}
                >
                  {isValidating ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    'Validate'
                  )}
                </Button>
              </div>
              {validationResult && (
                <div
                  className={`text-sm p-2 rounded ${
                    validationResult.valid
                      ? 'bg-green-500/10 text-green-600'
                      : 'bg-destructive/10 text-destructive'
                  }`}
                >
                  {validationResult.valid ? (
                    <div className="flex items-center gap-2">
                      <Check className="h-4 w-4" />
                      Found {validationResult.indices.length} indices,{' '}
                      {validationResult.total_docs.toLocaleString()} documents
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <X className="h-4 w-4" />
                      {validationResult.error || 'No matching indices found'}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="percolator">Percolator Index</Label>
              <Input
                id="percolator"
                value={formData.percolator_index}
                onChange={(e) =>
                  setFormData({ ...formData, percolator_index: e.target.value })
                }
                placeholder="percolator-windows"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Where deployed rules will be stored in OpenSearch
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description (optional)</Label>
              <Input
                id="description"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
                placeholder="Windows event logs from Sysmon"
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={
                isSaving ||
                !formData.name ||
                !formData.pattern ||
                !formData.percolator_index
              }
            >
              {isSaving ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Index Pattern</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this index pattern? This action
              cannot be undone. Rules using this pattern will need to be
              reassigned.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
