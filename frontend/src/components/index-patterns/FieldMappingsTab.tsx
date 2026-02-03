import { useEffect, useState, useRef, useCallback } from 'react'
import {
  fieldMappingsApi,
  indexPatternsApi,
  FieldMapping,
  FieldMappingCreate,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
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
import { Badge } from '@/components/ui/badge'
import { Loader2, Pencil, Plus, Search, Sparkles, Trash2, Filter } from 'lucide-react'

interface FieldMappingsTabProps {
  patternId: string
  patternName: string
}

export function FieldMappingsTab({ patternId, patternName }: FieldMappingsTabProps) {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [mappings, setMappings] = useState<FieldMapping[]>([])
  const [searchFilter, setSearchFilter] = useState('')

  // Add/Edit modal state
  const [showModal, setShowModal] = useState(false)
  const [editingMapping, setEditingMapping] = useState<FieldMapping | null>(null)
  const [formSigmaField, setFormSigmaField] = useState('')
  const [formTargetField, setFormTargetField] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [modalError, setModalError] = useState('')

  // Available fields for target field dropdown
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(false)
  const [fieldSearch, setFieldSearch] = useState('')
  const [showFieldDropdown, setShowFieldDropdown] = useState(false)
  const fieldDropdownRef = useRef<HTMLDivElement>(null)

  // Delete confirmation
  const [deleteMapping, setDeleteMapping] = useState<FieldMapping | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Load mappings
  const loadMappings = useCallback(async () => {
    if (!patternId) return
    setIsLoading(true)
    try {
      const data = await fieldMappingsApi.list(patternId)
      setMappings(data)
    } catch {
      showToast('Failed to load field mappings', 'error')
    } finally {
      setIsLoading(false)
    }
  }, [patternId, showToast])

  useEffect(() => {
    loadMappings()
  }, [loadMappings])

  // Load available fields for autocomplete
  const loadAvailableFields = async () => {
    if (!patternId) return
    setIsLoadingFields(true)
    try {
      const fields = await indexPatternsApi.getFields(patternId)
      setAvailableFields(fields.sort())
    } catch {
      setAvailableFields([])
    } finally {
      setIsLoadingFields(false)
    }
  }

  // Handle click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        fieldDropdownRef.current &&
        !fieldDropdownRef.current.contains(event.target as Node)
      ) {
        setShowFieldDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const openAddModal = () => {
    setEditingMapping(null)
    setFormSigmaField('')
    setFormTargetField('')
    setFieldSearch('')
    setShowFieldDropdown(false)
    setModalError('')
    setShowModal(true)
    loadAvailableFields()
  }

  const openEditModal = (mapping: FieldMapping) => {
    setEditingMapping(mapping)
    setFormSigmaField(mapping.sigma_field)
    setFormTargetField(mapping.target_field)
    setFieldSearch(mapping.target_field)
    setShowFieldDropdown(false)
    setModalError('')
    setShowModal(true)
    loadAvailableFields()
  }

  // Filter available fields based on search
  const filteredFields = availableFields.filter((f) =>
    f.toLowerCase().includes(fieldSearch.toLowerCase())
  )

  // Filter mappings based on search
  const filteredMappings = mappings.filter(
    (m) =>
      m.sigma_field.toLowerCase().includes(searchFilter.toLowerCase()) ||
      m.target_field.toLowerCase().includes(searchFilter.toLowerCase())
  )

  const handleSave = async () => {
    if (!formSigmaField.trim() || !formTargetField.trim()) {
      showToast('Please fill in all fields', 'error')
      return
    }

    setIsSaving(true)
    setModalError('')
    try {
      if (editingMapping) {
        await fieldMappingsApi.update(editingMapping.id, {
          target_field: formTargetField.trim(),
        })
        showToast('Mapping updated')
        setShowModal(false)
        loadMappings()
      } else {
        const data: FieldMappingCreate = {
          sigma_field: formSigmaField.trim(),
          target_field: formTargetField.trim(),
          index_pattern_id: patternId,
        }
        await fieldMappingsApi.create(data)
        showToast('Mapping created')
        setShowModal(false)
        loadMappings()
      }
    } catch (err: unknown) {
      // Parse error response
      let errorMessage = 'Save failed'
      const errorObj = err as { message?: string | object; detail?: { error?: string; field?: string; suggestions?: string[] } | string }

      if (typeof errorObj?.message === 'string') {
        errorMessage = errorObj.message
      } else if (typeof errorObj?.message === 'object') {
        const msgObj = errorObj.message as { detail?: string; error?: string }
        errorMessage = msgObj.detail || msgObj.error || JSON.stringify(errorObj.message)
      } else if (errorObj?.detail) {
        errorMessage = typeof errorObj.detail === 'string' ? errorObj.detail : JSON.stringify(errorObj.detail)
      }

      // Check if it's a field_not_found error
      if (typeof errorObj.detail === 'object' && errorObj.detail?.error === 'field_not_found') {
        const suggestions = errorObj.detail.suggestions || []
        const suggestionText = suggestions.length > 0
          ? ` Did you mean: ${suggestions.slice(0, 3).join(', ')}?`
          : ''
        setModalError(
          `Field "${errorObj.detail.field}" does not exist in this index pattern.${suggestionText}`
        )
      } else {
        setModalError(String(errorMessage))
      }
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteMapping) return

    setIsDeleting(true)
    try {
      await fieldMappingsApi.delete(deleteMapping.id)
      showToast('Mapping deleted')
      setDeleteMapping(null)
      loadMappings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    } finally {
      setIsDeleting(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header with search and add button */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative flex-1">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Filter mappings..."
            className="pl-9"
          />
        </div>
        <Button onClick={openAddModal} size="sm">
          <Plus className="mr-2 h-4 w-4" />
          Add
        </Button>
      </div>

      {/* Mappings table */}
      {filteredMappings.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground border rounded-lg">
          {mappings.length === 0 ? (
            <>
              No mappings configured.{' '}
              <button className="text-primary underline" onClick={openAddModal}>
                Add one
              </button>
            </>
          ) : (
            'No mappings match your filter.'
          )}
        </div>
      ) : (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Sigma Field</TableHead>
                <TableHead>Target Field</TableHead>
                <TableHead>Origin</TableHead>
                <TableHead className="w-[80px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredMappings.map((mapping) => (
                <TableRow key={mapping.id}>
                  <TableCell className="font-mono text-sm">
                    {mapping.sigma_field}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {mapping.target_field}
                  </TableCell>
                  <TableCell>
                    {mapping.origin === 'AI_SUGGESTED' ? (
                      <Badge variant="secondary" className="text-xs">
                        <Sparkles className="mr-1 h-3 w-3" />
                        AI
                        {mapping.confidence !== null && (
                          <span className="ml-1">
                            ({Math.round(mapping.confidence * 100)}%)
                          </span>
                        )}
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-xs">Manual</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => openEditModal(mapping)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive hover:text-destructive"
                        onClick={() => setDeleteMapping(mapping)}
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

      <p className="text-xs text-muted-foreground">
        {mappings.length} mapping{mappings.length !== 1 ? 's' : ''} for {patternName}
      </p>

      {/* Add/Edit Modal */}
      <Dialog open={showModal} onOpenChange={setShowModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingMapping ? 'Edit Mapping' : 'Add Mapping'}
            </DialogTitle>
            <DialogDescription>
              {editingMapping
                ? 'Update the target field for this mapping.'
                : 'Create a new field mapping from a Sigma field to a log field.'}
            </DialogDescription>
          </DialogHeader>

          {modalError && (
            <div className="bg-destructive/15 border border-destructive/50 text-destructive text-sm p-4 rounded-md">
              <p className="font-medium">Validation Error</p>
              <p className="whitespace-pre-wrap mt-1">{modalError}</p>
            </div>
          )}

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="sigma-field">Sigma Field</Label>
              <Input
                id="sigma-field"
                value={formSigmaField}
                onChange={(e) => setFormSigmaField(e.target.value)}
                placeholder="e.g., SourceIp"
                disabled={!!editingMapping}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="target-field">Target Field</Label>
              <div ref={fieldDropdownRef} className="relative">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="target-field"
                    value={fieldSearch}
                    onChange={(e) => {
                      setFieldSearch(e.target.value)
                      setFormTargetField(e.target.value)
                      setShowFieldDropdown(true)
                    }}
                    onFocus={() => setShowFieldDropdown(true)}
                    placeholder="Search fields..."
                    className="pl-9"
                  />
                  {isLoadingFields && (
                    <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-muted-foreground" />
                  )}
                </div>
                {showFieldDropdown && availableFields.length > 0 && (
                  <div className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-60 overflow-y-auto">
                    {filteredFields.length === 0 ? (
                      <div className="px-3 py-2 text-sm text-muted-foreground">
                        No matching fields
                      </div>
                    ) : (
                      filteredFields.slice(0, 100).map((field) => (
                        <button
                          key={field}
                          type="button"
                          className="w-full px-3 py-2 text-left text-sm font-mono hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground outline-none"
                          onClick={() => {
                            setFormTargetField(field)
                            setFieldSearch(field)
                            setShowFieldDropdown(false)
                          }}
                        >
                          {field}
                        </button>
                      ))
                    )}
                    {filteredFields.length > 100 && (
                      <div className="px-3 py-2 text-xs text-muted-foreground border-t">
                        Showing first 100 of {filteredFields.length} matches
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowModal(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editingMapping ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog
        open={!!deleteMapping}
        onOpenChange={(open: boolean) => !open && setDeleteMapping(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Mapping</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete the mapping for{' '}
              <code className="bg-muted px-1 rounded">
                {deleteMapping?.sigma_field}
              </code>
              ? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteMapping(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              {isDeleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
