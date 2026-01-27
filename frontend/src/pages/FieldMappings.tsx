import { useEffect, useState, useRef, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  fieldMappingsApi,
  indexPatternsApi,
  FieldMapping,
  FieldMappingCreate,
  IndexPattern,
  AISuggestion,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
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
import { Loader2, Pencil, Plus, Search, Sparkles, Trash2 } from 'lucide-react'

export default function FieldMappingsPage() {
  const { showToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const [isLoading, setIsLoading] = useState(true)
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [activeTab, setActiveTab] = useState<string>('')
  const [mappings, setMappings] = useState<FieldMapping[]>([])
  const initialParamsProcessed = useRef(false)

  // Add/Edit modal state
  const [showModal, setShowModal] = useState(false)
  const [editingMapping, setEditingMapping] = useState<FieldMapping | null>(null)
  const [formSigmaField, setFormSigmaField] = useState('')
  const [formTargetField, setFormTargetField] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Available fields for target field dropdown
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(false)
  const [fieldSearch, setFieldSearch] = useState('')
  const [showFieldDropdown, setShowFieldDropdown] = useState(false)
  const fieldDropdownRef = useRef<HTMLDivElement>(null)

  // Delete confirmation
  const [deleteMapping, setDeleteMapping] = useState<FieldMapping | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // AI Suggestions
  const [showSuggestModal, setShowSuggestModal] = useState(false)
  const [suggestSigmaFields, setSuggestSigmaFields] = useState('')
  const [suggestions, setSuggestions] = useState<AISuggestion[]>([])
  const [isSuggesting, setIsSuggesting] = useState(false)
  const [savingSuggestions, setSavingSuggestions] = useState<Set<string>>(new Set())

  // Load functions - must be declared before useEffect that uses them
  const loadData = useCallback(async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
    } catch {
      showToast('Failed to load index patterns', 'error')
    } finally {
      setIsLoading(false)
    }
  }, [showToast])

  const loadMappings = useCallback(async () => {
    try {
      if (!activeTab) {
        setMappings([])
        return
      }
      const data = await fieldMappingsApi.list(activeTab)
      setMappings(data)
    } catch {
      showToast('Failed to load field mappings', 'error')
    }
  }, [activeTab, showToast])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Set first index pattern as default tab when loaded
  useEffect(() => {
    if (indexPatterns.length > 0 && !activeTab) {
      setActiveTab(indexPatterns[0].id)
    }
  }, [indexPatterns, activeTab])

  // Handle URL parameters from rule deployment redirect
  useEffect(() => {
    if (initialParamsProcessed.current || indexPatterns.length === 0) return

    const indexPatternId = searchParams.get('index_pattern_id')
    const fields = searchParams.get('fields')

    if (indexPatternId) {
      // Find if this index pattern exists
      const pattern = indexPatterns.find((p) => p.id === indexPatternId)
      if (pattern) {
        // Switch to the index pattern tab
        setActiveTab(indexPatternId)

        // If fields are provided, open the suggest modal with them pre-filled
        if (fields) {
          setSuggestSigmaFields(fields.split(',').join('\n'))
          setShowSuggestModal(true)
        }

        // Clear the URL parameters
        setSearchParams({})

        showToast(
          'Configure field mappings for the unmapped fields listed below.',
          'info'
        )
      }
    }

    initialParamsProcessed.current = true
  }, [indexPatterns, searchParams, setSearchParams, showToast])

  useEffect(() => {
    loadMappings()
  }, [activeTab, loadMappings])

  const loadAvailableFields = async (indexPatternId: string) => {
    setIsLoadingFields(true)
    try {
      const fields = await indexPatternsApi.getFields(indexPatternId)
      setAvailableFields(fields.sort())
    } catch {
      // Silent fail - user can still type manually
      setAvailableFields([])
    } finally {
      setIsLoadingFields(false)
    }
  }

  const openAddModal = () => {
    setEditingMapping(null)
    setFormSigmaField('')
    setFormTargetField('')
    setFieldSearch('')
    setShowFieldDropdown(false)
    setShowModal(true)
    // Load available fields
    if (activeTab) {
      loadAvailableFields(activeTab)
    } else {
      setAvailableFields([])
    }
  }

  const openEditModal = (mapping: FieldMapping) => {
    setEditingMapping(mapping)
    setFormSigmaField(mapping.sigma_field)
    setFormTargetField(mapping.target_field)
    setFieldSearch(mapping.target_field)
    setShowFieldDropdown(false)
    setShowModal(true)
    // Load available fields
    const patternId = mapping.index_pattern_id || activeTab
    if (patternId) {
      loadAvailableFields(patternId)
    } else {
      setAvailableFields([])
    }
  }

  // Filter available fields based on search
  const filteredFields = availableFields.filter((f) =>
    f.toLowerCase().includes(fieldSearch.toLowerCase())
  )

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

  const handleSave = async () => {
    if (!formSigmaField.trim() || !formTargetField.trim()) {
      showToast('Please fill in all fields', 'error')
      return
    }

    setIsSaving(true)
    try {
      if (editingMapping) {
        await fieldMappingsApi.update(editingMapping.id, {
          target_field: formTargetField.trim(),
        })
        showToast('Mapping updated')
      } else {
        if (!activeTab) {
          showToast('Please select an index pattern first', 'error')
          return
        }
        const data: FieldMappingCreate = {
          sigma_field: formSigmaField.trim(),
          target_field: formTargetField.trim(),
          index_pattern_id: activeTab,
        }
        await fieldMappingsApi.create(data)
        showToast('Mapping created')
      }
      setShowModal(false)
      loadMappings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
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

  const openSuggestModal = () => {
    setSuggestSigmaFields('')
    setSuggestions([])
    setShowSuggestModal(true)
  }

  const handleSuggest = async () => {
    const fields = suggestSigmaFields
      .split('\n')
      .map((f) => f.trim())
      .filter((f) => f)

    if (fields.length === 0) {
      showToast('Please enter at least one field', 'error')
      return
    }

    if (!activeTab) {
      showToast('Please select an index pattern to get AI suggestions', 'error')
      return
    }

    setIsSuggesting(true)
    try {
      const result = await fieldMappingsApi.suggest({
        index_pattern_id: activeTab,
        sigma_fields: fields,
      })
      setSuggestions(result)
      if (result.length === 0) {
        showToast('No suggestions returned', 'error')
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'AI suggestion failed', 'error')
    } finally {
      setIsSuggesting(false)
    }
  }

  const acceptSuggestion = async (suggestion: AISuggestion) => {
    if (!suggestion.target_field) return

    setSavingSuggestions((prev) => new Set(prev).add(suggestion.sigma_field))
    try {
      await fieldMappingsApi.create({
        sigma_field: suggestion.sigma_field,
        target_field: suggestion.target_field,
        index_pattern_id: activeTab,
        origin: 'ai_suggested',
        confidence: suggestion.confidence,
      })
      showToast(`Mapping for ${suggestion.sigma_field} saved`)
      // Remove from suggestions list
      setSuggestions((prev) =>
        prev.filter((s) => s.sigma_field !== suggestion.sigma_field)
      )
      loadMappings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setSavingSuggestions((prev) => {
        const next = new Set(prev)
        next.delete(suggestion.sigma_field)
        return next
      })
    }
  }

  const getConfidenceBadge = (confidence: number) => {
    if (confidence >= 0.8) {
      return <Badge variant="default" className="bg-green-600">High ({Math.round(confidence * 100)}%)</Badge>
    } else if (confidence >= 0.5) {
      return <Badge variant="secondary" className="bg-yellow-600">Medium ({Math.round(confidence * 100)}%)</Badge>
    } else {
      return <Badge variant="outline">Low ({Math.round(confidence * 100)}%)</Badge>
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Field Mappings</h1>
          <p className="text-muted-foreground">
            Map Sigma rule field names to your log field names
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={openSuggestModal}>
            <Sparkles className="mr-2 h-4 w-4" />
            Suggest with AI
          </Button>
          <Button onClick={openAddModal}>
            <Plus className="mr-2 h-4 w-4" />
            Add Mapping
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex-wrap h-auto gap-1">
          {indexPatterns.map((pattern) => (
            <TabsTrigger key={pattern.id} value={pattern.id}>
              {pattern.name}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value={activeTab} className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>
                {`Mappings for ${indexPatterns.find((p) => p.id === activeTab)?.name || 'Select an Index Pattern'}`}
              </CardTitle>
              <CardDescription>
                Define field mappings for this index pattern. These mappings translate Sigma rule fields to your specific log field names.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {mappings.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No mappings configured.{' '}
                  <button
                    className="text-primary underline"
                    onClick={openAddModal}
                  >
                    Add one
                  </button>
                  {' '}
                  or{' '}
                  <button
                    className="text-primary underline"
                    onClick={openSuggestModal}
                  >
                    get AI suggestions
                  </button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Sigma Field</TableHead>
                      <TableHead>Target Field</TableHead>
                      <TableHead>Origin</TableHead>
                      <TableHead className="w-[100px]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {mappings.map((mapping) => (
                      <TableRow key={mapping.id}>
                        <TableCell className="font-mono">
                          {mapping.sigma_field}
                        </TableCell>
                        <TableCell className="font-mono">
                          {mapping.target_field}
                        </TableCell>
                        <TableCell>
                          {mapping.origin === 'ai_suggested' ? (
                            <Badge variant="secondary">
                              <Sparkles className="mr-1 h-3 w-3" />
                              AI
                              {mapping.confidence !== null && (
                                <span className="ml-1">
                                  ({Math.round(mapping.confidence * 100)}%)
                                </span>
                              )}
                            </Badge>
                          ) : (
                            <Badge variant="outline">Manual</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => openEditModal(mapping)}
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="text-destructive hover:text-destructive"
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
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

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
              {activeTab || editingMapping?.index_pattern_id ? (
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
              ) : (
                <Input
                  id="target-field"
                  value={formTargetField}
                  onChange={(e) => setFormTargetField(e.target.value)}
                  placeholder="e.g., src_ip"
                />
              )}
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

      {/* AI Suggest Modal */}
      <Dialog open={showSuggestModal} onOpenChange={setShowSuggestModal}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>AI Field Mapping Suggestions</DialogTitle>
            <DialogDescription>
              Enter Sigma field names (one per line) to get AI suggestions for
              mapping them to your log fields.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="sigma-fields">Sigma Fields (one per line)</Label>
              <textarea
                id="sigma-fields"
                className="w-full h-32 px-3 py-2 border rounded-md bg-background resize-none font-mono text-sm"
                value={suggestSigmaFields}
                onChange={(e) => setSuggestSigmaFields(e.target.value)}
                placeholder="SourceIp&#10;DestinationIp&#10;User&#10;CommandLine"
              />
            </div>
            <Button
              onClick={handleSuggest}
              disabled={isSuggesting || !suggestSigmaFields.trim()}
            >
              {isSuggesting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Getting Suggestions...
                </>
              ) : (
                <>
                  <Sparkles className="mr-2 h-4 w-4" />
                  Get Suggestions
                </>
              )}
            </Button>

            {suggestions.length > 0 && (
              <div className="space-y-2 pt-4 border-t">
                <Label>Suggestions</Label>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Sigma Field</TableHead>
                      <TableHead>Suggested Target</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead className="w-[100px]">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {suggestions.map((suggestion) => (
                      <TableRow key={suggestion.sigma_field}>
                        <TableCell className="font-mono">
                          {suggestion.sigma_field}
                        </TableCell>
                        <TableCell className="font-mono">
                          {suggestion.target_field || (
                            <span className="text-muted-foreground italic">
                              No match
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          {suggestion.target_field
                            ? getConfidenceBadge(suggestion.confidence)
                            : '-'}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                          {suggestion.reason}
                        </TableCell>
                        <TableCell>
                          {suggestion.target_field && (
                            <Button
                              size="sm"
                              onClick={() => acceptSuggestion(suggestion)}
                              disabled={savingSuggestions.has(suggestion.sigma_field)}
                            >
                              {savingSuggestions.has(suggestion.sigma_field) ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                'Accept'
                              )}
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSuggestModal(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
