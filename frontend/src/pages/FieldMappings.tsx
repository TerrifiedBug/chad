import { useEffect, useState } from 'react'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Globe, Loader2, Pencil, Plus, Sparkles, Trash2 } from 'lucide-react'

export default function FieldMappingsPage() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [activeTab, setActiveTab] = useState<string>('global')
  const [mappings, setMappings] = useState<FieldMapping[]>([])

  // Add/Edit modal state
  const [showModal, setShowModal] = useState(false)
  const [editingMapping, setEditingMapping] = useState<FieldMapping | null>(null)
  const [formSigmaField, setFormSigmaField] = useState('')
  const [formTargetField, setFormTargetField] = useState('')
  const [formScope, setFormScope] = useState<'global' | 'index'>('global')
  const [isSaving, setIsSaving] = useState(false)

  // Delete confirmation
  const [deleteMapping, setDeleteMapping] = useState<FieldMapping | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // AI Suggestions
  const [showSuggestModal, setShowSuggestModal] = useState(false)
  const [suggestSigmaFields, setSuggestSigmaFields] = useState('')
  const [suggestions, setSuggestions] = useState<AISuggestion[]>([])
  const [isSuggesting, setIsSuggesting] = useState(false)
  const [savingSuggestions, setSavingSuggestions] = useState<Set<string>>(new Set())

  useEffect(() => {
    loadData()
  }, [])

  useEffect(() => {
    loadMappings()
  }, [activeTab])

  const loadData = async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
    } catch (err) {
      showToast('Failed to load index patterns', 'error')
    } finally {
      setIsLoading(false)
    }
  }

  const loadMappings = async () => {
    try {
      const indexPatternId = activeTab === 'global' ? null : activeTab
      const data = await fieldMappingsApi.list(indexPatternId)
      setMappings(data)
    } catch (err) {
      showToast('Failed to load mappings', 'error')
    }
  }

  const openAddModal = () => {
    setEditingMapping(null)
    setFormSigmaField('')
    setFormTargetField('')
    setFormScope(activeTab === 'global' ? 'global' : 'index')
    setShowModal(true)
  }

  const openEditModal = (mapping: FieldMapping) => {
    setEditingMapping(mapping)
    setFormSigmaField(mapping.sigma_field)
    setFormTargetField(mapping.target_field)
    setFormScope(mapping.index_pattern_id ? 'index' : 'global')
    setShowModal(true)
  }

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
        const data: FieldMappingCreate = {
          sigma_field: formSigmaField.trim(),
          target_field: formTargetField.trim(),
          index_pattern_id:
            formScope === 'global'
              ? null
              : activeTab === 'global'
              ? null
              : activeTab,
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

    if (activeTab === 'global') {
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
        index_pattern_id: activeTab === 'global' ? null : activeTab,
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
          {activeTab !== 'global' && (
            <Button variant="outline" onClick={openSuggestModal}>
              <Sparkles className="mr-2 h-4 w-4" />
              Suggest with AI
            </Button>
          )}
          <Button onClick={openAddModal}>
            <Plus className="mr-2 h-4 w-4" />
            Add Mapping
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="global" className="flex items-center gap-1">
            <Globe className="h-4 w-4" />
            Global
          </TabsTrigger>
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
                {activeTab === 'global' ? 'Global Mappings' : `Mappings for ${indexPatterns.find((p) => p.id === activeTab)?.name}`}
              </CardTitle>
              <CardDescription>
                {activeTab === 'global'
                  ? 'Global mappings apply to all index patterns unless overridden by a per-index mapping.'
                  : 'Per-index mappings override global mappings for this index pattern.'}
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
                  {activeTab !== 'global' && (
                    <>
                      {' '}
                      or{' '}
                      <button
                        className="text-primary underline"
                        onClick={openSuggestModal}
                      >
                        get AI suggestions
                      </button>
                    </>
                  )}
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
              <Label htmlFor="target-field">Target Field (in your logs)</Label>
              <Input
                id="target-field"
                value={formTargetField}
                onChange={(e) => setFormTargetField(e.target.value)}
                placeholder="e.g., src_ip"
              />
            </div>
            {!editingMapping && activeTab !== 'global' && (
              <div className="space-y-2">
                <Label>Scope</Label>
                <Select
                  value={formScope}
                  onValueChange={(v) => setFormScope(v as 'global' | 'index')}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="index">This index pattern only</SelectItem>
                    <SelectItem value="global">Global (all index patterns)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
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
