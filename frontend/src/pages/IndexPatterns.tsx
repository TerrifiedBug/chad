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
import { Switch } from '@/components/ui/switch'
import { Plus, Pencil, Trash2, Check, X, Loader2, Copy, Eye, EyeOff, RefreshCw, Key, ChevronDown, ChevronUp, Globe } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

export default function IndexPatternsPage() {
  const [patterns, setPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Dialog state
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingPattern, setEditingPattern] = useState<IndexPattern | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    percolator_index: '',
    description: '',
  })

  // Health alerting form state
  const [healthAlerting, setHealthAlerting] = useState({
    enabled: true,
    noDataMinutes: null as number | null,
    errorRatePercent: null as number | null,
    latencyMs: null as number | null,
  })

  // GeoIP enrichment state
  const [geoipFields, setGeoipFields] = useState<string[]>([])
  const [geoipFieldInput, setGeoipFieldInput] = useState('')

  // Toggle for health settings section
  const [showHealthSettings, setShowHealthSettings] = useState(false)
  const [showGeoipSettings, setShowGeoipSettings] = useState(false)

  // Validation state
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] =
    useState<IndexPatternValidateResponse | null>(null)

  // Delete confirmation
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')

  // Token visibility state
  const [visibleTokens, setVisibleTokens] = useState<Set<string>>(new Set())
  const [copiedToken, setCopiedToken] = useState<string | null>(null)

  // Token regeneration state
  const [regenerateId, setRegenerateId] = useState<string | null>(null)
  const [isRegenerating, setIsRegenerating] = useState(false)

  // Token details dialog
  const [tokenDetailsPattern, setTokenDetailsPattern] = useState<IndexPattern | null>(null)

  // Track if user has manually edited percolator_index
  const [percolatorIndexManuallyEdited, setPercolatorIndexManuallyEdited] = useState(false)

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
    setHealthAlerting({
      enabled: true,
      noDataMinutes: null,
      errorRatePercent: null,
      latencyMs: null,
    })
    setGeoipFields([])
    setGeoipFieldInput('')
    setShowHealthSettings(false)
    setShowGeoipSettings(false)
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(false)
    setSaveError('')
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
    setHealthAlerting({
      enabled: pattern.health_alerting_enabled,
      noDataMinutes: pattern.health_no_data_minutes,
      errorRatePercent: pattern.health_error_rate_percent,
      latencyMs: pattern.health_latency_ms,
    })
    setGeoipFields(pattern.geoip_fields || [])
    setGeoipFieldInput('')
    setShowHealthSettings(
      pattern.health_no_data_minutes !== null ||
      pattern.health_error_rate_percent !== null ||
      pattern.health_latency_ms !== null ||
      !pattern.health_alerting_enabled
    )
    setShowGeoipSettings(pattern.geoip_fields && pattern.geoip_fields.length > 0)
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(true) // Don't auto-generate for existing patterns
    setSaveError('')
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
    setSaveError('')
    try {
      const healthData = {
        health_alerting_enabled: healthAlerting.enabled,
        health_no_data_minutes: healthAlerting.noDataMinutes,
        health_error_rate_percent: healthAlerting.errorRatePercent,
        health_latency_ms: healthAlerting.latencyMs,
      }

      if (editingPattern) {
        await indexPatternsApi.update(editingPattern.id, {
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: formData.percolator_index,
          description: formData.description || undefined,
          ...healthData,
          geoip_fields: geoipFields,
        })
      } else {
        await indexPatternsApi.create({
          name: formData.name,
          pattern: formData.pattern,
          percolator_index: formData.percolator_index,
          description: formData.description || undefined,
          ...healthData,
          geoip_fields: geoipFields,
        })
      }
      setIsDialogOpen(false)
      loadPatterns()
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return

    setIsDeleting(true)
    setDeleteError('')
    try {
      await indexPatternsApi.delete(deleteId)
      setDeleteId(null)
      loadPatterns()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setIsDeleting(false)
    }
  }

  const openDeleteDialog = (patternId: string) => {
    setDeleteId(patternId)
    setDeleteError('')
  }

  const handleRegenerateToken = async () => {
    if (!regenerateId) return

    setIsRegenerating(true)
    try {
      const result = await indexPatternsApi.regenerateToken(regenerateId)
      // Update the pattern in state with the new token
      setPatterns(prev =>
        prev.map(p =>
          p.id === regenerateId ? { ...p, auth_token: result.auth_token } : p
        )
      )
      // Also update token details dialog if open
      if (tokenDetailsPattern?.id === regenerateId) {
        setTokenDetailsPattern(prev =>
          prev ? { ...prev, auth_token: result.auth_token } : null
        )
      }
      setRegenerateId(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to regenerate token')
    } finally {
      setIsRegenerating(false)
    }
  }

  const toggleTokenVisibility = (patternId: string) => {
    setVisibleTokens(prev => {
      const newSet = new Set(prev)
      if (newSet.has(patternId)) {
        newSet.delete(patternId)
      } else {
        newSet.add(patternId)
      }
      return newSet
    })
  }

  const copyToClipboard = async (text: string, patternId: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedToken(patternId)
      setTimeout(() => setCopiedToken(null), 2000)
    } catch {
      setError('Failed to copy to clipboard')
    }
  }

  // Auto-generate percolator index name from pattern
  const handlePatternChange = (value: string) => {
    setFormData((prev) => ({
      ...prev,
      pattern: value,
      // Only auto-generate if user hasn't manually edited percolator_index
      percolator_index: percolatorIndexManuallyEdited
        ? prev.percolator_index
        : `chad-percolator-${value.replace(/\*/g, '').replace(/-$/, '')}`,
    }))
    setValidationResult(null)
  }

  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
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
                <TableHead className="w-32">Actions</TableHead>
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
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        title="View token & endpoint"
                        onClick={() => setTokenDetailsPattern(pattern)}
                      >
                        <Key className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Edit pattern"
                        onClick={() => openEditDialog(pattern)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Delete pattern"
                        onClick={() => openDeleteDialog(pattern.id)}
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

      {/* Token Details Dialog */}
      <Dialog open={!!tokenDetailsPattern} onOpenChange={() => setTokenDetailsPattern(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Log Shipping Configuration</DialogTitle>
            <DialogDescription>
              Use this token to authenticate log shipping requests for "{tokenDetailsPattern?.name}"
            </DialogDescription>
          </DialogHeader>

          {tokenDetailsPattern && (
            <div className="space-y-4 py-4">
              {/* Endpoint URL */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Endpoint URL</Label>
                <div className="flex gap-2">
                  <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                    POST {window.location.origin}/api/logs/{getIndexSuffix(tokenDetailsPattern.percolator_index)}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(
                      `${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}`,
                      `${tokenDetailsPattern.id}-url`
                    )}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-url` ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Auth Token */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Auth Token</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 text-xs"
                    onClick={() => setRegenerateId(tokenDetailsPattern.id)}
                  >
                    <RefreshCw className="h-3 w-3 mr-1" />
                    Regenerate
                  </Button>
                </div>
                <div className="flex gap-2">
                  <code className="flex-1 text-sm bg-muted p-2 rounded font-mono break-all">
                    {visibleTokens.has(tokenDetailsPattern.id)
                      ? tokenDetailsPattern.auth_token
                      : `${'*'.repeat(20)}...${tokenDetailsPattern.auth_token.slice(-4)}`
                    }
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => toggleTokenVisibility(tokenDetailsPattern.id)}
                  >
                    {visibleTokens.has(tokenDetailsPattern.id) ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(tokenDetailsPattern.auth_token, `${tokenDetailsPattern.id}-token`)}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-token` ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              {/* Example curl command */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Example Request</Label>
                <div className="relative">
                  <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap">
{`curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\
  -H "Authorization: Bearer ${visibleTokens.has(tokenDetailsPattern.id) ? tokenDetailsPattern.auth_token : '<your-token>'}" \\
  -H "Content-Type: application/json" \\
  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`}
                  </pre>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-2 right-2 h-6 w-6"
                    onClick={() => copyToClipboard(
                      `curl -X POST "${window.location.origin}/api/logs/${getIndexSuffix(tokenDetailsPattern.percolator_index)}" \\\n  -H "Authorization: Bearer ${tokenDetailsPattern.auth_token}" \\\n  -H "Content-Type: application/json" \\\n  -d '[{"message": "test log", "timestamp": "2024-01-01T00:00:00Z"}]'`,
                      `${tokenDetailsPattern.id}-curl`
                    )}
                  >
                    {copiedToken === `${tokenDetailsPattern.id}-curl` ? (
                      <Check className="h-3 w-3 text-green-500" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </Button>
                </div>
              </div>

              <p className="text-xs text-muted-foreground">
                Send a JSON array of log documents to this endpoint. Each log will be matched against deployed rules and alerts will be generated for matches.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setTokenDetailsPattern(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create/Edit Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>
              {editingPattern ? 'Edit Index Pattern' : 'Create Index Pattern'}
            </DialogTitle>
            <DialogDescription>
              Index patterns define which OpenSearch indices rules will match against.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4 overflow-y-auto flex-1">
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
                onChange={(e) => {
                  setFormData({ ...formData, percolator_index: e.target.value })
                  setPercolatorIndexManuallyEdited(true)
                }}
                placeholder="chad-percolator-windows"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Where deployed rules will be stored in OpenSearch. Must start with "chad-percolator-".
              </p>
            </div>

            {/* Dynamic Log Shipper Endpoint Info */}
            {formData.percolator_index && formData.percolator_index.startsWith('chad-percolator-') && (
              <div className="space-y-2 p-3 bg-muted rounded-md">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Log Shipper Endpoint</Label>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6"
                    onClick={() => {
                      const suffix = getIndexSuffix(formData.percolator_index)
                      navigator.clipboard.writeText(`${window.location.origin}/api/logs/${suffix}`)
                    }}
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                </div>
                <code className="block text-xs bg-background p-2 rounded font-mono break-all">
                  POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}
                </code>
                <p className="text-xs text-muted-foreground">
                  {editingPattern
                    ? 'Use the auth token to authenticate requests to this endpoint.'
                    : 'An auth token will be generated when you save this pattern.'}
                </p>
              </div>
            )}

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

            {/* Health Alerting Section */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowHealthSettings(!showHealthSettings)}
              >
                <span className="font-medium text-sm">Health Alerting</span>
                {showHealthSettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showHealthSettings && (
                <div className="p-3 pt-0 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="health-enabled" className="font-normal">Enable Health Alerting</Label>
                      <p className="text-xs text-muted-foreground">Send alerts when thresholds are exceeded</p>
                    </div>
                    <Switch
                      id="health-enabled"
                      checked={healthAlerting.enabled}
                      onCheckedChange={(checked) =>
                        setHealthAlerting({ ...healthAlerting, enabled: checked })
                      }
                    />
                  </div>

                  <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                      Leave empty to use global defaults from the Health page.
                    </p>

                    <div className="grid grid-cols-3 gap-3">
                      <div className="space-y-1">
                        <Label htmlFor="no-data-minutes" className="text-xs">No Data (min)</Label>
                        <Input
                          id="no-data-minutes"
                          type="number"
                          min="1"
                          placeholder="15"
                          value={healthAlerting.noDataMinutes ?? ''}
                          onChange={(e) =>
                            setHealthAlerting({
                              ...healthAlerting,
                              noDataMinutes: e.target.value ? parseInt(e.target.value) : null,
                            })
                          }
                        />
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="error-rate" className="text-xs">Error Rate (%)</Label>
                        <Input
                          id="error-rate"
                          type="number"
                          min="0"
                          step="0.1"
                          placeholder="5.0"
                          value={healthAlerting.errorRatePercent ?? ''}
                          onChange={(e) =>
                            setHealthAlerting({
                              ...healthAlerting,
                              errorRatePercent: e.target.value ? parseFloat(e.target.value) : null,
                            })
                          }
                        />
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="latency-ms" className="text-xs">Latency (ms)</Label>
                        <Input
                          id="latency-ms"
                          type="number"
                          min="1"
                          placeholder="1000"
                          value={healthAlerting.latencyMs ?? ''}
                          onChange={(e) =>
                            setHealthAlerting({
                              ...healthAlerting,
                              latencyMs: e.target.value ? parseInt(e.target.value) : null,
                            })
                          }
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* GeoIP Enrichment Section */}
            <div className="border rounded-lg">
              <button
                type="button"
                className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                onClick={() => setShowGeoipSettings(!showGeoipSettings)}
              >
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  <span className="font-medium text-sm">GeoIP Enrichment</span>
                  {geoipFields.length > 0 && (
                    <Badge variant="secondary" className="text-xs">
                      {geoipFields.length} field{geoipFields.length > 1 ? 's' : ''}
                    </Badge>
                  )}
                </div>
                {showGeoipSettings ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {showGeoipSettings && (
                <div className="p-3 pt-0 space-y-4">
                  <p className="text-xs text-muted-foreground">
                    Specify IP address fields to enrich with geographic data when alerts are generated.
                    GeoIP must be enabled in Settings.
                  </p>

                  <div className="flex gap-2">
                    <Input
                      value={geoipFieldInput}
                      onChange={(e) => setGeoipFieldInput(e.target.value)}
                      placeholder="e.g., source.ip, destination.ip"
                      className="flex-1"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && geoipFieldInput.trim()) {
                          e.preventDefault()
                          const field = geoipFieldInput.trim()
                          if (!geoipFields.includes(field)) {
                            setGeoipFields([...geoipFields, field])
                          }
                          setGeoipFieldInput('')
                        }
                      }}
                    />
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        const field = geoipFieldInput.trim()
                        if (field && !geoipFields.includes(field)) {
                          setGeoipFields([...geoipFields, field])
                        }
                        setGeoipFieldInput('')
                      }}
                      disabled={!geoipFieldInput.trim()}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>

                  {geoipFields.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {geoipFields.map((field) => (
                        <Badge
                          key={field}
                          variant="outline"
                          className="flex items-center gap-1 pr-1"
                        >
                          {field}
                          <button
                            type="button"
                            onClick={() => setGeoipFields(geoipFields.filter(f => f !== field))}
                            className="ml-1 hover:bg-muted rounded-full p-0.5"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  )}

                  <p className="text-xs text-muted-foreground">
                    Common fields: source.ip, destination.ip, client.ip, server.ip
                  </p>
                </div>
              )}
            </div>

            {saveError && (
              <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
                {saveError}
              </div>
            )}
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
          {deleteError && (
            <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
              {deleteError}
            </div>
          )}
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

      {/* Regenerate Token Confirmation Dialog */}
      <Dialog open={!!regenerateId} onOpenChange={() => setRegenerateId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate Auth Token</DialogTitle>
            <DialogDescription>
              Are you sure you want to regenerate the auth token? This will
              immediately invalidate the existing token. Any log shippers using
              the old token will stop working until updated with the new token.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegenerateId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRegenerateToken}
              disabled={isRegenerating}
            >
              {isRegenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Regenerating...
                </>
              ) : (
                'Regenerate Token'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
