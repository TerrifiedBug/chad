import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  IndexPattern,
  IndexPatternMode,
  IndexPatternValidateResponse,
  indexPatternsApi,
} from '@/lib/api'
import { useMode } from '@/hooks/useMode'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Check,
  X,
  Loader2,
  Database,
} from 'lucide-react'

interface SettingsTabProps {
  pattern: IndexPattern | null
  isNew: boolean
  onSave: (data: Partial<IndexPattern>) => Promise<void>
  isSaving?: boolean
  onDirtyChange?: (isDirty: boolean) => void
}

interface FormData {
  name: string
  pattern: string
  percolator_index: string
  description: string
}

export function SettingsTab({ pattern, isNew, onSave, isSaving = false, onDirtyChange }: SettingsTabProps) {
  const { isPullOnly, supportsPush } = useMode()

  // Form state
  const [formData, setFormData] = useState<FormData>({
    name: '',
    pattern: '',
    percolator_index: '',
    description: '',
  })

  // Detection mode state
  const [detectionMode, setDetectionMode] = useState<IndexPatternMode>('push')
  const [pollIntervalMinutes, setPollIntervalMinutes] = useState(5)
  const [timestampField, setTimestampField] = useState('@timestamp')
  const [availableTimeFields, setAvailableTimeFields] = useState<string[]>([])
  const [isLoadingTimeFields, setIsLoadingTimeFields] = useState(false)

  // Validation state
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<IndexPatternValidateResponse | null>(null)
  const [percolatorIndexManuallyEdited, setPercolatorIndexManuallyEdited] = useState(false)

  // Error state
  const [saveError, setSaveError] = useState('')

  // Initialize form from pattern
  useEffect(() => {
    if (pattern) {
      setFormData({
        name: pattern.name,
        pattern: pattern.pattern,
        percolator_index: pattern.percolator_index,
        description: pattern.description || '',
      })
      setDetectionMode(pattern.mode)
      setPollIntervalMinutes(pattern.poll_interval_minutes || 5)
      setTimestampField(pattern.timestamp_field || '@timestamp')
    } else {
      // Create mode - reset to defaults
      setFormData({
        name: '',
        pattern: '',
        percolator_index: '',
        description: '',
      })
      setDetectionMode(isPullOnly ? 'pull' : 'push')
      setPollIntervalMinutes(5)
      setTimestampField('@timestamp')
    }
    setValidationResult(null)
    setPercolatorIndexManuallyEdited(false)
    setSaveError('')
  }, [pattern, isPullOnly])

  // Track dirty state
  const isDirty = useMemo(() => {
    if (isNew) {
      // For new patterns, dirty if any required field has content
      return formData.name.trim() !== '' || formData.pattern.trim() !== ''
    }
    if (!pattern) return false

    // Compare current form state to saved pattern
    return (
      formData.name !== pattern.name ||
      formData.pattern !== pattern.pattern ||
      formData.percolator_index !== pattern.percolator_index ||
      formData.description !== (pattern.description || '') ||
      detectionMode !== pattern.mode ||
      (detectionMode === 'pull' && pollIntervalMinutes !== (pattern.poll_interval_minutes || 5)) ||
      (detectionMode === 'pull' && timestampField !== (pattern.timestamp_field || '@timestamp'))
    )
  }, [isNew, pattern, formData, detectionMode, pollIntervalMinutes, timestampField])

  // Notify parent of dirty state changes
  useEffect(() => {
    onDirtyChange?.(isDirty)
  }, [isDirty, onDirtyChange])

  // Load time fields for existing pattern
  const loadTimeFields = useCallback(async (patternId: string) => {
    setIsLoadingTimeFields(true)
    try {
      const fields = await indexPatternsApi.getTimeFields(patternId)
      setAvailableTimeFields(fields)
    } catch {
      setAvailableTimeFields([])
    } finally {
      setIsLoadingTimeFields(false)
    }
  }, [])

  // Auto-generate percolator index
  const handlePatternChange = (value: string) => {
    setFormData({ ...formData, pattern: value })
    setValidationResult(null)

    // Auto-generate percolator index if not manually edited
    if (!percolatorIndexManuallyEdited && value) {
      const baseName = value
        .replace(/[*?]/g, '')
        .replace(/-+$/, '')
        .replace(/^-+/, '')
        .split('-')
        .filter(Boolean)
        .slice(0, 2)
        .join('-')
      if (baseName) {
        setFormData((prev) => ({
          ...prev,
          pattern: value,
          percolator_index: `chad-percolator-${baseName}`,
        }))
      }
    }
  }

  // Validate pattern
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

  // Get index suffix for endpoints
  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
  }

  // Handle save
  const handleSave = async (e?: React.FormEvent) => {
    e?.preventDefault()
    setSaveError('')

    const data: Partial<IndexPattern> = {
      name: formData.name,
      pattern: formData.pattern,
      percolator_index: detectionMode === 'push' ? formData.percolator_index : `chad-percolator-${formData.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
      description: formData.description || undefined,
      mode: detectionMode,
      poll_interval_minutes: detectionMode === 'pull' ? pollIntervalMinutes : undefined,
      timestamp_field: detectionMode === 'pull' ? timestampField : undefined,
    }

    try {
      await onSave(data)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save')
    }
  }

  return (
    <form id="settings-form" onSubmit={handleSave} className="space-y-6">
      {saveError && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {saveError}
        </div>
      )}

      {/* Basic Settings */}
      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="name">Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
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
              {isValidating ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Validate'}
            </Button>
          </div>
          {validationResult && (
            <div
              className={`text-sm p-2 rounded ${
                validationResult.valid
                  ? 'bg-green-500/10 text-green-600 dark:text-green-400'
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

        {detectionMode === 'push' && (
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
              Where deployed rules will be stored. Must start with "chad-percolator-".
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="description">Description (optional)</Label>
          <Input
            id="description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Windows event logs from Sysmon"
          />
        </div>
      </div>

      {/* Detection Mode */}
      <div className="space-y-3 p-3 border rounded-lg">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4" />
          <Label className="font-medium">Detection Mode</Label>
        </div>
        <div className="space-y-2">
          <Select
            value={detectionMode}
            onValueChange={(value) => setDetectionMode(value as IndexPatternMode)}
            disabled={isPullOnly}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {supportsPush && (
                <SelectItem value="push">Push (Real-time via /logs endpoint)</SelectItem>
              )}
              <SelectItem value="pull">Pull (Scheduled OpenSearch queries)</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {detectionMode === 'push'
              ? 'Logs are pushed to CHAD via the /logs endpoint for real-time detection.'
              : 'CHAD periodically queries OpenSearch for new logs matching deployed rules.'}
          </p>
          {isPullOnly && (
            <p className="text-xs text-amber-600">This deployment only supports pull mode.</p>
          )}
        </div>

        {detectionMode === 'pull' && (
          <div className="space-y-4 pt-2 border-t">
            <div className="space-y-2">
              <Label htmlFor="poll-interval">Poll Interval (minutes)</Label>
              <Input
                id="poll-interval"
                type="number"
                min="1"
                max="1440"
                value={pollIntervalMinutes}
                onChange={(e) => setPollIntervalMinutes(Math.min(1440, Math.max(1, parseInt(e.target.value) || 5)))}
                className="w-24"
              />
              <p className="text-xs text-muted-foreground">
                How often to query OpenSearch (1-1440 minutes).
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="timestamp-field">Timestamp Field</Label>
              <Select value={timestampField} onValueChange={setTimestampField}>
                <SelectTrigger className="font-mono text-sm">
                  <SelectValue placeholder="Select timestamp field" />
                </SelectTrigger>
                <SelectContent>
                  {isLoadingTimeFields ? (
                    <div className="p-2 text-xs text-muted-foreground flex items-center gap-2">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      Loading...
                    </div>
                  ) : availableTimeFields.length > 0 ? (
                    availableTimeFields.map((field) => (
                      <SelectItem key={field} value={field} className="font-mono">
                        {field}
                      </SelectItem>
                    ))
                  ) : (
                    <>
                      <SelectItem value="@timestamp" className="font-mono">@timestamp</SelectItem>
                      <SelectItem value="timestamp" className="font-mono">timestamp</SelectItem>
                      <SelectItem value="event.created" className="font-mono">event.created</SelectItem>
                    </>
                  )}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Field used to track processed logs.
              </p>
              {pattern && availableTimeFields.length === 0 && !isLoadingTimeFields && (
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="h-auto p-0 text-xs"
                  onClick={() => loadTimeFields(pattern.id)}
                >
                  Load available time fields
                </Button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Endpoint Preview for Push Mode */}
      {detectionMode === 'push' && formData.percolator_index?.startsWith('chad-percolator-') && (
        <div className="space-y-3 p-3 bg-muted rounded-md">
          <Label className="text-sm font-medium">Log Shipper Endpoints (Preview)</Label>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-background p-2 rounded font-mono break-all">
                POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}
              </code>
              <span className="text-xs text-muted-foreground">sync</span>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-background p-2 rounded font-mono break-all">
                POST {window.location.origin}/api/logs/{getIndexSuffix(formData.percolator_index)}/queue
              </code>
              <span className="text-xs text-green-600 dark:text-green-400 font-medium">recommended</span>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            {pattern ? 'Use the auth token to authenticate requests.' : 'An auth token will be generated when you save.'}
          </p>
        </div>
      )}

      {/* Save Button */}
      <div className="flex justify-end pt-4 border-t">
        <Button type="submit" disabled={isSaving || !formData.name || !formData.pattern}>
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : isNew ? (
            'Create Pattern'
          ) : (
            'Save Changes'
          )}
        </Button>
      </div>
    </form>
  )
}
