import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import {
  IndexPattern,
  indexPatternsApi,
} from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { useUnsavedChanges } from '@/hooks/useUnsavedChanges'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import {
  ArrowLeft,
  Settings,
  Table2,
  Key,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import { SettingsTab } from '@/components/index-patterns/SettingsTab'
import { FieldMappingsTab } from '@/components/index-patterns/FieldMappingsTab'
import { EndpointTab } from '@/components/index-patterns/EndpointTab'

type DetailTab = 'settings' | 'mappings' | 'endpoint'

export default function IndexPatternDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { showToast } = useToast()

  const isNew = id === 'new'
  const activeTab = (searchParams.get('tab') as DetailTab) || 'settings'

  const [pattern, setPattern] = useState<IndexPattern | null>(null)
  const [isLoading, setIsLoading] = useState(!isNew)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)

  // Warn on browser refresh/close when there are unsaved changes
  const { confirmNavigation } = useUnsavedChanges(hasUnsavedChanges)

  // Load pattern data
  const loadPattern = useCallback(async () => {
    if (isNew || !id) return

    setIsLoading(true)
    setError(null)
    try {
      const data = await indexPatternsApi.get(id)
      setPattern(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load pattern')
      showToast('Failed to load index pattern', 'error')
    } finally {
      setIsLoading(false)
    }
  }, [id, isNew, showToast])

  useEffect(() => {
    loadPattern()
  }, [loadPattern])

  // Handle tab change
  const handleTabChange = (tab: string) => {
    setSearchParams({ tab })
  }

  // Handle save
  const handleSave = async (data: Partial<IndexPattern>) => {
    setIsSaving(true)
    try {
      if (isNew) {
        const created = await indexPatternsApi.create(data as Parameters<typeof indexPatternsApi.create>[0])
        setHasUnsavedChanges(false) // Clear before navigation
        showToast('Index pattern created')
        // Navigate to the edit view of the new pattern
        navigate(`/index-patterns/${created.id}`, { replace: true })
      } else if (pattern) {
        const updated = await indexPatternsApi.update(pattern.id, data)
        setPattern(updated)
        setHasUnsavedChanges(false)
        showToast('Index pattern updated')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save'
      showToast(message, 'error')
      throw err // Re-throw so SettingsTab can show the error
    } finally {
      setIsSaving(false)
    }
  }

  // Handle dirty state from SettingsTab
  const handleDirtyChange = useCallback((isDirty: boolean) => {
    setHasUnsavedChanges(isDirty)
  }, [])

  // Handle back navigation
  const handleBack = () => {
    if (confirmNavigation()) {
      navigate('/index-patterns')
    }
  }

  // Handle pattern update from EndpointTab (for token regeneration)
  const handlePatternUpdated = (updatedPattern: IndexPattern) => {
    setPattern(updatedPattern)
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  // Error state
  if (error && !isNew) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" onClick={handleBack} className="gap-2">
          <ArrowLeft className="h-4 w-4" />
          Back to Index Patterns
        </Button>
        <div className="flex flex-col items-center justify-center h-64 space-y-4">
          <p className="text-destructive">{error}</p>
          <Button onClick={loadPattern}>Retry</Button>
        </div>
      </div>
    )
  }

  const title = isNew
    ? 'Create Index Pattern'
    : pattern?.name || 'Index Pattern'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={handleBack} title="Back to Index Patterns">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
              {pattern && !isNew && (
                <Badge
                  className={
                    pattern.mode === 'push'
                      ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                      : 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
                  }
                >
                  {pattern.mode === 'push' ? 'Push' : `Pull (${pattern.poll_interval_minutes}m)`}
                </Badge>
              )}
              {hasUnsavedChanges && (
                <Badge variant="outline" className="text-amber-600 border-amber-600">
                  <AlertCircle className="h-3 w-3 mr-1" />
                  Unsaved changes
                </Badge>
              )}
            </div>
            {pattern && !isNew && pattern.updated_at && (
              <p className="text-sm text-muted-foreground mt-1">
                Last edited{' '}
                <TimestampTooltip timestamp={pattern.updated_at}>
                  <span className="underline decoration-dotted cursor-help">
                    {new Date(pattern.updated_at).toLocaleDateString(undefined, {
                      month: 'short',
                      day: 'numeric',
                      year: 'numeric',
                      hour: 'numeric',
                      minute: '2-digit',
                    })}
                  </span>
                </TimestampTooltip>
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
        <TabsList>
          <TabsTrigger value="settings" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Settings
          </TabsTrigger>
          <TabsTrigger
            value="mappings"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Table2 className="h-4 w-4" />
            Field Mappings
          </TabsTrigger>
          <TabsTrigger
            value="endpoint"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Key className="h-4 w-4" />
            Endpoint
          </TabsTrigger>
        </TabsList>

        {/* Tab Contents */}
        <div className="max-w-4xl">
          <TabsContent value="settings" className="mt-0">
            <div className="rounded-lg border bg-card p-6">
              <SettingsTab
                pattern={pattern}
                isNew={isNew}
                onSave={handleSave}
                isSaving={isSaving}
                onDirtyChange={handleDirtyChange}
              />
            </div>
          </TabsContent>

          <TabsContent value="mappings" className="mt-0">
            <div className="rounded-lg border bg-card p-6">
              {pattern ? (
                <FieldMappingsTab
                  patternId={pattern.id}
                  patternName={pattern.name}
                />
              ) : (
                <div className="text-sm text-muted-foreground py-8 text-center">
                  Save the pattern first to configure field mappings.
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="endpoint" className="mt-0">
            <div className="rounded-lg border bg-card p-6">
              {pattern ? (
                <EndpointTab
                  pattern={pattern}
                  onPatternUpdated={handlePatternUpdated}
                />
              ) : (
                <div className="text-sm text-muted-foreground py-8 text-center">
                  Save the pattern first to view endpoint configuration.
                </div>
              )}
            </div>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  )
}
