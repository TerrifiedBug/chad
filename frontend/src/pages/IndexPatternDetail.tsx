import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import {
  IndexPattern,
  indexPatternsApi,
  indexPatternEnrichmentsApi,
  IndexPatternEnrichmentsUpdate,
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
  Save,
  Shield,
  Globe,
  Lock,
  HeartPulse,
  Crosshair,
  Webhook,
} from 'lucide-react'
import { SettingsTab } from '@/components/index-patterns/SettingsTab'
import { FieldMappingsTab } from '@/components/index-patterns/FieldMappingsTab'
import { EndpointTab } from '@/components/index-patterns/EndpointTab'
import { TIEnrichmentTab } from '@/components/index-patterns/TIEnrichmentTab'
import { GeoIPTab } from '@/components/index-patterns/GeoIPTab'
import { SecurityTab } from '@/components/index-patterns/SecurityTab'
import { HealthTab } from '@/components/index-patterns/HealthTab'
import { IOCDetectionTab } from '@/components/index-patterns/IOCDetectionTab'
import { WebhooksTab } from '@/components/index-patterns/WebhooksTab'
import { ChangeReasonDialog } from '@/components/ChangeReasonDialog'

type DetailTab = 'settings' | 'mappings' | 'threat-intel' | 'ioc-detection' | 'geoip' | 'webhooks' | 'security' | 'health' | 'endpoint'

export default function IndexPatternDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { showToast } = useToast()

  const isNew = !id || id === 'new'
  const activeTab = (searchParams.get('tab') as DetailTab) || 'settings'

  const [pattern, setPattern] = useState<IndexPattern | null>(null)
  const [isLoading, setIsLoading] = useState(!isNew)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showChangeReasonDialog, setShowChangeReasonDialog] = useState(false)

  // Unified dirty state tracking across all tabs
  const [dirtyTabs, setDirtyTabs] = useState<Set<string>>(new Set())
  const hasUnsavedChanges = dirtyTabs.size > 0

  // Unified pending changes from all tabs
  const [pendingPatternChanges, setPendingPatternChanges] = useState<Partial<IndexPattern>>({})
  const [pendingEnrichmentChanges, setPendingEnrichmentChanges] = useState<IndexPatternEnrichmentsUpdate | null>(null)

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

  // Handle save from Settings tab (for new patterns or direct saves)
  const handleSettingsSave = async (data: Partial<IndexPattern>) => {
    if (isNew) {
      // For new patterns, save directly (no audit needed)
      setIsSaving(true)
      try {
        const created = await indexPatternsApi.create(data as Parameters<typeof indexPatternsApi.create>[0])
        setDirtyTabs(new Set()) // Clear before navigation
        showToast('Index pattern created')
        // Navigate to the edit view of the new pattern
        navigate(`/index-patterns/${created.id}`, { replace: true })
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to save'
        showToast(message, 'error')
        throw err // Re-throw so SettingsTab can show the error
      } finally {
        setIsSaving(false)
      }
    } else {
      // For updates, merge with pending changes and show dialog
      setPendingPatternChanges(prev => ({ ...prev, ...data }))
      setShowChangeReasonDialog(true)
    }
  }

  // Trigger unified save (shows change reason dialog)
  const handleUnifiedSave = () => {
    if (!pattern) return
    setShowChangeReasonDialog(true)
  }

  // Handle confirm save with change reason (unified save for all tabs)
  const handleConfirmSave = async (changeReason: string) => {
    if (!pattern) return

    setIsSaving(true)
    try {
      // Save index pattern changes if any
      if (Object.keys(pendingPatternChanges).length > 0) {
        const updated = await indexPatternsApi.update(pattern.id, {
          ...pendingPatternChanges,
          change_reason: changeReason,
        })
        setPattern(updated)
      }

      // Save webhook enrichment changes if any
      if (pendingEnrichmentChanges) {
        await indexPatternEnrichmentsApi.update(pattern.id, pendingEnrichmentChanges)
      }

      // Clear all dirty state
      setDirtyTabs(new Set())
      setPendingPatternChanges({})
      setPendingEnrichmentChanges(null)
      showToast('Index pattern updated')
      setShowChangeReasonDialog(false)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save'
      showToast(message, 'error')
    } finally {
      setIsSaving(false)
    }
  }

  // Stable dirty handlers for each tab (memoized to prevent infinite loops)
  const handleSettingsDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('settings') } else { next.delete('settings') }
      return next
    })
  }, [])

  const handleThreatIntelDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('threat-intel') } else { next.delete('threat-intel') }
      return next
    })
  }, [])

  const handleIocDetectionDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('ioc-detection') } else { next.delete('ioc-detection') }
      return next
    })
  }, [])

  const handleGeoipDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('geoip') } else { next.delete('geoip') }
      return next
    })
  }, [])

  const handleWebhooksDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('webhooks') } else { next.delete('webhooks') }
      return next
    })
  }, [])

  const handleSecurityDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('security') } else { next.delete('security') }
      return next
    })
  }, [])

  const handleHealthDirty = useCallback((isDirty: boolean) => {
    setDirtyTabs(prev => {
      const next = new Set(prev)
      if (isDirty) { next.add('health') } else { next.delete('health') }
      return next
    })
  }, [])

  // Handle pending changes from any tab (for index pattern fields)
  const handlePendingPatternChange = useCallback((changes: Partial<IndexPattern>) => {
    setPendingPatternChanges(prev => ({ ...prev, ...changes }))
  }, [])

  // Handle pending changes for webhook enrichments (separate API)
  const handlePendingEnrichmentChange = useCallback((changes: IndexPatternEnrichmentsUpdate) => {
    setPendingEnrichmentChanges(changes)
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
        {/* Unified Save button - always visible */}
        <Button
          onClick={() => {
            if (isNew && activeTab === 'settings') {
              // For new patterns, trigger form submission
              const form = document.getElementById('settings-form') as HTMLFormElement
              form?.requestSubmit()
            } else {
              // For existing patterns, show change reason dialog
              handleUnifiedSave()
            }
          }}
          disabled={isSaving || !hasUnsavedChanges}
        >
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              {isNew ? 'Create Pattern' : 'Save Changes'}
            </>
          )}
        </Button>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
        <TabsList className="flex-wrap h-auto gap-1">
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
            value="threat-intel"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Shield className="h-4 w-4" />
            Threat Intel
          </TabsTrigger>
          <TabsTrigger
            value="ioc-detection"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Crosshair className="h-4 w-4" />
            IOC Detection
          </TabsTrigger>
          <TabsTrigger
            value="geoip"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Globe className="h-4 w-4" />
            GeoIP
          </TabsTrigger>
          <TabsTrigger
            value="webhooks"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <Webhook className="h-4 w-4" />
            Webhooks
          </TabsTrigger>
          <TabsTrigger
            value="security"
            className="flex items-center gap-2"
            disabled={isNew || pattern?.mode !== 'push'}
          >
            <Lock className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger
            value="health"
            className="flex items-center gap-2"
            disabled={isNew}
          >
            <HeartPulse className="h-4 w-4" />
            Health
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

        {/* Tab Contents - Full width */}
        <TabsContent value="settings" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            <SettingsTab
              pattern={pattern}
              isNew={isNew}
              onSave={handleSettingsSave}
              isSaving={isSaving}
              onDirtyChange={handleSettingsDirty}
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

        <TabsContent value="threat-intel" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <TIEnrichmentTab
                pattern={pattern}
                onDirtyChange={handleThreatIntelDirty}
                onPendingChange={handlePendingPatternChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure threat intelligence enrichment.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="ioc-detection" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <IOCDetectionTab
                pattern={pattern}
                onDirtyChange={handleIocDetectionDirty}
                onPendingChange={handlePendingPatternChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure IOC detection.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="geoip" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <GeoIPTab
                pattern={pattern}
                onDirtyChange={handleGeoipDirty}
                onPendingChange={handlePendingPatternChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure GeoIP enrichment.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="webhooks" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <WebhooksTab
                pattern={pattern}
                onDirtyChange={handleWebhooksDirty}
                onPendingChange={handlePendingEnrichmentChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure webhook enrichment.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="security" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <SecurityTab
                pattern={pattern}
                onDirtyChange={handleSecurityDirty}
                onPendingChange={handlePendingPatternChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure security settings.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="health" className="mt-0">
          <div className="rounded-lg border bg-card p-6">
            {pattern ? (
              <HealthTab
                pattern={pattern}
                onDirtyChange={handleHealthDirty}
                onPendingChange={handlePendingPatternChange}
              />
            ) : (
              <div className="text-sm text-muted-foreground py-8 text-center">
                Save the pattern first to configure health alerting.
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
      </Tabs>

      <ChangeReasonDialog
        open={showChangeReasonDialog}
        onOpenChange={setShowChangeReasonDialog}
        onConfirm={handleConfirmSave}
        title="Save Index Pattern Changes"
        description="Please provide a reason for these changes. This will be recorded in the audit log."
        isLoading={isSaving}
      />
    </div>
  )
}
