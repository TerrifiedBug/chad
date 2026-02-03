import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { mispSyncApi, MISPSyncConfig, MISPSyncStatus } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { AlertCircle, CheckCircle2, ChevronDown, Clock, Database, Loader2, RefreshCw } from 'lucide-react'

const THREAT_LEVELS = [
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

const IOC_TYPES = [
  { value: 'ip-dst', label: 'IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'md5', label: 'MD5' },
  { value: 'sha256', label: 'SHA256' },
]

function formatRelativeTime(isoString: string | null): string {
  if (!isoString) return 'Never'
  const date = new Date(isoString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
}

export function MISPSyncDashboard() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(true)
  const [isSaving, setIsSaving] = useState(false)

  // Load status
  const { data: status, isLoading: statusLoading } = useQuery<MISPSyncStatus>({
    queryKey: ['misp-sync-status'],
    queryFn: () => mispSyncApi.getStatus(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Load config
  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ['misp-sync-config'],
    queryFn: () => mispSyncApi.getConfig(),
  })

  // Local config state for editing
  const [localConfig, setLocalConfig] = useState<Partial<MISPSyncConfig>>({})

  // Merge loaded config with local changes
  const mergedConfig = { ...config, ...localConfig }

  // Trigger sync mutation
  const triggerMutation = useMutation({
    mutationFn: () => mispSyncApi.trigger(),
    onSuccess: (result) => {
      if (result.success) {
        showToast(`Synced ${result.iocs_fetched.toLocaleString()} IOCs in ${result.duration_ms}ms`)
      } else {
        showToast(result.error || 'Sync failed', 'error')
      }
      queryClient.invalidateQueries({ queryKey: ['misp-sync-status'] })
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Sync failed', 'error')
    },
  })

  const handleSaveConfig = async () => {
    if (Object.keys(localConfig).length === 0) return

    setIsSaving(true)
    try {
      await mispSyncApi.updateConfig(localConfig)
      queryClient.invalidateQueries({ queryKey: ['misp-sync-config'] })
      setLocalConfig({})
      showToast('Sync settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const updateConfig = (updates: Partial<MISPSyncConfig>) => {
    setLocalConfig(prev => ({ ...prev, ...updates }))
  }

  const toggleThreatLevel = (level: string, checked: boolean) => {
    const current = mergedConfig.threat_levels || []
    const updated = checked
      ? [...current, level]
      : current.filter(l => l !== level)
    updateConfig({ threat_levels: updated })
  }

  const toggleIOCType = (type: string, checked: boolean) => {
    const current = mergedConfig.ioc_types || IOC_TYPES.map(t => t.value)
    const updated = checked
      ? [...current, type]
      : current.filter(t => t !== type)
    updateConfig({ ioc_types: updated.length > 0 ? updated : null })
  }

  const isLoading = statusLoading || configLoading
  const hasChanges = Object.keys(localConfig).length > 0

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50 rounded-lg">
        <div className="flex items-center gap-3">
          <Database className="h-5 w-5" />
          <div className="text-left">
            <h3 className="font-medium">MISP IOC Sync</h3>
            <p className="text-sm text-muted-foreground">
              Sync indicators for real-time detection
            </p>
          </div>
        </div>
        <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </CollapsibleTrigger>

      <CollapsibleContent className="px-4 pb-4">
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        ) : (
          <div className="space-y-6 pt-4">
            {/* Status Card */}
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">Sync Status</CardTitle>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => triggerMutation.mutate()}
                    disabled={triggerMutation.isPending}
                  >
                    {triggerMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <RefreshCw className="h-4 w-4" />
                    )}
                    <span className="ml-2">Sync Now</span>
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Last Sync:</span>
                    <span className="font-medium">{formatRelativeTime(status?.last_sync_at ?? null)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Redis:</span>
                    <span className="font-medium">{(status?.redis_ioc_count ?? 0).toLocaleString()} IOCs</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">OpenSearch:</span>
                    <span className="font-medium">{(status?.opensearch_ioc_count ?? 0).toLocaleString()} IOCs</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Duration:</span>
                    <span className="font-medium">{status?.sync_duration_ms ?? 0}ms</span>
                  </div>
                </div>
                {status?.error_message && (
                  <div className="mt-3 flex items-start gap-2 p-2 rounded bg-destructive/10 text-destructive text-sm">
                    <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                    {status.error_message}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Configuration */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-base">Enable Automatic Sync</Label>
                  <p className="text-sm text-muted-foreground">
                    Sync IOCs from MISP on a schedule
                  </p>
                </div>
                <Switch
                  checked={mergedConfig.enabled ?? false}
                  onCheckedChange={(checked) => updateConfig({ enabled: checked })}
                />
              </div>

              {mergedConfig.enabled && (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label>Sync Interval (minutes)</Label>
                      <Input
                        type="number"
                        min={1}
                        max={1440}
                        value={mergedConfig.interval_minutes ?? 10}
                        onChange={(e) => updateConfig({ interval_minutes: parseInt(e.target.value) || 10 })}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label>Max Age (days)</Label>
                      <Input
                        type="number"
                        min={1}
                        max={365}
                        value={mergedConfig.max_age_days ?? 30}
                        onChange={(e) => updateConfig({ max_age_days: parseInt(e.target.value) || 30 })}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label>TTL / Cache Expiry (days)</Label>
                      <Input
                        type="number"
                        min={1}
                        max={365}
                        value={mergedConfig.ttl_days ?? 30}
                        onChange={(e) => updateConfig({ ttl_days: parseInt(e.target.value) || 30 })}
                        className="mt-1"
                      />
                    </div>
                  </div>

                  <div>
                    <Label>Threat Levels</Label>
                    <div className="flex gap-4 mt-2">
                      {THREAT_LEVELS.map(({ value, label }) => (
                        <label key={value} className="flex items-center gap-2 cursor-pointer">
                          <Checkbox
                            checked={(mergedConfig.threat_levels ?? []).includes(value)}
                            onCheckedChange={(checked) => toggleThreatLevel(value, !!checked)}
                          />
                          <span className="text-sm">{label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div>
                    <Label>IOC Types</Label>
                    <div className="flex flex-wrap gap-4 mt-2">
                      {IOC_TYPES.map(({ value, label }) => (
                        <label key={value} className="flex items-center gap-2 cursor-pointer">
                          <Checkbox
                            checked={(mergedConfig.ioc_types ?? IOC_TYPES.map(t => t.value)).includes(value)}
                            onCheckedChange={(checked) => toggleIOCType(value, !!checked)}
                          />
                          <span className="text-sm">{label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div>
                    <Label>Tags Filter (optional)</Label>
                    <Input
                      placeholder="e.g., tlp:amber, apt"
                      value={(mergedConfig.tags ?? []).join(', ')}
                      onChange={(e) => {
                        const tags = e.target.value
                          .split(',')
                          .map(t => t.trim())
                          .filter(Boolean)
                        updateConfig({ tags: tags.length > 0 ? tags : null })
                      }}
                      className="mt-1"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Comma-separated. Only sync IOCs with these tags.
                    </p>
                  </div>
                </>
              )}
            </div>

            {hasChanges && (
              <div className="flex justify-end pt-4 border-t">
                <Button onClick={handleSaveConfig} disabled={isSaving}>
                  {isSaving ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                  )}
                  Save Settings
                </Button>
              </div>
            )}
          </div>
        )}
      </CollapsibleContent>
    </Collapsible>
  )
}
