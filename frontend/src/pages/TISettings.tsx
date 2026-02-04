import { useEffect, useState } from 'react'
import {
  tiApi,
  TISourceConfig,
  TISourceType,
  TISourceConfigUpdate,
  TI_SOURCE_INFO,
} from '@/lib/api'
import { MISPSyncDashboard } from '@/components/ti/MISPSyncDashboard'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Badge } from '@/components/ui/badge'
import { Check, ChevronDown, ExternalLink, Loader2, Shield, XCircle } from 'lucide-react'

type SourceFormState = {
  apiKey: string
  instanceUrl: string
  verifyTls: boolean
  isTesting: boolean
  isSaving: boolean
  testResult: { success: boolean; error?: string | null } | null
}

export default function TISettings() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [sources, setSources] = useState<TISourceConfig[]>([])
  const [expandedSource, setExpandedSource] = useState<TISourceType | null>(null)
  const [formStates, setFormStates] = useState<Record<TISourceType, SourceFormState>>({
    virustotal: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    abuseipdb: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    greynoise: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    threatfox: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    misp: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    abuse_ch: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    alienvault_otx: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
    phishtank: { apiKey: '', instanceUrl: '', verifyTls: true, isTesting: false, isSaving: false, testResult: null },
  })

  useEffect(() => {
    loadSources()
  }, [])

  const loadSources = async () => {
    try {
      const response = await tiApi.listSources()
      setSources(response.sources)
      // Initialize form state with saved config values (e.g., verify_tls)
      response.sources.forEach((source) => {
        const sourceType = source.source_type as TISourceType
        const verifyTls = typeof source.config?.verify_tls === 'boolean' ? source.config.verify_tls : true
        updateFormState(sourceType, { verifyTls })
      })
    } catch {
      console.log('Failed to load TI sources')
    } finally {
      setIsLoading(false)
    }
  }

  const updateFormState = (
    sourceType: TISourceType,
    updates: Partial<SourceFormState>
  ) => {
    setFormStates((prev) => ({
      ...prev,
      [sourceType]: { ...prev[sourceType], ...updates },
    }))
  }

  const handleToggleEnabled = async (source: TISourceConfig) => {
    const newEnabled = !source.is_enabled

    // If enabling and no API key is configured (for sources that require it)
    const info = TI_SOURCE_INFO[source.source_type as TISourceType]
    if (newEnabled && info.requiresKey && !source.has_api_key) {
      showToast(`Please configure an API key for ${info.name} first`, 'error')
      setExpandedSource(source.source_type as TISourceType)
      return
    }

    try {
      await tiApi.updateSource(source.source_type as TISourceType, {
        is_enabled: newEnabled,
      })
      setSources((prev) =>
        prev.map((s) =>
          s.source_type === source.source_type ? { ...s, is_enabled: newEnabled } : s
        )
      )
      showToast(
        `${info.name} ${newEnabled ? 'enabled' : 'disabled'}`,
        newEnabled ? 'success' : 'info'
      )
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update', 'error')
    }
  }

  const handleTestConnection = async (sourceType: TISourceType) => {
    const formState = formStates[sourceType]
    const source = sources.find((s) => s.source_type === sourceType)
    const info = TI_SOURCE_INFO[sourceType]

    // Check if we have an API key to test with
    if (info.requiresKey && !formState.apiKey && !source?.has_api_key) {
      showToast('Please enter an API key', 'error')
      return
    }

    updateFormState(sourceType, { isTesting: true, testResult: null })

    try {
      let result
      if (formState.apiKey) {
        // Test with new API key
        result = await tiApi.testConnection(sourceType, {
          is_enabled: true,
          api_key: formState.apiKey,
          instance_url: formState.instanceUrl || null,
          config: info.requiresInstance ? { verify_tls: formState.verifyTls } : null,
        })
      } else if (source?.has_api_key) {
        // Test saved configuration
        result = await tiApi.testSavedConnection(sourceType)
      } else {
        // For ThreatFox (no key required)
        result = await tiApi.testConnection(sourceType, {
          is_enabled: true,
          config: info.requiresInstance ? { verify_tls: formState.verifyTls } : null,
        })
      }

      updateFormState(sourceType, { testResult: result })
      if (result.success) {
        showToast(`${info.name} connection successful`)
      } else {
        showToast(result.error || 'Connection failed', 'error')
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Connection test failed'
      updateFormState(sourceType, {
        testResult: { success: false, error: errorMsg },
      })
      showToast(errorMsg, 'error')
    } finally {
      updateFormState(sourceType, { isTesting: false })
    }
  }

  const handleSave = async (sourceType: TISourceType) => {
    const formState = formStates[sourceType]
    const info = TI_SOURCE_INFO[sourceType]
    const source = sources.find((s) => s.source_type === sourceType)

    // Validate API key for new configurations that require it
    if (info.requiresKey && !source?.has_api_key && !formState.apiKey) {
      showToast('API key is required', 'error')
      return
    }

    updateFormState(sourceType, { isSaving: true })

    try {
      const data: TISourceConfigUpdate = {
        is_enabled: source?.is_enabled ?? false,
        instance_url: formState.instanceUrl || null,
        config: info.requiresInstance ? { verify_tls: formState.verifyTls } : null,
      }

      // Only include API key if provided
      if (formState.apiKey) {
        data.api_key = formState.apiKey
      }

      const updated = await tiApi.updateSource(sourceType, data)
      setSources((prev) =>
        prev.map((s) => (s.source_type === sourceType ? updated : s))
      )

      // Clear the form
      updateFormState(sourceType, {
        apiKey: '',
        testResult: null,
      })

      showToast(`${info.name} configuration saved`)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      updateFormState(sourceType, { isSaving: false })
    }
  }

  const getEnabledCount = () => sources.filter((s) => s.is_enabled).length

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Threat Intelligence Sources
          </CardTitle>
          <div className="text-sm text-muted-foreground">
            <span>Configure external threat intelligence providers to automatically enrich alerts with reputation data, risk scores, and indicator context.</span>
            {getEnabledCount() > 0 && (
              <span className="ml-2">
                <Badge variant="secondary">{getEnabledCount()} enabled</Badge>
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {sources.map((source) => {
            const sourceType = source.source_type as TISourceType
            const info = TI_SOURCE_INFO[sourceType]
            const formState = formStates[sourceType]
            const isExpanded = expandedSource === sourceType

            return (
              <Collapsible
                key={source.source_type}
                open={isExpanded}
                onOpenChange={(open) => setExpandedSource(open ? sourceType : null)}
              >
                <div className="border rounded-lg">
                  <div className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-4">
                      <Switch
                        checked={source.is_enabled}
                        onCheckedChange={() => handleToggleEnabled(source)}
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{info.name}</span>
                          {source.has_api_key && (
                            <Badge variant="outline" className="text-xs">
                              Configured
                            </Badge>
                          )}
                          {source.is_enabled && (
                            <Badge className="text-xs bg-green-600">Active</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{info.description}</p>
                      </div>
                    </div>
                    <CollapsibleTrigger asChild>
                      <Button variant="ghost" size="sm">
                        <ChevronDown
                          className={`h-4 w-4 transition-transform ${
                            isExpanded ? 'transform rotate-180' : ''
                          }`}
                        />
                      </Button>
                    </CollapsibleTrigger>
                  </div>

                  <CollapsibleContent>
                    <div className="border-t p-4 space-y-4 bg-muted/50">
                      {/* Instance URL Input */}
                      {info.requiresInstance && (
                        <div className="space-y-2">
                          <Label htmlFor={`${sourceType}-instance-url`}>Instance URL</Label>
                          <Input
                            id={`${sourceType}-instance-url`}
                            type="text"
                            value={formState.instanceUrl}
                            onChange={(e) =>
                              updateFormState(sourceType, { instanceUrl: e.target.value })
                            }
                            placeholder={
                              source.instance_url
                                ? source.instance_url
                                : `https://${sourceType}.example.com`
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            {source.instance_url
                              ? 'Leave blank to keep existing URL'
                              : `Enter your ${info.name} instance URL (e.g., https://misp.example.com)`}
                          </p>
                        </div>
                      )}

                      {/* TLS Verification Toggle - for self-hosted instances with internal certs */}
                      {info.requiresInstance && (
                        <div className="flex items-center space-x-2">
                          <Switch
                            id={`${sourceType}-verify-tls`}
                            checked={formState.verifyTls}
                            onCheckedChange={(checked) =>
                              updateFormState(sourceType, { verifyTls: checked })
                            }
                          />
                          <Label htmlFor={`${sourceType}-verify-tls`} className="text-sm font-normal">
                            Verify TLS certificate
                          </Label>
                          <span className="text-xs text-muted-foreground">
                            (disable for self-signed certificates)
                          </span>
                        </div>
                      )}

                      {/* API Key Input */}
                      {info.requiresKey && (
                        <div className="space-y-2">
                          <Label htmlFor={`${sourceType}-api-key`}>API Key</Label>
                          <Input
                            id={`${sourceType}-api-key`}
                            type="password"
                            value={formState.apiKey}
                            onChange={(e) =>
                              updateFormState(sourceType, { apiKey: e.target.value })
                            }
                            placeholder={
                              source.has_api_key
                                ? '********'
                                : `Enter ${info.name} API key`
                            }
                          />
                          <p className="text-xs text-muted-foreground">
                            {source.has_api_key ? (
                              'Leave blank to keep existing key'
                            ) : (
                              <>
                                Get your API key from{' '}
                                <a
                                  href={info.docsUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="underline hover:text-foreground inline-flex items-center gap-1"
                                >
                                  {info.name} documentation
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                              </>
                            )}
                          </p>
                        </div>
                      )}

                      {!info.requiresKey && (
                        <p className="text-sm text-muted-foreground">
                          {info.name} does not require an API key. It provides free community
                          threat intelligence data.
                        </p>
                      )}

                      {/* Test and Save Buttons */}
                      <div className="flex items-center gap-4">
                        <Button
                          variant="outline"
                          onClick={() => handleTestConnection(sourceType)}
                          disabled={formState.isTesting}
                        >
                          {formState.isTesting ? (
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          ) : null}
                          Test Connection
                        </Button>

                        <Button
                          onClick={() => handleSave(sourceType)}
                          disabled={formState.isSaving}
                        >
                          {formState.isSaving ? (
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          ) : null}
                          Save Configuration
                        </Button>

                        {formState.testResult && (
                          <span
                            className={`flex items-center text-sm ${
                              formState.testResult.success
                                ? 'text-green-600'
                                : 'text-red-600'
                            }`}
                          >
                            {formState.testResult.success ? (
                              <>
                                <Check className="h-4 w-4 mr-1" />
                                Connection successful
                              </>
                            ) : (
                              <>
                                <XCircle className="h-4 w-4 mr-1" />
                                {formState.testResult.error || 'Connection failed'}
                              </>
                            )}
                          </span>
                        )}
                      </div>

                      {/* MISP IOC Sync - embedded inside MISP source section */}
                      {sourceType === 'misp' && source.is_enabled && source.has_api_key && (
                        <div className="mt-4 pt-4 border-t">
                          <h4 className="font-medium mb-2">IOC Sync Settings</h4>
                          <MISPSyncDashboard embedded />
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </div>
              </Collapsible>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}
