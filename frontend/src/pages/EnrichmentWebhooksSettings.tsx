import { useEffect, useState } from 'react'
import {
  enrichmentWebhooksApi,
  EnrichmentWebhook,
  EnrichmentWebhookCreate,
  EnrichmentWebhookMethod,
} from '@/lib/api'
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import {
  Check,
  Loader2,
  Plus,
  Pencil,
  Trash2,
  Webhook,
  XCircle,
  Zap,
} from 'lucide-react'
import { Link } from 'react-router-dom'

type WebhookFormData = {
  name: string
  url: string
  namespace: string
  method: EnrichmentWebhookMethod
  header_name: string
  header_value: string
  timeout_seconds: number
  max_concurrent_calls: number
  cache_ttl_seconds: number
  is_active: boolean
}

const DEFAULT_FORM_DATA: WebhookFormData = {
  name: '',
  url: '',
  namespace: '',
  method: 'POST',
  header_name: '',
  header_value: '',
  timeout_seconds: 10,
  max_concurrent_calls: 5,
  cache_ttl_seconds: 300,
  is_active: true,
}

export default function EnrichmentWebhooksSettings() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [webhooks, setWebhooks] = useState<EnrichmentWebhook[]>([])
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingWebhook, setEditingWebhook] = useState<EnrichmentWebhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(DEFAULT_FORM_DATA)
  const [isSaving, setIsSaving] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<{
    success: boolean
    error?: string | null
    response_data?: Record<string, unknown>
  } | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)

  useEffect(() => {
    loadWebhooks()
  }, [])

  const loadWebhooks = async () => {
    try {
      const data = await enrichmentWebhooksApi.list()
      setWebhooks(data)
    } catch {
      console.log('Failed to load enrichment webhooks')
    } finally {
      setIsLoading(false)
    }
  }

  const handleOpenDialog = (webhook?: EnrichmentWebhook) => {
    if (webhook) {
      setEditingWebhook(webhook)
      setFormData({
        name: webhook.name,
        url: webhook.url,
        namespace: webhook.namespace,
        method: webhook.method,
        header_name: webhook.header_name || '',
        header_value: '',
        timeout_seconds: webhook.timeout_seconds,
        max_concurrent_calls: webhook.max_concurrent_calls,
        cache_ttl_seconds: webhook.cache_ttl_seconds,
        is_active: webhook.is_active,
      })
    } else {
      setEditingWebhook(null)
      setFormData(DEFAULT_FORM_DATA)
    }
    setTestResult(null)
    setIsDialogOpen(true)
  }

  const handleCloseDialog = () => {
    setIsDialogOpen(false)
    setEditingWebhook(null)
    setFormData(DEFAULT_FORM_DATA)
    setTestResult(null)
  }

  const handleToggleActive = async (webhook: EnrichmentWebhook) => {
    try {
      await enrichmentWebhooksApi.update(webhook.id, {
        is_active: !webhook.is_active,
      })
      setWebhooks((prev) =>
        prev.map((w) =>
          w.id === webhook.id ? { ...w, is_active: !w.is_active } : w
        )
      )
      showToast(
        `${webhook.name} ${!webhook.is_active ? 'enabled' : 'disabled'}`,
        !webhook.is_active ? 'success' : 'info'
      )
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update', 'error')
    }
  }

  const handleTest = async () => {
    setIsTesting(true)
    setTestResult(null)

    try {
      let result
      if (editingWebhook) {
        // Test existing webhook
        result = await enrichmentWebhooksApi.test(editingWebhook.id)
      } else {
        // Test new webhook URL
        result = await enrichmentWebhooksApi.testUrl({
          url: formData.url,
          method: formData.method,
          header_name: formData.header_name || undefined,
          header_value: formData.header_value || undefined,
          timeout_seconds: formData.timeout_seconds,
        })
      }

      setTestResult(result)
      if (result.success) {
        showToast('Webhook test successful')
      } else {
        showToast(result.error || 'Test failed', 'error')
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Test failed'
      setTestResult({ success: false, error: errorMsg })
      showToast(errorMsg, 'error')
    } finally {
      setIsTesting(false)
    }
  }

  const handleSave = async () => {
    // Validate required fields
    if (!formData.name.trim()) {
      showToast('Name is required', 'error')
      return
    }
    if (!formData.url.trim()) {
      showToast('URL is required', 'error')
      return
    }
    if (!formData.namespace.trim()) {
      showToast('Namespace is required', 'error')
      return
    }

    // Validate namespace format (lowercase letters, numbers, underscores)
    if (!/^[a-z][a-z0-9_]*$/.test(formData.namespace)) {
      showToast(
        'Namespace must start with lowercase letter and contain only lowercase letters, numbers, and underscores',
        'error'
      )
      return
    }

    setIsSaving(true)

    try {
      if (editingWebhook) {
        // Update existing webhook
        const updated = await enrichmentWebhooksApi.update(editingWebhook.id, {
          name: formData.name,
          url: formData.url,
          method: formData.method,
          header_name: formData.header_name || undefined,
          header_value: formData.header_value || undefined,
          timeout_seconds: formData.timeout_seconds,
          max_concurrent_calls: formData.max_concurrent_calls,
          cache_ttl_seconds: formData.cache_ttl_seconds,
          is_active: formData.is_active,
        })
        setWebhooks((prev) =>
          prev.map((w) => (w.id === editingWebhook.id ? updated : w))
        )
        showToast('Webhook updated')
      } else {
        // Create new webhook
        const createData: EnrichmentWebhookCreate = {
          name: formData.name,
          url: formData.url,
          namespace: formData.namespace,
          method: formData.method,
          timeout_seconds: formData.timeout_seconds,
          max_concurrent_calls: formData.max_concurrent_calls,
          cache_ttl_seconds: formData.cache_ttl_seconds,
          is_active: formData.is_active,
        }
        if (formData.header_name) {
          createData.header_name = formData.header_name
          if (formData.header_value) {
            createData.header_value = formData.header_value
          }
        }
        const created = await enrichmentWebhooksApi.create(createData)
        setWebhooks((prev) => [...prev, created])
        showToast('Webhook created')
      }

      handleCloseDialog()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async (webhook: EnrichmentWebhook) => {
    setDeletingId(webhook.id)
    try {
      await enrichmentWebhooksApi.delete(webhook.id)
      setWebhooks((prev) => prev.filter((w) => w.id !== webhook.id))
      showToast('Webhook deleted')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    } finally {
      setDeletingId(null)
    }
  }

  const getActiveCount = () => webhooks.filter((w) => w.is_active).length

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
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Webhook className="h-5 w-5" />
              Custom Enrichment Webhooks
            </div>
            <Button onClick={() => handleOpenDialog()} size="sm">
              <Plus className="h-4 w-4 mr-2" />
              Add Webhook
            </Button>
          </CardTitle>
          <div className="text-sm text-muted-foreground">
            <span>
              Configure external webhooks to enrich alerts with data from your internal systems
              (Entra ID, CMDB, HR systems, etc).
            </span>
            {getActiveCount() > 0 && (
              <span className="ml-2">
                <Badge variant="secondary">{getActiveCount()} active</Badge>
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {webhooks.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Webhook className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No enrichment webhooks configured</p>
              <p className="text-sm mt-2">
                Add a webhook to enrich alerts with custom data from external systems.
              </p>
            </div>
          ) : (
            webhooks.map((webhook) => (
              <div
                key={webhook.id}
                className="border rounded-lg p-4 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <Switch
                    checked={webhook.is_active}
                    onCheckedChange={() => handleToggleActive(webhook)}
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{webhook.name}</span>
                      <Badge variant="outline" className="text-xs font-mono">
                        {webhook.namespace}
                      </Badge>
                      {webhook.is_active && (
                        <Badge className="text-xs bg-green-600">Active</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {webhook.method} {webhook.url}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Timeout: {webhook.timeout_seconds}s | Cache: {webhook.cache_ttl_seconds}s |
                      Concurrent: {webhook.max_concurrent_calls}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleOpenDialog(webhook)}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDelete(webhook)}
                    disabled={deletingId === webhook.id}
                  >
                    {deletingId === webhook.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4 text-destructive" />
                    )}
                  </Button>
                </div>
              </div>
            ))
          )}

          {webhooks.length > 0 && (
            <div className="border-t pt-4 mt-4">
              <p className="text-sm text-muted-foreground">
                Configure which index patterns use these webhooks in{' '}
                <Link to="/index-patterns" className="text-primary hover:underline">
                  Index Pattern settings
                </Link>
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add/Edit Webhook Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingWebhook ? 'Edit Webhook' : 'Add Enrichment Webhook'}
            </DialogTitle>
            <DialogDescription>
              {editingWebhook
                ? 'Update the webhook configuration.'
                : 'Configure a new webhook to enrich alerts with external data.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, name: e.target.value }))
                }
                placeholder="Entra ID User Lookup"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="namespace">Namespace</Label>
              <Input
                id="namespace"
                value={formData.namespace}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    namespace: e.target.value.toLowerCase(),
                  }))
                }
                placeholder="entra_id"
                disabled={!!editingWebhook}
              />
              <p className="text-xs text-muted-foreground">
                Prefix for enrichment fields (e.g., entra_id.display_name). Cannot be changed after
                creation.
              </p>
            </div>

            <div className="grid grid-cols-4 gap-4">
              <div className="space-y-2">
                <Label htmlFor="method">Method</Label>
                <Select
                  value={formData.method}
                  onValueChange={(value: EnrichmentWebhookMethod) =>
                    setFormData((prev) => ({ ...prev, method: value }))
                  }
                >
                  <SelectTrigger id="method">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    <SelectItem value="POST">POST</SelectItem>
                    <SelectItem value="GET">GET</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="col-span-3 space-y-2">
                <Label htmlFor="url">URL</Label>
                <Input
                  id="url"
                  value={formData.url}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, url: e.target.value }))
                  }
                  placeholder="https://api.example.com/enrich"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="header_name">Auth Header Name</Label>
                <Input
                  id="header_name"
                  value={formData.header_name}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, header_name: e.target.value }))
                  }
                  placeholder="Authorization"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="header_value">Auth Header Value</Label>
                <Input
                  id="header_value"
                  type="password"
                  value={formData.header_value}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, header_value: e.target.value }))
                  }
                  placeholder={editingWebhook?.has_credentials ? '********' : 'Bearer token...'}
                />
                {editingWebhook?.has_credentials && (
                  <p className="text-xs text-muted-foreground">
                    Leave blank to keep existing credentials
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="timeout">Timeout (s)</Label>
                <Input
                  id="timeout"
                  type="number"
                  min={1}
                  max={30}
                  value={formData.timeout_seconds}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      timeout_seconds: parseInt(e.target.value) || 10,
                    }))
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="cache_ttl">Cache TTL (s)</Label>
                <Input
                  id="cache_ttl"
                  type="number"
                  min={0}
                  max={86400}
                  value={formData.cache_ttl_seconds}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      cache_ttl_seconds: parseInt(e.target.value) || 0,
                    }))
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="concurrent">Concurrent</Label>
                <Input
                  id="concurrent"
                  type="number"
                  min={1}
                  max={20}
                  value={formData.max_concurrent_calls}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      max_concurrent_calls: parseInt(e.target.value) || 5,
                    }))
                  }
                />
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="is_active"
                checked={formData.is_active}
                onCheckedChange={(checked) =>
                  setFormData((prev) => ({ ...prev, is_active: checked }))
                }
              />
              <Label htmlFor="is_active">Active</Label>
            </div>

            {/* Test Result */}
            {testResult && (
              <div
                className={`p-3 rounded-md text-sm ${
                  testResult.success
                    ? 'bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300'
                    : 'bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  {testResult.success ? (
                    <>
                      <Check className="h-4 w-4" />
                      Connection successful
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4" />
                      {testResult.error || 'Connection failed'}
                    </>
                  )}
                </div>
                {testResult.success && testResult.response_data && (
                  <pre className="mt-2 text-xs bg-black/10 dark:bg-white/10 p-2 rounded overflow-auto max-h-32">
                    {JSON.stringify(testResult.response_data, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={handleCloseDialog}>
              Cancel
            </Button>
            <Button
              variant="outline"
              onClick={handleTest}
              disabled={isTesting || !formData.url}
            >
              {isTesting ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Zap className="h-4 w-4 mr-2" />
              )}
              Test
            </Button>
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : null}
              {editingWebhook ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
