import { useState, useEffect } from 'react'
import { webhooksApi, Webhook } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import {
  CheckCircle2,
  ExternalLink,
  Key,
  Loader2,
  Pencil,
  Plus,
  Send,
  Trash2,
  XCircle,
} from 'lucide-react'

type WebhookFormData = {
  name: string
  url: string
  auth_header: string
  enabled: boolean
}

const emptyFormData: WebhookFormData = {
  name: '',
  url: '',
  auth_header: '',
  enabled: true,
}

export default function WebhooksSettings() {
  const { showToast } = useToast()
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [isLoading, setIsLoading] = useState(true)

  // Dialog states
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(emptyFormData)
  const [isSaving, setIsSaving] = useState(false)

  // Delete modal state
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Test state
  const [testingId, setTestingId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; error?: string }>>({})

  useEffect(() => {
    loadWebhooks()
  }, [])

  const loadWebhooks = async () => {
    try {
      const data = await webhooksApi.list()
      setWebhooks(data)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load webhooks', 'error')
    } finally {
      setIsLoading(false)
    }
  }

  const openAddDialog = () => {
    setEditingWebhook(null)
    setFormData(emptyFormData)
    setDialogOpen(true)
  }

  const openEditDialog = (webhook: Webhook) => {
    setEditingWebhook(webhook)
    setFormData({
      name: webhook.name,
      url: webhook.url,
      auth_header: '', // Never pre-fill auth header
      enabled: webhook.enabled,
    })
    setDialogOpen(true)
  }

  const closeDialog = () => {
    setDialogOpen(false)
    setEditingWebhook(null)
    setFormData(emptyFormData)
  }

  const handleSave = async () => {
    if (!formData.name.trim()) {
      showToast('Name is required', 'error')
      return
    }
    if (!formData.url.trim()) {
      showToast('URL is required', 'error')
      return
    }

    setIsSaving(true)
    try {
      if (editingWebhook) {
        // Update existing webhook
        const updateData: Partial<{ name: string; url: string; auth_header: string; enabled: boolean }> = {
          name: formData.name,
          url: formData.url,
          enabled: formData.enabled,
        }
        // Only include auth_header if user entered a new one
        if (formData.auth_header) {
          updateData.auth_header = formData.auth_header
        }
        const updated = await webhooksApi.update(editingWebhook.id, updateData)
        setWebhooks(webhooks.map(w => w.id === updated.id ? updated : w))
        showToast('Webhook updated')
      } else {
        // Create new webhook
        const created = await webhooksApi.create({
          name: formData.name,
          url: formData.url,
          auth_header: formData.auth_header || undefined,
          enabled: formData.enabled,
        })
        setWebhooks([...webhooks, created])
        showToast('Webhook created')
      }
      closeDialog()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save webhook', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const openDeleteModal = (webhook: Webhook) => {
    setWebhookToDelete(webhook)
    setDeleteModalOpen(true)
  }

  const handleDelete = async () => {
    if (!webhookToDelete) return

    setIsDeleting(true)
    try {
      await webhooksApi.delete(webhookToDelete.id)
      setWebhooks(webhooks.filter(w => w.id !== webhookToDelete.id))
      // Clear test result
      const newResults = { ...testResults }
      delete newResults[webhookToDelete.id]
      setTestResults(newResults)
      showToast('Webhook deleted')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete webhook', 'error')
    } finally {
      setIsDeleting(false)
      setDeleteModalOpen(false)
      setWebhookToDelete(null)
    }
  }

  const handleTest = async (webhook: Webhook) => {
    setTestingId(webhook.id)
    // Clear previous result
    setTestResults(prev => {
      const newResults = { ...prev }
      delete newResults[webhook.id]
      return newResults
    })

    try {
      const result = await webhooksApi.test(webhook.id)
      setTestResults(prev => ({
        ...prev,
        [webhook.id]: {
          success: result.success,
          error: result.error || (result.status_code ? `Status: ${result.status_code}` : undefined),
        },
      }))
      if (result.success) {
        showToast('Test notification sent successfully')
      } else {
        showToast(result.error || 'Test failed', 'error')
      }
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [webhook.id]: {
          success: false,
          error: err instanceof Error ? err.message : 'Test failed',
        },
      }))
      showToast(err instanceof Error ? err.message : 'Test failed', 'error')
    } finally {
      setTestingId(null)
    }
  }

  const handleToggleEnabled = async (webhook: Webhook) => {
    try {
      const updated = await webhooksApi.update(webhook.id, { enabled: !webhook.enabled })
      setWebhooks(webhooks.map(w => w.id === updated.id ? updated : w))
      showToast(updated.enabled ? 'Webhook enabled' : 'Webhook disabled')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update webhook', 'error')
    }
  }

  const truncateUrl = (url: string, maxLength: number = 50) => {
    if (url.length <= maxLength) return url
    return url.substring(0, maxLength) + '...'
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Webhook Endpoints</h2>
          <p className="text-sm text-muted-foreground">
            Configure HTTP endpoints to receive alert notifications
          </p>
        </div>
        <Button onClick={openAddDialog}>
          <Plus className="mr-2 h-4 w-4" />
          Add Webhook
        </Button>
      </div>

      {webhooks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ExternalLink className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No webhooks configured</h3>
            <p className="text-sm text-muted-foreground text-center max-w-md mb-4">
              Add webhook endpoints to receive alert notifications via HTTP POST requests.
              Webhooks can be used to integrate with external systems like Slack, Discord, or custom notification handlers.
            </p>
            <Button onClick={openAddDialog}>
              <Plus className="mr-2 h-4 w-4" />
              Add First Webhook
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {webhooks.map(webhook => (
            <Card key={webhook.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={webhook.enabled}
                      onCheckedChange={() => handleToggleEnabled(webhook)}
                      aria-label={webhook.enabled ? 'Disable webhook' : 'Enable webhook'}
                    />
                    <div>
                      <CardTitle className="text-base">{webhook.name}</CardTitle>
                      <CardDescription className="flex items-center gap-2 mt-1">
                        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                          {truncateUrl(webhook.url)}
                        </code>
                        {webhook.has_auth && (
                          <span className="flex items-center text-xs text-muted-foreground">
                            <Key className="h-3 w-3 mr-1" />
                            Auth
                          </span>
                        )}
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleTest(webhook)}
                      disabled={testingId === webhook.id || !webhook.enabled}
                    >
                      {testingId === webhook.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Send className="h-4 w-4" />
                      )}
                      <span className="ml-1">Test</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openEditDialog(webhook)}
                    >
                      <Pencil className="h-4 w-4" />
                      <span className="ml-1">Edit</span>
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => openDeleteModal(webhook)}
                      className="text-destructive hover:text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              {testResults[webhook.id] && (
                <CardContent className="pt-0">
                  <div
                    className={`flex items-center gap-2 text-sm px-3 py-2 rounded-md ${
                      testResults[webhook.id].success
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                        : 'bg-destructive/10 text-destructive'
                    }`}
                  >
                    {testResults[webhook.id].success ? (
                      <CheckCircle2 className="h-4 w-4" />
                    ) : (
                      <XCircle className="h-4 w-4" />
                    )}
                    {testResults[webhook.id].success
                      ? 'Test notification sent successfully'
                      : `Test failed: ${testResults[webhook.id].error}`}
                  </div>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingWebhook ? 'Edit Webhook' : 'Add Webhook'}
            </DialogTitle>
            <DialogDescription>
              {editingWebhook
                ? 'Update the webhook configuration. Leave the auth header blank to keep the existing value.'
                : 'Configure a new webhook endpoint to receive alert notifications.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="webhook-name">Name</Label>
              <Input
                id="webhook-name"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                placeholder="My Webhook"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="webhook-url">URL</Label>
              <Input
                id="webhook-url"
                value={formData.url}
                onChange={e => setFormData({ ...formData, url: e.target.value })}
                placeholder="https://api.example.com/webhook"
              />
              <p className="text-xs text-muted-foreground">
                Alert payloads will be sent as JSON via HTTP POST
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="webhook-auth">Authorization Header (optional)</Label>
              <Input
                id="webhook-auth"
                type="password"
                value={formData.auth_header}
                onChange={e => setFormData({ ...formData, auth_header: e.target.value })}
                placeholder={editingWebhook?.has_auth ? 'Enter new value to change' : 'Bearer token or API key'}
              />
              <p className="text-xs text-muted-foreground">
                Will be sent as the Authorization header value
                {editingWebhook?.has_auth && ' (leave blank to keep existing)'}
              </p>
            </div>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Enabled</Label>
                <p className="text-sm text-muted-foreground">
                  Receive notifications when enabled
                </p>
              </div>
              <Switch
                checked={formData.enabled}
                onCheckedChange={enabled => setFormData({ ...formData, enabled })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog} disabled={isSaving}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={isSaving}>
              {isSaving ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : editingWebhook ? (
                'Update'
              ) : (
                'Create'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <DeleteConfirmModal
        open={deleteModalOpen}
        onOpenChange={setDeleteModalOpen}
        title="Delete Webhook"
        description="Are you sure you want to delete this webhook? This action cannot be undone."
        itemName={webhookToDelete?.name}
        onConfirm={handleDelete}
        isDeleting={isDeleting}
      />
    </div>
  )
}
