import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { settingsApiExtended } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Save, Users } from 'lucide-react'

export default function SettingsPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Webhook settings
  const [webhookUrl, setWebhookUrl] = useState('')
  const [webhookEnabled, setWebhookEnabled] = useState(false)

  // Session settings
  const [sessionTimeout, setSessionTimeout] = useState(480)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const settings = await settingsApiExtended.getAll()

      // Webhook
      if (settings.webhooks && typeof settings.webhooks === 'object') {
        const webhooks = settings.webhooks as Record<string, unknown>
        setWebhookUrl((webhooks.global_url as string) || '')
        setWebhookEnabled((webhooks.enabled as boolean) || false)
      }

      // Session
      if (settings.session && typeof settings.session === 'object') {
        const session = settings.session as Record<string, unknown>
        setSessionTimeout((session.timeout_minutes as number) || 480)
      }
    } catch (err) {
      // Settings may not exist yet, that's okay
      console.log('No settings found, using defaults')
    } finally {
      setIsLoading(false)
    }
  }

  const saveWebhooks = async () => {
    setIsSaving(true)
    setError('')
    setSuccess('')
    try {
      await settingsApiExtended.update('webhooks', {
        enabled: webhookEnabled,
        global_url: webhookUrl,
      })
      setSuccess('Webhook settings saved')
      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const saveSession = async () => {
    setIsSaving(true)
    setError('')
    setSuccess('')
    try {
      await settingsApiExtended.update('session', {
        timeout_minutes: sessionTimeout,
      })
      setSuccess('Session settings saved')
      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">Loading...</div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Configure your CHAD installation</p>
        </div>
        <Button variant="outline" asChild>
          <Link to="/settings/users">
            <Users className="mr-2 h-4 w-4" /> Manage Users
          </Link>
        </Button>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive p-3 rounded-md">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 p-3 rounded-md">
          {success}
        </div>
      )}

      <Tabs defaultValue="webhooks">
        <TabsList>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="session">Session</TabsTrigger>
          <TabsTrigger value="opensearch">OpenSearch</TabsTrigger>
        </TabsList>

        <TabsContent value="webhooks" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Webhook Notifications</CardTitle>
              <CardDescription>
                Configure webhook endpoints for alert notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label>Enable Webhooks</Label>
                  <p className="text-sm text-muted-foreground">
                    Send notifications when alerts are created
                  </p>
                </div>
                <Switch
                  checked={webhookEnabled}
                  onCheckedChange={setWebhookEnabled}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="webhook-url">Webhook URL</Label>
                <Input
                  id="webhook-url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://hooks.example.com/alerts"
                  disabled={!webhookEnabled}
                />
              </div>
              <Button onClick={saveWebhooks} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="session" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Session Settings</CardTitle>
              <CardDescription>
                Configure authentication and session behavior
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                <Input
                  id="session-timeout"
                  type="number"
                  value={sessionTimeout}
                  onChange={(e) =>
                    setSessionTimeout(parseInt(e.target.value) || 480)
                  }
                  min={15}
                  max={10080}
                />
                <p className="text-sm text-muted-foreground">
                  How long until users are logged out due to inactivity (15 min -
                  7 days)
                </p>
              </div>
              <Button onClick={saveSession} disabled={isSaving}>
                <Save className="mr-2 h-4 w-4" />
                {isSaving ? 'Saving...' : 'Save'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="opensearch" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>OpenSearch Connection</CardTitle>
              <CardDescription>
                Manage your OpenSearch cluster connection
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                OpenSearch connection is configured during initial setup. To
                reconfigure, use the OpenSearch wizard.
              </p>
              <Button variant="outline" asChild>
                <Link to="/opensearch-wizard">Reconfigure OpenSearch</Link>
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
