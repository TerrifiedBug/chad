import { useEffect, useState } from 'react'
import { geoipApi, GeoIPSettings as GeoIPSettingsType } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Check, Download, Globe, Loader2 } from 'lucide-react'

export default function GeoIPSettings() {
  const { showToast } = useToast()
  const [settings, setSettings] = useState<GeoIPSettingsType | null>(null)
  const [licenseKey, setLicenseKey] = useState('')
  const [testIp, setTestIp] = useState('8.8.8.8')
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null)
  const [isDownloading, setIsDownloading] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const data = await geoipApi.getSettings()
      setSettings(data)
    } catch (err) {
      console.log('Failed to load GeoIP settings')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      const updates: { license_key?: string } = {}
      if (licenseKey) updates.license_key = licenseKey
      await geoipApi.updateSettings(updates)
      setLicenseKey('')
      showToast('License key saved')
      loadSettings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  const handleToggle = async (enabled: boolean) => {
    try {
      await geoipApi.updateSettings({ enabled })
      showToast(enabled ? 'GeoIP enrichment enabled' : 'GeoIP enrichment disabled')
      loadSettings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Update failed', 'error')
    }
  }

  const handleUpdateInterval = async (interval: string) => {
    try {
      await geoipApi.updateSettings({ update_interval: interval })
      showToast('Update interval saved')
      loadSettings()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Update failed', 'error')
    }
  }

  const handleDownload = async () => {
    setIsDownloading(true)
    try {
      const result = await geoipApi.downloadDatabase()
      if (result.success) {
        showToast('GeoIP database downloaded successfully')
        loadSettings()
      } else {
        showToast(result.error || 'Download failed', 'error')
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Download failed', 'error')
    } finally {
      setIsDownloading(false)
    }
  }

  const handleTest = async () => {
    try {
      const result = await geoipApi.testLookup(testIp)
      setTestResult(result as unknown as Record<string, unknown>)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Test failed', 'error')
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="text-center text-muted-foreground py-8">
        Failed to load GeoIP settings
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            GeoIP Enrichment
          </CardTitle>
          <CardDescription>
            Enrich alerts with geographic information for public IP addresses using MaxMind GeoLite2.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Switch
              checked={settings.enabled}
              onCheckedChange={handleToggle}
              disabled={!settings.database_available}
            />
            <Label>Enable GeoIP Enrichment</Label>
            {!settings.database_available && (
              <span className="text-xs text-muted-foreground">
                (Download database first)
              </span>
            )}
          </div>

          <div className="space-y-2">
            <Label>MaxMind License Key</Label>
            <div className="flex gap-2">
              <Input
                type="password"
                value={licenseKey}
                onChange={e => setLicenseKey(e.target.value)}
                placeholder={settings.has_license_key ? '********' : 'Enter license key'}
                className="max-w-md"
              />
              <Button onClick={handleSave} disabled={!licenseKey || isSaving}>
                {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Get a free license key from{' '}
              <a
                href="https://www.maxmind.com/en/geolite2/signup"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-foreground"
              >
                MaxMind
              </a>
            </p>
          </div>

          <div className="space-y-2">
            <Label>Update Interval</Label>
            <Select value={settings.update_interval} onValueChange={handleUpdateInterval}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="z-50 bg-popover">
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              How often to automatically update the GeoIP database
            </p>
          </div>

          <div className="border-t pt-4 mt-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium">Database Status</h4>
                {settings.database_available && settings.database_info ? (
                  <p className="text-sm text-muted-foreground">
                    <Check className="inline h-4 w-4 text-green-500 mr-1" />
                    Available ({settings.database_info.size_mb.toFixed(1)} MB)
                    <br />
                    <span className="text-xs">
                      Last updated: {new Date(settings.database_info.modified_at).toLocaleString()}
                    </span>
                  </p>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Database not downloaded
                  </p>
                )}
              </div>
              <Button
                onClick={handleDownload}
                disabled={!settings.has_license_key || isDownloading}
              >
                {isDownloading ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Download className="h-4 w-4 mr-2" />
                )}
                {settings.database_available ? 'Update Database' : 'Download Database'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {settings.database_available && (
        <Card>
          <CardHeader>
            <CardTitle>Test Lookup</CardTitle>
            <CardDescription>
              Test the GeoIP database by looking up an IP address
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                value={testIp}
                onChange={e => setTestIp(e.target.value)}
                placeholder="Enter IP address"
                className="max-w-xs"
              />
              <Button onClick={handleTest} variant="outline">
                Test
              </Button>
            </div>
            {testResult && (
              <pre className="text-xs bg-muted p-4 rounded overflow-auto max-h-64">
                {JSON.stringify(testResult, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
