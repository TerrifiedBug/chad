import { useState, useEffect } from 'react'
import { useAuth } from '@/hooks/use-auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Shield, ShieldCheck, ShieldOff, User, Loader2, Bell, Sun, Moon, Monitor, Palette } from 'lucide-react'
import { TwoFactorSetup } from '@/components/TwoFactorSetup'
import { authApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { useTheme } from '@/hooks/use-theme'
import { PageHeader } from '@/components/PageHeader'

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical', color: 'bg-red-500' },
  { value: 'high', label: 'High', color: 'bg-orange-500' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { value: 'low', label: 'Low', color: 'bg-blue-500' },
  { value: 'informational', label: 'Informational', color: 'bg-gray-500' },
]

export default function AccountPage() {
  const { user, refreshUser } = useAuth()
  const { showToast } = useToast()
  const { theme, setTheme, palette, setPalette } = useTheme()
  const [showSetup, setShowSetup] = useState(false)
  const [showDisable, setShowDisable] = useState(false)
  const [disableCode, setDisableCode] = useState('')
  const [disabling, setDisabling] = useState(false)

  // Notification preferences
  const [notificationsEnabled, setNotificationsEnabled] = useState(false)
  const [notificationSeverities, setNotificationSeverities] = useState<string[]>([])
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>('default')
  const [savingNotifications, setSavingNotifications] = useState(false)

  // Initialize notification state from user preferences
  useEffect(() => {
    if (user?.notification_preferences) {
      setNotificationsEnabled(user.notification_preferences.browser_notifications)
      setNotificationSeverities(user.notification_preferences.severities)
    }
    // Check browser notification permission
    if ('Notification' in window) {
      setNotificationPermission(Notification.permission)
    }
  }, [user])

  const requestNotificationPermission = async () => {
    if (!('Notification' in window)) {
      showToast('Browser notifications are not supported', 'error')
      return false
    }
    const permission = await Notification.requestPermission()
    setNotificationPermission(permission)
    return permission === 'granted'
  }

  const handleNotificationToggle = async (enabled: boolean) => {
    if (enabled && notificationPermission !== 'granted') {
      const granted = await requestNotificationPermission()
      if (!granted) {
        showToast('Browser notification permission denied', 'error')
        return
      }
    }

    setSavingNotifications(true)
    try {
      await authApi.updateNotificationPreferences({ browser_notifications: enabled })
      setNotificationsEnabled(enabled)
      await refreshUser()
      showToast(enabled ? 'Browser notifications enabled' : 'Browser notifications disabled', 'success')
    } catch {
      showToast('Failed to update notification preferences', 'error')
    } finally {
      setSavingNotifications(false)
    }
  }

  const handleSeverityToggle = async (severity: string) => {
    const oldSeverities = notificationSeverities
    const newSeverities = notificationSeverities.includes(severity)
      ? notificationSeverities.filter(s => s !== severity)
      : [...notificationSeverities, severity]

    // Optimistic update - set state immediately
    setNotificationSeverities(newSeverities)
    setSavingNotifications(true)
    try {
      await authApi.updateNotificationPreferences({ severities: newSeverities })
      await refreshUser()
    } catch {
      // Revert on failure
      setNotificationSeverities(oldSeverities)
      showToast('Failed to update notification preferences', 'error')
    } finally {
      setSavingNotifications(false)
    }
  }

  const handle2FAComplete = async () => {
    await refreshUser()
    showToast('Two-Factor Authentication enabled', 'success')
  }

  const handleDisable2FA = async () => {
    if (disableCode.length !== 6 && disableCode.length !== 8) return

    setDisabling(true)
    try {
      await authApi.disable2FA(disableCode)
      await refreshUser()
      setShowDisable(false)
      setDisableCode('')
      showToast('Two-Factor Authentication disabled', 'success')
    } catch {
      showToast('Invalid code. Please try again.', 'error')
    } finally {
      setDisabling(false)
    }
  }

  if (!user) return null

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="Account"
        description="Manage your profile, security, and preferences"
      />

      {/* Profile Section - Compact inline display */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <div className="p-1.5 bg-primary/10 rounded-md">
              <User className="h-4 w-4 text-primary" />
            </div>
            Profile
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <p className="text-xs text-muted-foreground mb-1">Email</p>
              <p className="text-sm font-medium truncate">{user.email}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Role</p>
              <p className="text-sm font-medium capitalize">{user.role}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Auth Method</p>
              <p className="text-sm font-medium">{user.auth_method === 'sso' ? 'SSO' : 'Local'}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security - 2FA */}
      {user.auth_method === 'local' && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <div className="p-1.5 bg-primary/10 rounded-md">
                <Shield className="h-4 w-4 text-primary" />
              </div>
              Security
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {user.totp_enabled ? (
                  <ShieldCheck className="h-5 w-5 text-green-500 flex-shrink-0" />
                ) : (
                  <ShieldOff className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                )}
                <div>
                  <p className="text-sm font-medium">Two-Factor Authentication</p>
                  <p className="text-xs text-muted-foreground">
                    {user.totp_enabled
                      ? 'Your account is protected with 2FA'
                      : 'Add an extra layer of security'}
                  </p>
                </div>
              </div>
              {user.totp_enabled ? (
                <Button variant="outline" size="sm" onClick={() => setShowDisable(true)}>
                  Disable
                </Button>
              ) : (
                <Button size="sm" onClick={() => setShowSetup(true)}>
                  Enable
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Browser Notifications */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <div className="p-1.5 bg-primary/10 rounded-md">
              <Bell className="h-4 w-4 text-primary" />
            </div>
            Browser Notifications
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Enable Notifications</p>
              <p className="text-xs text-muted-foreground">
                {notificationPermission === 'denied'
                  ? 'Notifications are blocked in browser settings'
                  : 'Get notified when alerts match selected severities'}
              </p>
            </div>
            <Switch
              checked={notificationsEnabled}
              onCheckedChange={handleNotificationToggle}
              disabled={savingNotifications || notificationPermission === 'denied'}
            />
          </div>

          {notificationsEnabled && (
            <div className="pt-2 border-t">
              <p className="text-xs text-muted-foreground mb-3">Notify for severities:</p>
              <div className="flex flex-wrap gap-2">
                {SEVERITY_OPTIONS.map((severity) => (
                  <label
                    key={severity.value}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-md border cursor-pointer hover:bg-muted/50 transition-colors text-sm"
                  >
                    <Checkbox
                      id={`severity-${severity.value}`}
                      checked={notificationSeverities.includes(severity.value)}
                      onCheckedChange={() => handleSeverityToggle(severity.value)}
                      disabled={savingNotifications}
                      className="h-3.5 w-3.5"
                    />
                    <span className={`w-2 h-2 rounded-full ${severity.color}`} />
                    {severity.label}
                  </label>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <div className="p-1.5 bg-primary/10 rounded-md">
              <Sun className="h-4 w-4 text-primary" />
            </div>
            Appearance
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Theme</p>
              <p className="text-xs text-muted-foreground">Select your preferred theme</p>
            </div>
            <div className="flex gap-1 p-1 bg-muted rounded-lg">
              <Button
                variant={theme === 'light' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setTheme('light')}
                className="h-8 px-3"
              >
                <Sun className="h-4 w-4" />
              </Button>
              <Button
                variant={theme === 'dark' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setTheme('dark')}
                className="h-8 px-3"
              >
                <Moon className="h-4 w-4" />
              </Button>
              <Button
                variant={theme === 'system' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setTheme('system')}
                className="h-8 px-3"
              >
                <Monitor className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 border-t">
            <div>
              <p className="text-sm font-medium flex items-center gap-2">
                <Palette className="h-4 w-4" />
                Color Palette
              </p>
              <p className="text-xs text-muted-foreground">
                {palette === 'sentinel'
                  ? 'Security-focused blue palette'
                  : 'Neutral dark/light contrast'}
              </p>
            </div>
            <div className="flex gap-1 p-1 bg-muted rounded-lg">
              <Button
                variant={palette === 'sentinel' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setPalette('sentinel')}
                className="h-8 px-3 gap-2"
              >
                <span className="w-3 h-3 rounded-full bg-blue-500" />
                Sentinel
              </Button>
              <Button
                variant={palette === 'classic' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setPalette('classic')}
                className="h-8 px-3 gap-2"
              >
                <span className="w-3 h-3 rounded-full bg-slate-900 dark:bg-slate-100" />
                Classic
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 2FA Setup Dialog */}
      <TwoFactorSetup
        open={showSetup}
        onOpenChange={setShowSetup}
        onComplete={handle2FAComplete}
      />

      {/* Disable 2FA Dialog */}
      <Dialog open={showDisable} onOpenChange={setShowDisable}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication</DialogTitle>
            <DialogDescription>
              Enter your authenticator code or a backup code to confirm.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="disable-code">Verification Code</Label>
              <Input
                id="disable-code"
                type="text"
                inputMode="numeric"
                maxLength={8}
                placeholder="000000"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value.replace(/[^a-zA-Z0-9]/g, '').toUpperCase())}
                className="text-center text-2xl tracking-widest"
                autoComplete="one-time-code"
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Enter a 6-digit authenticator code or an 8-character backup code
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDisable(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDisable2FA}
              disabled={disabling || (disableCode.length !== 6 && disableCode.length !== 8)}
            >
              {disabling && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Disable 2FA
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
