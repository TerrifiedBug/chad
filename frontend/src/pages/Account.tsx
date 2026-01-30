import { useState, useEffect } from 'react'
import { useAuth } from '@/hooks/use-auth'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Shield, ShieldCheck, ShieldOff, User, Loader2, Bell } from 'lucide-react'
import { TwoFactorSetup } from '@/components/TwoFactorSetup'
import { authApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'

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
    <div className="container max-w-2xl py-8">
      <h1 className="text-3xl font-bold mb-8">Account Settings</h1>

      {/* Profile Info */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-muted-foreground">Email</Label>
            <p className="font-medium">{user.email}</p>
          </div>
          <div>
            <Label className="text-muted-foreground">Role</Label>
            <p className="font-medium capitalize">{user.role}</p>
          </div>
          <div>
            <Label className="text-muted-foreground">Authentication Method</Label>
            <p className="font-medium">{user.auth_method === 'sso' ? 'Single Sign-On (SSO)' : 'Local Account'}</p>
          </div>
        </CardContent>
      </Card>

      {/* Security - 2FA */}
      {user.auth_method === 'local' && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Security
            </CardTitle>
            <CardDescription>
              Manage your account security settings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {user.totp_enabled ? (
                  <ShieldCheck className="h-8 w-8 text-green-500" />
                ) : (
                  <ShieldOff className="h-8 w-8 text-muted-foreground" />
                )}
                <div>
                  <p className="font-medium">Two-Factor Authentication</p>
                  <p className="text-sm text-muted-foreground">
                    {user.totp_enabled
                      ? 'Your account is protected with 2FA'
                      : 'Add an extra layer of security to your account'}
                  </p>
                </div>
              </div>
              {user.totp_enabled ? (
                <Button variant="outline" onClick={() => setShowDisable(true)}>
                  Disable 2FA
                </Button>
              ) : (
                <Button onClick={() => setShowSetup(true)}>
                  Enable 2FA
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Browser Notifications */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Browser Notifications
          </CardTitle>
          <CardDescription>
            Receive desktop notifications when new alerts are triggered
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Enable Notifications</p>
              <p className="text-sm text-muted-foreground">
                {notificationPermission === 'denied'
                  ? 'Notifications are blocked. Please enable in browser settings.'
                  : 'Get notified when alerts match the selected severities'}
              </p>
            </div>
            <Switch
              checked={notificationsEnabled}
              onCheckedChange={handleNotificationToggle}
              disabled={savingNotifications || notificationPermission === 'denied'}
            />
          </div>

          {notificationsEnabled && (
            <div className="space-y-3">
              <Label>Notify for severities:</Label>
              <div className="space-y-2">
                {SEVERITY_OPTIONS.map((severity) => (
                  <div key={severity.value} className="flex items-center space-x-3">
                    <Checkbox
                      id={`severity-${severity.value}`}
                      checked={notificationSeverities.includes(severity.value)}
                      onCheckedChange={() => handleSeverityToggle(severity.value)}
                      disabled={savingNotifications}
                    />
                    <label
                      htmlFor={`severity-${severity.value}`}
                      className="flex items-center gap-2 text-sm font-medium cursor-pointer"
                    >
                      <span className={`w-2 h-2 rounded-full ${severity.color}`} />
                      {severity.label}
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}
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
