import { useState } from 'react'
import { useAuth } from '@/hooks/use-auth'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Shield, ShieldCheck, ShieldOff, User, Loader2 } from 'lucide-react'
import { TwoFactorSetup } from '@/components/TwoFactorSetup'
import { authApi } from '@/lib/api'
import { useToast } from '@/hooks/use-toast'

export default function AccountPage() {
  const { user, refreshUser } = useAuth()
  const { toast } = useToast()
  const [showSetup, setShowSetup] = useState(false)
  const [showDisable, setShowDisable] = useState(false)
  const [disableCode, setDisableCode] = useState('')
  const [disabling, setDisabling] = useState(false)

  const handle2FAComplete = async () => {
    await refreshUser()
    toast({
      title: 'Two-Factor Authentication Enabled',
      description: 'Your account is now protected with 2FA.',
    })
  }

  const handleDisable2FA = async () => {
    if (disableCode.length !== 6 && disableCode.length !== 8) return

    setDisabling(true)
    try {
      await authApi.disable2FA(disableCode)
      await refreshUser()
      setShowDisable(false)
      setDisableCode('')
      toast({
        title: 'Two-Factor Authentication Disabled',
        description: '2FA has been removed from your account.',
      })
    } catch {
      toast({
        title: 'Failed to Disable 2FA',
        description: 'Invalid code. Please try again.',
        variant: 'destructive',
      })
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
        <Card>
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
