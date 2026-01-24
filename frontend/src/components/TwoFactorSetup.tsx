import { useState } from 'react'
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
import { Loader2, Shield, Copy, Check, AlertTriangle } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { authApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'

interface TwoFactorSetupProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onComplete: () => void
}

type SetupStep = 'initial' | 'scan' | 'verify' | 'backup'

export function TwoFactorSetup({ open, onOpenChange, onComplete }: TwoFactorSetupProps) {
  const { showToast } = useToast()
  const [step, setStep] = useState<SetupStep>('initial')
  const [loading, setLoading] = useState(false)
  const [qrUri, setQrUri] = useState('')
  const [secret, setSecret] = useState('')
  const [code, setCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [copiedBackup, setCopiedBackup] = useState(false)

  const handleStartSetup = async () => {
    setLoading(true)
    try {
      const response = await authApi.setup2FA()
      setQrUri(response.qr_uri)
      setSecret(response.secret)
      setStep('scan')
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Failed to start 2FA setup', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async () => {
    if (code.length !== 6) return

    setLoading(true)
    try {
      const response = await authApi.verify2FA(code)
      setBackupCodes(response.backup_codes)
      setStep('backup')
    } catch {
      showToast('Invalid code. Please check your authenticator app and try again.', 'error')
    } finally {
      setLoading(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard.writeText(secret)
    setCopiedSecret(true)
    setTimeout(() => setCopiedSecret(false), 2000)
  }

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'))
    setCopiedBackup(true)
    setTimeout(() => setCopiedBackup(false), 2000)
  }

  const handleComplete = () => {
    setStep('initial')
    setCode('')
    setQrUri('')
    setSecret('')
    setBackupCodes([])
    onComplete()
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            {step === 'initial' && 'Enable Two-Factor Authentication'}
            {step === 'scan' && 'Scan QR Code'}
            {step === 'verify' && 'Enter Verification Code'}
            {step === 'backup' && 'Save Backup Codes'}
          </DialogTitle>
          <DialogDescription>
            {step === 'initial' && 'Add an extra layer of security to your account.'}
            {step === 'scan' && 'Scan this QR code with your authenticator app.'}
            {step === 'verify' && 'Enter the 6-digit code from your authenticator app.'}
            {step === 'backup' && 'Save these codes somewhere safe. Each can be used once if you lose access to your authenticator.'}
          </DialogDescription>
        </DialogHeader>

        {step === 'initial' && (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Two-factor authentication adds an extra layer of security by requiring a code from your phone in addition to your password.
            </p>
            <p className="text-sm text-muted-foreground">
              You'll need an authenticator app like Google Authenticator, Authy, or 1Password.
            </p>
          </div>
        )}

        {step === 'scan' && (
          <div className="space-y-4">
            <div className="flex justify-center p-4 bg-white rounded-lg">
              <QRCodeSVG value={qrUri} size={200} />
            </div>
            <div className="space-y-2">
              <Label>Can't scan? Enter this code manually:</Label>
              <div className="flex gap-2">
                <code className="flex-1 p-2 bg-muted rounded text-xs break-all">
                  {secret}
                </code>
                <Button variant="outline" size="sm" onClick={copySecret}>
                  {copiedSecret ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <Button className="w-full" onClick={() => setStep('verify')}>
              Continue
            </Button>
          </div>
        )}

        {step === 'verify' && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="code">Verification Code</Label>
              <Input
                id="code"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                className="text-center text-2xl tracking-widest"
                autoFocus
              />
            </div>
          </div>
        )}

        {step === 'backup' && (
          <div className="space-y-4">
            <div className="flex gap-3 p-4 rounded-lg border border-yellow-500/50 bg-yellow-500/10">
              <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-sm">Important!</p>
                <p className="text-sm text-muted-foreground">
                  These backup codes can be used to access your account if you lose your authenticator. Each code can only be used once. Save them somewhere safe!
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 p-4 bg-muted rounded-lg font-mono text-sm">
              {backupCodes.map((code, i) => (
                <div key={i} className="text-center">{code}</div>
              ))}
            </div>
            <Button variant="outline" className="w-full" onClick={copyBackupCodes}>
              {copiedBackup ? (
                <>
                  <Check className="h-4 w-4 mr-2" /> Copied!
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4 mr-2" /> Copy All Codes
                </>
              )}
            </Button>
          </div>
        )}

        <DialogFooter>
          {step === 'initial' && (
            <Button onClick={handleStartSetup} disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Get Started
            </Button>
          )}
          {step === 'verify' && (
            <Button onClick={handleVerify} disabled={loading || code.length !== 6}>
              {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Verify
            </Button>
          )}
          {step === 'backup' && (
            <Button onClick={handleComplete}>
              I've Saved My Backup Codes
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
