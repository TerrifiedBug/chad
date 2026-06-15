import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi, authApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'

/**
 * Enterprise identity controls (I4): enforce org-wide MFA and break-glass
 * session revocation. Self-contained; admin only (mounted in Security settings).
 */
export function IdpSecurityCard() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [confirmOpen, setConfirmOpen] = useState(false)

  const { data } = useQuery({ queryKey: ['security-settings'], queryFn: () => settingsApi.getSecuritySettings() })

  const toggleMfa = useMutation({
    mutationFn: (enforce_mfa: boolean) => settingsApi.updateSecuritySettings({ ...data, enforce_mfa }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-settings'] })
      showToast('MFA enforcement updated', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to update', 'error'),
  })

  const revokeAll = useMutation({
    mutationFn: () => authApi.revokeAllSessions(),
    onSuccess: () => {
      setConfirmOpen(false)
      showToast('All sessions revoked — everyone must sign in again', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to revoke', 'error'),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Identity & Sessions</CardTitle>
        <CardDescription>Enforce multi-factor auth and revoke active sessions.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <Label>Enforce MFA</Label>
            <p className="text-xs text-muted-foreground">Local users without an authenticator must enrol before using CHAD.</p>
          </div>
          <Switch
            checked={!!data?.enforce_mfa}
            onCheckedChange={(v) => toggleMfa.mutate(v)}
            disabled={!data}
          />
        </div>
        <div className="flex items-center justify-between border-t pt-4">
          <div>
            <Label>Revoke all sessions</Label>
            <p className="text-xs text-muted-foreground">Break-glass: sign every user out (including you) immediately.</p>
          </div>
          <Button variant="destructive" onClick={() => setConfirmOpen(true)}>Revoke all</Button>
        </div>
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke all sessions?</DialogTitle>
            <DialogDescription>
              Every active session — including your own — will be invalidated and all users must sign in again. Use this if you suspect a token has been compromised.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={() => revokeAll.mutate()} disabled={revokeAll.isPending}>
              {revokeAll.isPending ? 'Revoking…' : 'Revoke all sessions'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
