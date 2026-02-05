import { useEffect, useState } from 'react'
import { usersApi, settingsApiExtended, UserInfo } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Check, Copy, KeyRound, Pencil, Plus, Trash2, X, Lock, Unlock, Loader2, Users } from 'lucide-react'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import { TimestampTooltip } from '@/components/timestamp-tooltip'
import { LoadingState } from '@/components/ui/loading-state'
import { EmptyState } from '@/components/ui/empty-state'
import { PageHeader } from '@/components/PageHeader'

// Password complexity validation
function validatePasswordComplexity(password: string) {
  return {
    minLength: password.length >= 12,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecial: /[!@#$%^&*()_+\-=[\]{}|;:',.<>?/`~]/.test(password),
  }
}

function PasswordRequirement({ met, text }: { met: boolean; text: string }) {
  return (
    <div className={`flex items-center gap-2 text-xs ${met ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'}`}>
      {met ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
      {text}
    </div>
  )
}

export default function UsersPage() {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [isCreating, setIsCreating] = useState(false)

  // New user form
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('analyst')
  const [createError, setCreateError] = useState('')

  // Edit user state
  const [editUser, setEditUser] = useState<UserInfo | null>(null)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [editRole, setEditRole] = useState('')
  const [editIsActive, setEditIsActive] = useState(true)
  const [editError, setEditError] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Password reset state
  const [isResettingPassword, setIsResettingPassword] = useState(false)
  const [tempPassword, setTempPassword] = useState('')
  const [passwordCopied, setPasswordCopied] = useState(false)

  // Delete confirmation state
  const [userToDelete, setUserToDelete] = useState<UserInfo | null>(null)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)

  // Password reset confirmation state
  const [isPasswordResetDialogOpen, setIsPasswordResetDialogOpen] = useState(false)

  // SSO role mapping state
  const [ssoRoleMappingEnabled, setSsoRoleMappingEnabled] = useState(true)

  // Lock status state
  const [lockStatuses, setLockStatuses] = useState<Record<string, {locked: boolean; remaining_minutes: number | null}>>({})
  const [isLoadingLockStatus, setIsLoadingLockStatus] = useState(false)

  // Password complexity
  const passwordComplexity = validatePasswordComplexity(newPassword)
  const allRequirementsMet = Object.values(passwordComplexity).every(Boolean)

  useEffect(() => {
    loadUsers()
    loadSsoSettings()
  }, [])

  useEffect(() => {
    const loadLockStatuses = async () => {
      if (users.length === 0) return

      setIsLoadingLockStatus(true)
      const statuses: typeof lockStatuses = {}

      for (const user of users) {
        if (user.auth_method === 'local') {
          try {
            const status = await usersApi.getLockStatus(user.email)
            statuses[user.email] = status
          } catch {
            // User doesn't exist or other error, skip
            statuses[user.email] = { locked: false, remaining_minutes: null }
          }
        }
      }

      setLockStatuses(statuses)
      setIsLoadingLockStatus(false)
    }

    loadLockStatuses()
  }, [users])

  const loadSsoSettings = async () => {
    try {
      const settings = await settingsApiExtended.getAll()
      if (settings.sso && typeof settings.sso === 'object') {
        const sso = settings.sso as Record<string, unknown>
        setSsoRoleMappingEnabled((sso.role_mapping_enabled as boolean) || false)
      } else {
        setSsoRoleMappingEnabled(false)
      }
    } catch {
      // Default to false if we can't load settings (allow role changes)
      setSsoRoleMappingEnabled(false)
    }
  }

  const loadUsers = async () => {
    try {
      const data = await usersApi.list()
      setUsers(data)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users')
    } finally {
      setIsLoading(false)
    }
  }

  const createUser = async () => {
    if (!newEmail || !newPassword) {
      setCreateError('Email and password are required')
      return
    }

    if (!allRequirementsMet) {
      setCreateError('Password does not meet all complexity requirements')
      return
    }

    setIsCreating(true)
    setCreateError('')

    try {
      await usersApi.create({
        email: newEmail,
        password: newPassword,
        role: newRole,
      })
      setIsDialogOpen(false)
      setNewEmail('')
      setNewPassword('')
      setNewRole('analyst')
      setCreateError('')
      loadUsers()
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create user')
    } finally {
      setIsCreating(false)
    }
  }

  const openDeleteDialog = (user: UserInfo) => {
    setUserToDelete(user)
    setIsDeleteDialogOpen(true)
  }

  const confirmDeleteUser = async () => {
    if (!userToDelete) return

    setIsDeleting(true)
    try {
      await usersApi.delete(userToDelete.id)
      setIsDeleteDialogOpen(false)
      setUserToDelete(null)
      loadUsers()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user')
    } finally {
      setIsDeleting(false)
    }
  }

  const openEditDialog = (user: UserInfo) => {
    setEditUser(user)
    setEditRole(user.role)
    setEditIsActive(user.is_active)
    setEditError('')
    setTempPassword('')
    setPasswordCopied(false)
    setIsEditDialogOpen(true)
  }

  const closeEditDialog = () => {
    setIsEditDialogOpen(false)
    setEditUser(null)
    setEditError('')
    setTempPassword('')
    setPasswordCopied(false)
  }

  const saveUserChanges = async () => {
    if (!editUser) return

    setIsSaving(true)
    setEditError('')

    try {
      await usersApi.update(editUser.id, {
        role: editRole,
        is_active: editIsActive,
      })
      closeEditDialog()
      loadUsers()
    } catch (err) {
      setEditError(err instanceof Error ? err.message : 'Failed to update user')
    } finally {
      setIsSaving(false)
    }
  }

  const confirmResetPassword = async () => {
    if (!editUser) return

    setIsResettingPassword(true)
    setEditError('')
    setIsPasswordResetDialogOpen(false)

    try {
      const response = await usersApi.resetPassword(editUser.id)
      setTempPassword(response.temporary_password)
      setPasswordCopied(false)
    } catch (err) {
      setEditError(err instanceof Error ? err.message : 'Failed to reset password')
    } finally {
      setIsResettingPassword(false)
    }
  }

  const copyTempPassword = async () => {
    try {
      await navigator.clipboard.writeText(tempPassword)
      setPasswordCopied(true)
      setTimeout(() => setPasswordCopied(false), 2000)
    } catch {
      // Fallback for older browsers
      const textArea = document.createElement('textarea')
      textArea.value = tempPassword
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
      setPasswordCopied(true)
      setTimeout(() => setPasswordCopied(false), 2000)
    }
  }

  const handleUnlockUser = async (userId: string, email: string) => {
    try {
      await usersApi.unlockUser(userId)

      // Refresh lock statuses
      const updatedStatus = await usersApi.getLockStatus(email)
      setLockStatuses(prev => ({
        ...prev,
        [email]: updatedStatus
      }))

      // Refresh the user list to get updated data
      loadUsers()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unlock user')
    }
  }

  const roleColors: Record<string, string> = {
    admin: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    analyst: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    viewer: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
  }

  return (
    <TooltipProvider>
      <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Manage user accounts"
        breadcrumb={[
          { label: 'Settings', href: '/settings/hub' },
          { label: 'Users' },
        ]}
        actions={
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" /> Add User
              </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create User</DialogTitle>
              <DialogDescription>
                The user will be required to change their password on first login.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              {createError && (
                <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
                  {createError}
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="user@example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter password"
                />
                <div className="space-y-1 pt-1">
                  <PasswordRequirement met={passwordComplexity.minLength} text="At least 12 characters" />
                  <PasswordRequirement met={passwordComplexity.hasUppercase} text="At least one uppercase letter" />
                  <PasswordRequirement met={passwordComplexity.hasLowercase} text="At least one lowercase letter" />
                  <PasswordRequirement met={passwordComplexity.hasNumber} text="At least one number" />
                  <PasswordRequirement met={passwordComplexity.hasSpecial} text="At least one special character (!@#$%^&*...)" />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="role">Role</Label>
                <Select value={newRole} onValueChange={setNewRole}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="z-50 bg-popover">
                    <SelectItem value="admin">Admin</SelectItem>
                    <SelectItem value="analyst">Analyst</SelectItem>
                    <SelectItem value="viewer">Viewer</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={createUser}
                className="w-full"
                disabled={isCreating || !allRequirementsMet || !newEmail}
              >
                {isCreating ? 'Creating...' : 'Create User'}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
        }
      />

      {error && (
        <div className="bg-destructive/10 text-destructive p-3 rounded-md">
          {error}
        </div>
      )}

      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Auth</TableHead>
              <TableHead>2FA</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Lock</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-[100px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8}>
                  <LoadingState message="Loading users..." />
                </TableCell>
              </TableRow>
            ) : users.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8}>
                  <EmptyState
                    icon={<Users className="h-12 w-12" />}
                    title="No users found"
                    description="Add users to grant access to CHAD."
                  />
                </TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.email}</TableCell>
                  <TableCell>
                    <Badge className={roleColors[user.role] || roleColors.viewer}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        user.auth_method === 'sso'
                          ? 'border-purple-300 text-purple-700 dark:border-purple-700 dark:text-purple-300'
                          : 'border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-300'
                      }
                    >
                      {user.auth_method === 'sso' ? 'SSO' : 'Local'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {user.auth_method === 'local' && (
                      <Badge
                        variant="outline"
                        className={
                          user.totp_enabled
                            ? 'border-green-300 text-green-700 dark:border-green-700 dark:text-green-300'
                            : 'border-gray-300 text-gray-500 dark:border-gray-600 dark:text-gray-400'
                        }
                      >
                        {user.totp_enabled ? 'Enabled' : 'Off'}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={user.is_active ? 'default' : 'secondary'}
                      className={
                        user.is_active
                          ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                          : ''
                      }
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {user.auth_method === 'local' ? (
                      isLoadingLockStatus ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : lockStatuses[user.email]?.locked ? (
                        <div className="flex items-center gap-1 text-orange-600">
                          <Lock className="h-4 w-4" />
                          <span className="text-xs">
                            {lockStatuses[user.email].remaining_minutes}m
                          </span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-green-600">
                          <Unlock className="h-4 w-4" />
                          <span className="text-xs">Open</span>
                        </div>
                      )
                    ) : (
                      <span className="text-muted-foreground text-xs">N/A</span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    <TimestampTooltip timestamp={user.created_at}>
                      <span>{new Date(user.created_at).toLocaleDateString()}</span>
                    </TimestampTooltip>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => openEditDialog(user)}
                        title="Edit user"
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => openDeleteDialog(user)}
                        className="text-destructive hover:text-destructive"
                        title="Delete user"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Edit User Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={(open) => !open && closeEditDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>
              {editUser?.email}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {editError && (
              <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
                {editError}
              </div>
            )}

            {/* Role Selection */}
            <div className="space-y-2">
              <Label htmlFor="edit-role">Role</Label>
              {editUser?.auth_method === 'sso' && ssoRoleMappingEnabled ? (
                <div className="space-y-1">
                  <Select value={editRole} disabled>
                    <SelectTrigger className="opacity-50 cursor-not-allowed">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="z-50 bg-popover">
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="analyst">Analyst</SelectItem>
                      <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Role is managed by SSO provider. Disable role mapping in Settings to allow manual changes.
                  </p>
                </div>
              ) : (
                <div className="space-y-1">
                  <Select value={editRole} onValueChange={setEditRole}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="z-50 bg-popover">
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="analyst">Analyst</SelectItem>
                      <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                  </Select>
                  {editUser?.auth_method === 'sso' && (
                    <p className="text-xs text-muted-foreground">
                      Role mapping is disabled. Role will persist until mapping is enabled.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Active Status */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="edit-active">Active Status</Label>
                <p className="text-xs text-muted-foreground">
                  Inactive users cannot log in
                </p>
              </div>
              <Switch
                id="edit-active"
                checked={editIsActive}
                onCheckedChange={setEditIsActive}
              />
            </div>

            {/* Account Lock Status - Show if locked */}
            {lockStatuses[editUser?.email || '']?.locked && (
              <div className="rounded-lg border border-orange-200 bg-orange-50 p-4 dark:border-orange-900 dark:bg-orange-950">
                <div className="flex items-start gap-2">
                  <Lock className="h-5 w-5 text-orange-600 mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <h4 className="text-sm font-medium text-orange-900 dark:text-orange-100">
                      Account Locked
                    </h4>
                    <p className="text-xs text-orange-700 dark:text-orange-300">
                      This account has been locked due to too many failed login attempts.
                      {lockStatuses[editUser?.email || ''].remaining_minutes !== null && (
                        <> Time remaining: {lockStatuses[editUser?.email || ''].remaining_minutes} minutes</>
                      )}
                    </p>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => handleUnlockUser(editUser!.id, editUser!.email)}
                      disabled={isSaving}
                    >
                      <Unlock className="h-4 w-4 mr-1" />
                      Unlock Account
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {/* Password Reset Section - Only for local users */}
            {editUser?.auth_method === 'local' && (
              <div className="border-t pt-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Password Reset</Label>
                    <p className="text-xs text-muted-foreground">
                      Generate a temporary password for this user
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsPasswordResetDialogOpen(true)}
                    disabled={isResettingPassword}
                  >
                    <KeyRound className="mr-2 h-4 w-4" />
                    {isResettingPassword ? 'Resetting...' : 'Reset Password'}
                  </Button>
                </div>

                {tempPassword && (
                  <div className="bg-muted rounded-md p-3 space-y-2">
                    <p className="text-sm font-medium">Temporary Password</p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 bg-background px-3 py-2 rounded text-sm font-mono border">
                        {tempPassword}
                      </code>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={copyTempPassword}
                        className="shrink-0"
                      >
                        {passwordCopied ? (
                          <Check className="h-4 w-4 text-green-600" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      The user will be required to change this password on next login.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* SSO Info */}
            {editUser?.auth_method === 'sso' && (
              <div className="border-t pt-4">
                <p className="text-sm text-muted-foreground">
                  This user authenticates via SSO. Password management is handled by the identity provider.
                </p>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={closeEditDialog}>
                Cancel
              </Button>
              <Button onClick={saveUserChanges} disabled={isSaving}>
                {isSaving ? 'Saving...' : 'Save Changes'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete User Confirmation Modal */}
      <DeleteConfirmModal
        open={isDeleteDialogOpen}
        onOpenChange={setIsDeleteDialogOpen}
        title="Delete User"
        description="Are you sure you want to delete this user? This action cannot be undone."
        itemName={userToDelete?.email}
        onConfirm={confirmDeleteUser}
        isDeleting={isDeleting}
      />

      {/* Password Reset Confirmation Dialog */}
      <Dialog open={isPasswordResetDialogOpen} onOpenChange={setIsPasswordResetDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset Password</DialogTitle>
            <DialogDescription>
              Are you sure you want to reset this user's password? A temporary password will be generated and the user will be required to change it on next login.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsPasswordResetDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={confirmResetPassword}>
              Reset Password
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </TooltipProvider>
  )
}
