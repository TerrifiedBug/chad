import { useCallback, useEffect, useState } from 'react'
import {
  ssoApi,
  scimApi,
  teamsApi,
  type SsoProvider,
  type SsoProviderInput,
  type SsoGroupMapping,
  type SsoTokenAuthMethod,
  type Team,
} from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  Save,
  Trash2,
  XCircle,
} from 'lucide-react'

const ROLE_OPTIONS = ['admin', 'analyst', 'viewer'] as const

// Sentinel for "no team" in the mapping table Select (Radix disallows empty value).
const NO_TEAM = '__none__'

function emptyProviderInput(): SsoProviderInput {
  return {
    name: '',
    enabled: true,
    issuer_url: '',
    client_id: '',
    client_secret: '',
    token_auth_method: 'client_secret_post',
    scopes: 'openid email profile',
    default_role: 'analyst',
    default_team_id: null,
    require_email_verified: true,
    group_sync_enabled: false,
    groups_claim: 'groups',
    groups_scope: '',
    role_claim: '',
    group_mappings: [],
  }
}

function issuerHost(issuerUrl: string): string {
  try {
    return new URL(issuerUrl).host
  } catch {
    return issuerUrl
  }
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export default function SsoSettings() {
  const { showToast } = useToast()
  const { isAdmin, hasPermission } = useAuth()
  const canManage = isAdmin || hasPermission('manage_settings')
  const [providers, setProviders] = useState<SsoProvider[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [ssoEnforced, setSsoEnforced] = useState(false)

  // Provider editor dialog state
  const [editorOpen, setEditorOpen] = useState(false)
  const [editingProvider, setEditingProvider] = useState<SsoProvider | null>(null)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [providerList, teamList] = await Promise.all([
        ssoApi.listProviders(),
        teamsApi.list().catch(() => [] as Team[]),
      ])
      setProviders(providerList)
      setTeams(teamList)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load SSO providers', 'error')
    }
    // Enforcement flag is independent — don't fail the whole page if it 404s.
    try {
      const enforcement = await ssoApi.getEnforcement()
      setSsoEnforced(enforcement.sso_enforced)
    } catch {
      // older backend: leave default
    }
    setLoading(false)
  }, [showToast])

  useEffect(() => {
    if (canManage) loadAll()
    else setLoading(false)
  }, [loadAll, canManage])

  const handleDelete = async (provider: SsoProvider) => {
    if (!window.confirm(`Delete provider "${provider.name}"? This cannot be undone.`)) return
    try {
      await ssoApi.deleteProvider(provider.id)
      showToast('Provider deleted')
      loadAll()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Delete failed', 'error')
    }
  }

  const handleEnforcementToggle = async (next: boolean) => {
    setSsoEnforced(next)
    try {
      await ssoApi.updateEnforcement(next)
      showToast(next ? 'SSO enforcement enabled' : 'SSO enforcement disabled')
    } catch (err) {
      setSsoEnforced(!next)
      showToast(err instanceof Error ? err.message : 'Failed to update enforcement', 'error')
    }
  }

  if (!canManage) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-muted-foreground">
          You do not have permission to manage SSO settings.
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Providers list */}
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle>Identity Providers</CardTitle>
            <CardDescription>
              OIDC providers users can sign in with. Add one per identity provider (e.g. Okta, Microsoft Entra, Google).
            </CardDescription>
          </div>
          <Button
            onClick={() => {
              setEditingProvider(null)
              setEditorOpen(true)
            }}
          >
            <Plus className="mr-2 h-4 w-4" />
            Add Provider
          </Button>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-10 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
            </div>
          ) : providers.length === 0 ? (
            <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
              <KeyRound className="mx-auto mb-3 h-8 w-8 opacity-50" />
              No identity providers configured yet. Add one to enable SSO login.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Issuer</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {providers.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell className="font-medium">{provider.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {issuerHost(provider.issuer_url)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={provider.enabled ? 'success' : 'outline'}>
                        {provider.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Edit ${provider.name}`}
                          onClick={() => {
                            setEditingProvider(provider)
                            setEditorOpen(true)
                          }}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Delete ${provider.name}`}
                          onClick={() => handleDelete(provider)}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* SSO Enforcement */}
      <Card>
        <CardHeader>
          <CardTitle>SSO Enforcement</CardTitle>
          <CardDescription>
            Control whether local password login is allowed alongside SSO.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <Label>Require SSO for all logins</Label>
              <p className="text-sm text-muted-foreground">
                Hides the password form on the login page. Ensure at least one provider is enabled and
                tested before turning this on, or admins may be locked out.
              </p>
            </div>
            <Switch
              checked={ssoEnforced}
              onCheckedChange={handleEnforcementToggle}
              aria-label="Require SSO for all logins"
            />
          </div>
        </CardContent>
      </Card>

      {/* SCIM provisioning panel */}
      <ScimPanel />

      {/* Provider editor dialog */}
      {editorOpen && (
        <ProviderEditorDialog
          open={editorOpen}
          onOpenChange={setEditorOpen}
          provider={editingProvider}
          teams={teams}
          onSaved={() => {
            setEditorOpen(false)
            loadAll()
          }}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Provider editor dialog
// ---------------------------------------------------------------------------

function ProviderEditorDialog({
  open,
  onOpenChange,
  provider,
  teams,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  provider: SsoProvider | null
  teams: Team[]
  onSaved: () => void
}) {
  const { showToast } = useToast()
  const isEdit = provider !== null

  const [form, setForm] = useState<SsoProviderInput>(() =>
    provider
      ? {
          name: provider.name,
          enabled: provider.enabled,
          issuer_url: provider.issuer_url,
          client_id: provider.client_id,
          client_secret: '',
          token_auth_method: provider.token_auth_method,
          scopes: provider.scopes,
          default_role: provider.default_role,
          default_team_id: provider.default_team_id,
          require_email_verified: provider.require_email_verified,
          group_sync_enabled: provider.group_sync_enabled,
          groups_claim: provider.groups_claim || 'groups',
          groups_scope: provider.groups_scope || '',
          role_claim: provider.role_claim || '',
          // Mappings are embedded on the provider — seed the editor from them.
          group_mappings: provider.group_mappings ?? [],
        }
      : emptyProviderInput()
  )
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; error?: string | null } | null>(
    null
  )

  // Group mappings live inside the provider payload (form.group_mappings).
  const mappings = form.group_mappings

  const update = <K extends keyof SsoProviderInput>(key: K, value: SsoProviderInput[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  const handleTest = async () => {
    if (!provider) return
    setTesting(true)
    setTestResult(null)
    try {
      const result = await ssoApi.testConnection(provider.id)
      setTestResult(result)
    } catch (err) {
      setTestResult({ success: false, error: err instanceof Error ? err.message : 'Test failed' })
    } finally {
      setTesting(false)
    }
  }

  const setMappings = (
    updater: (prev: SsoGroupMapping[]) => SsoGroupMapping[]
  ) => setForm((prev) => ({ ...prev, group_mappings: updater(prev.group_mappings) }))

  const addMappingRow = () =>
    setMappings((prev) => [...prev, { group_value: '', team_id: null, role: 'viewer' }])

  const updateMapping = (index: number, patch: Partial<SsoGroupMapping>) =>
    setMappings((prev) => prev.map((m, i) => (i === index ? { ...m, ...patch } : m)))

  const removeMapping = (index: number) =>
    setMappings((prev) => prev.filter((_, i) => i !== index))

  const handleSave = async () => {
    setSaving(true)
    try {
      // Omit client_secret when blank so the stored secret is preserved. Group
      // mappings are embedded in the payload (replaced on save).
      const payload: SsoProviderInput = { ...form }
      if (!payload.client_secret) {
        delete payload.client_secret
      }

      if (provider) {
        await ssoApi.updateProvider(provider.id, payload)
      } else {
        await ssoApi.createProvider(payload)
      }

      showToast(isEdit ? 'Provider updated' : 'Provider created')
      onSaved()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Save failed', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit Provider' : 'Add Provider'}</DialogTitle>
          <DialogDescription>
            Configure an OIDC identity provider for SSO login.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="flex items-center justify-between">
            <div>
              <Label>Enabled</Label>
              <p className="text-sm text-muted-foreground">
                Shown as a login button when enabled.
              </p>
            </div>
            <Switch
              checked={form.enabled}
              onCheckedChange={(v) => update('enabled', v)}
              aria-label="Provider enabled"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="provider-name">Display Name</Label>
            <Input
              id="provider-name"
              value={form.name}
              onChange={(e) => update('name', e.target.value)}
              placeholder="Microsoft Entra"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="provider-issuer">Issuer URL</Label>
            <Input
              id="provider-issuer"
              value={form.issuer_url}
              onChange={(e) => update('issuer_url', e.target.value)}
              placeholder="https://login.microsoftonline.com/tenant-id/v2.0"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="provider-client-id">Client ID</Label>
            <Input
              id="provider-client-id"
              value={form.client_id}
              onChange={(e) => update('client_id', e.target.value)}
              placeholder="your-client-id"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="provider-client-secret">Client Secret</Label>
            <Input
              id="provider-client-secret"
              type="password"
              value={form.client_secret ?? ''}
              onChange={(e) => update('client_secret', e.target.value)}
              placeholder={
                provider?.client_secret_set ? 'Leave blank to keep existing secret' : 'Enter client secret'
              }
            />
            <p className="text-xs text-muted-foreground">
              Write-only. The stored secret is never shown.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Token Auth Method</Label>
              <Select
                value={form.token_auth_method}
                onValueChange={(v) => update('token_auth_method', v as SsoTokenAuthMethod)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  <SelectItem value="client_secret_post">POST Body (Most Common)</SelectItem>
                  <SelectItem value="client_secret_basic">HTTP Basic Auth</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Default Role</Label>
              <Select value={form.default_role} onValueChange={(v) => update('default_role', v)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  {ROLE_OPTIONS.map((role) => (
                    <SelectItem key={role} value={role} className="capitalize">
                      {role}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="provider-scopes">OAuth Scopes</Label>
            <Input
              id="provider-scopes"
              value={form.scopes}
              onChange={(e) => update('scopes', e.target.value)}
              placeholder="openid email profile"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Require Verified Email</Label>
              <p className="text-sm text-muted-foreground">
                Reject sign-ins whose email is not verified by the IdP.
              </p>
            </div>
            <Switch
              checked={form.require_email_verified}
              onCheckedChange={(v) => update('require_email_verified', v)}
              aria-label="Require verified email"
            />
          </div>

          {/* Test Connection */}
          <div className="rounded-md border p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {testing ? (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                ) : testResult?.success ? (
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                ) : testResult ? (
                  <XCircle className="h-4 w-4 text-destructive" />
                ) : (
                  <div className="h-3 w-3 rounded-full bg-muted-foreground/40" />
                )}
                <div>
                  <p className="text-sm font-medium">
                    {testing
                      ? 'Testing discovery...'
                      : testResult?.success
                        ? 'Discovery succeeded'
                        : testResult
                          ? 'Discovery failed'
                          : !provider
                            ? 'Save the provider to test'
                            : 'Not tested'}
                  </p>
                  {testResult && !testResult.success && testResult.error && (
                    <p className="text-sm text-destructive">{testResult.error}</p>
                  )}
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleTest}
                disabled={testing || !provider}
              >
                {testing ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
                Test Connection
              </Button>
            </div>
          </div>

          {/* Group Sync */}
          <div className="space-y-4 border-t pt-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Enable Group Sync</Label>
                <p className="text-sm text-muted-foreground">
                  Map IdP groups to a CHAD team and role on each sign-in.
                </p>
              </div>
              <Switch
                checked={form.group_sync_enabled}
                onCheckedChange={(v) => update('group_sync_enabled', v)}
                aria-label="Enable group sync"
              />
            </div>

            {form.group_sync_enabled && (
              <div className="space-y-4 border-l-2 border-muted pl-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="groups-claim">Groups Claim</Label>
                    <Input
                      id="groups-claim"
                      value={form.groups_claim}
                      onChange={(e) => update('groups_claim', e.target.value)}
                      placeholder="groups"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="groups-scope">Groups Scope</Label>
                    <Input
                      id="groups-scope"
                      value={form.groups_scope}
                      onChange={(e) => update('groups_scope', e.target.value)}
                      placeholder="groups"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="role-claim">Role Claim</Label>
                    <Input
                      id="role-claim"
                      value={form.role_claim}
                      onChange={(e) => update('role_claim', e.target.value)}
                      placeholder="roles"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label>Group Mappings</Label>
                    <Button type="button" variant="outline" size="sm" onClick={addMappingRow}>
                      <Plus className="mr-1 h-4 w-4" />
                      Add Mapping
                    </Button>
                  </div>

                  {mappings.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No mappings yet.</p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Group Value</TableHead>
                          <TableHead>Team</TableHead>
                          <TableHead>Role</TableHead>
                          <TableHead className="w-10" />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {mappings.map((mapping, index) => (
                          <TableRow key={index}>
                              <TableCell>
                                <Input
                                  aria-label={`Group value ${index + 1}`}
                                  value={mapping.group_value}
                                  onChange={(e) =>
                                    updateMapping(index, { group_value: e.target.value })
                                  }
                                  placeholder="soc-analysts"
                                />
                              </TableCell>
                              <TableCell>
                                <Select
                                  value={mapping.team_id ?? NO_TEAM}
                                  onValueChange={(v) =>
                                    updateMapping(index, {
                                      team_id: v === NO_TEAM ? null : v,
                                    })
                                  }
                                >
                                  <SelectTrigger aria-label={`Team ${index + 1}`}>
                                    <SelectValue placeholder="Select team" />
                                  </SelectTrigger>
                                  <SelectContent className="z-50 bg-popover">
                                    <SelectItem value={NO_TEAM}>No team</SelectItem>
                                    {teams.map((team) => (
                                      <SelectItem key={team.id} value={team.id}>
                                        {team.name}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              </TableCell>
                              <TableCell>
                                <Select
                                  value={mapping.role}
                                  onValueChange={(v) => updateMapping(index, { role: v })}
                                >
                                  <SelectTrigger aria-label={`Role ${index + 1}`}>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent className="z-50 bg-popover">
                                    {ROLE_OPTIONS.map((role) => (
                                      <SelectItem key={role} value={role} className="capitalize">
                                        {role}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              </TableCell>
                              <TableCell>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  aria-label={`Remove mapping ${index + 1}`}
                                  onClick={() => removeMapping(index)}
                                >
                                  <Trash2 className="h-4 w-4 text-destructive" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </div>
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="mr-2 h-4 w-4" />
                Save
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// SCIM provisioning panel
// ---------------------------------------------------------------------------

function ScimPanel() {
  const { showToast } = useToast()
  const [enabled, setEnabled] = useState(false)
  const [tokenConfigured, setTokenConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [generating, setGenerating] = useState(false)

  // One-time token reveal dialog
  const [revealOpen, setRevealOpen] = useState(false)
  const [revealedToken, setRevealedToken] = useState('')

  // SCIM base URL is derived on the client (the backend doesn't return it).
  const baseUrl =
    typeof window !== 'undefined' ? `${window.location.origin}/api/scim/v2` : '/api/scim/v2'

  useEffect(() => {
    let active = true
    scimApi
      .getConfig()
      .then((config) => {
        if (!active) return
        setEnabled(config.enabled)
        setTokenConfigured(config.token_configured)
      })
      .catch(() => {
        // older backend / SCIM not yet available: leave defaults
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  const handleToggle = async (next: boolean) => {
    setEnabled(next)
    setSaving(true)
    try {
      await scimApi.setEnabled(next)
      showToast(next ? 'SCIM provisioning enabled' : 'SCIM provisioning disabled')
    } catch (err) {
      setEnabled(!next)
      showToast(err instanceof Error ? err.message : 'Failed to update SCIM', 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const { token } = await scimApi.generateToken()
      setRevealedToken(token)
      setRevealOpen(true)
      setTokenConfigured(true)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to generate token', 'error')
    } finally {
      setGenerating(false)
    }
  }

  const handleCopyBaseUrl = async () => {
    const ok = await copyToClipboard(baseUrl)
    showToast(ok ? 'Base URL copied' : 'Copy failed', ok ? 'success' : 'error')
  }

  const handleCopyToken = async () => {
    const ok = await copyToClipboard(revealedToken)
    showToast(ok ? 'Token copied' : 'Copy failed', ok ? 'success' : 'error')
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>SCIM 2.0 Provisioning</CardTitle>
          <CardDescription>
            Let your identity provider auto-provision and deprovision users via SCIM.
          </CardDescription>
        </div>
        <Badge variant={enabled ? 'success' : 'outline'}>{enabled ? 'Enabled' : 'Disabled'}</Badge>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <Label>Enable SCIM provisioning</Label>
            <p className="text-sm text-muted-foreground">
              Exposes the SCIM 2.0 Users endpoint for your IdP. Disabled by default.
            </p>
          </div>
          <Switch
            checked={enabled}
            onCheckedChange={handleToggle}
            disabled={loading || saving}
            aria-label="Enable SCIM provisioning"
          />
        </div>

        <div className="space-y-2">
          <Label>Base URL</Label>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-md bg-muted px-3 py-2 font-mono text-xs">
              {baseUrl}
            </code>
            <Button variant="outline" size="sm" onClick={handleCopyBaseUrl} aria-label="Copy base URL">
              <Copy className="h-4 w-4" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Enter this as the SCIM connector base URL in your identity provider.
          </p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <Label>Bearer Token</Label>
              <p className="text-sm text-muted-foreground">
                {tokenConfigured
                  ? 'A token is configured. Regenerating invalidates the old one.'
                  : 'No token generated yet.'}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={handleGenerate} disabled={generating}>
              {generating ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <KeyRound className="mr-1 h-4 w-4" />}
              {tokenConfigured ? 'Regenerate Token' : 'Generate Token'}
            </Button>
          </div>
        </div>

        {/* IdP setup instructions */}
        <div className="rounded-md border bg-muted/40 p-4 text-sm">
          <p className="mb-2 font-medium">IdP Setup</p>
          <ol className="list-decimal space-y-1 pl-5 text-muted-foreground">
            <li>In your IdP, add a SCIM 2.0 provisioning connector.</li>
            <li>Set the base URL above as the SCIM endpoint.</li>
            <li>Use the generated bearer token for authentication.</li>
            <li>Enable user provisioning (push new users, updates, and deactivations).</li>
          </ol>
        </div>
      </CardContent>

      {/* One-time token reveal dialog */}
      <Dialog open={revealOpen} onOpenChange={setRevealOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>SCIM Bearer Token</DialogTitle>
            <DialogDescription>Copy this token now — it will not be shown again.</DialogDescription>
          </DialogHeader>

          <div
            role="alert"
            className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
          >
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span>This token won't be shown again. Store it securely.</span>
          </div>

          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">
              {revealedToken}
            </code>
            <Button variant="outline" size="sm" onClick={handleCopyToken} aria-label="Copy token">
              <Copy className="h-4 w-4" />
            </Button>
          </div>

          <DialogFooter>
            <Button onClick={() => setRevealOpen(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
