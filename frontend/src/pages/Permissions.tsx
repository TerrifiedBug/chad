import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { permissionsApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ArrowLeft, ChevronDown, ShieldCheck } from 'lucide-react'
import { LoadingState } from '@/components/ui/loading-state'

export default function PermissionsPage() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [permissions, setPermissions] = useState<Record<string, Record<string, boolean>>>({})
  const [permissionDescriptions, setPermissionDescriptions] = useState<Record<string, string>>({})

  useEffect(() => {
    loadPermissions()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loadPermissions = async () => {
    try {
      const data = await permissionsApi.getAll()
      setPermissions(data.roles)
      setPermissionDescriptions(data.descriptions)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load permissions', 'error')
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return <LoadingState message="Loading permissions..." />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/settings">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldCheck className="h-6 w-6" />
            Role Permissions
          </h1>
          <p className="text-muted-foreground">Configure what each role can do. Admin permissions cannot be modified.</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Permission Configuration</CardTitle>
          <CardDescription>
            Toggle permissions for Analyst and Viewer roles. Admin users have all permissions enabled by default.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {['analyst', 'viewer'].map((role) => {
              const enabledCount = Object.keys(permissionDescriptions).filter(
                (perm) => permissions[role]?.[perm] ?? false
              ).length
              const totalCount = Object.keys(permissionDescriptions).length
              return (
                <Collapsible key={role} defaultOpen={role === 'analyst'} className="border rounded-lg">
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors [&[data-state=open]>svg]:rotate-180">
                    <div className="flex items-center gap-3">
                      <h3 className="font-medium capitalize text-lg">{role}</h3>
                      <span className="text-sm text-muted-foreground">
                        {enabledCount} of {totalCount} permissions enabled
                      </span>
                    </div>
                    <ChevronDown className="h-4 w-4 transition-transform duration-200" />
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="grid gap-3 p-4 pt-0 border-t">
                      {Object.entries(permissionDescriptions).map(([perm, desc]) => (
                        <div key={perm} className="flex items-center justify-between py-2">
                          <div className="space-y-0.5">
                            <Label className="text-sm font-medium">
                              {perm.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                            </Label>
                            <p className="text-xs text-muted-foreground">{desc}</p>
                          </div>
                          <Switch
                            checked={permissions[role]?.[perm] ?? false}
                            onCheckedChange={async (checked) => {
                              try {
                                await permissionsApi.update(role, perm, checked)
                                setPermissions((prev) => ({
                                  ...prev,
                                  [role]: { ...prev[role], [perm]: checked },
                                }))
                                showToast(`Permission updated for ${role}`)
                              } catch (err) {
                                showToast(
                                  err instanceof Error ? err.message : 'Failed to update permission',
                                  'error'
                                )
                              }
                            }}
                          />
                        </div>
                      ))}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              )
            })}
            {Object.keys(permissionDescriptions).length === 0 && (
              <p className="text-muted-foreground text-sm">
                No permissions configured. The permissions API may not be available.
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
