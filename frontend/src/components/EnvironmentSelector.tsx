import { useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { environmentsApi, type Environment } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import {
  useActiveEnvironmentId,
  setActiveEnvironmentId,
  reconcileActiveEnvironment,
} from '@/stores/environment-store'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { Check, ChevronDown, Layers, Star } from 'lucide-react'

export const ENVIRONMENTS_QUERY_KEY = 'environments'

/**
 * Active-environment picker for the AppHeader (left of the user menu).
 *
 * Lists the team environments returned by GET /environments, checkmarks the
 * active one, and lets the user set the per-team default (the star). Switching
 * updates the module store (environment-store), which in turn flips the
 * X-CHAD-Environment header on every subsequent api request.
 *
 * On (re)load — including after a team change, which changes the returned list —
 * the store reconciles the persisted selection against the list and auto-selects
 * the team default when the prior selection is no longer present.
 */
export function EnvironmentSelector() {
  const { isAuthenticated, isAdmin, hasPermission } = useAuth()
  const queryClient = useQueryClient()
  const activeId = useActiveEnvironmentId()

  const { data: environments } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY],
    queryFn: () => environmentsApi.list(),
    enabled: isAuthenticated,
    // Degrade quietly: a backend without environments (older deploy) just hides
    // the selector rather than surfacing an error in the header.
    retry: false,
  })

  // Reconcile the persisted selection whenever the list changes (login, refetch,
  // team switch). This implements the "auto-select the team default" behaviour.
  useEffect(() => {
    if (environments) {
      reconcileActiveEnvironment(environments)
    }
  }, [environments])

  const setDefaultMutation = useMutation({
    mutationFn: (id: string) => environmentsApi.setDefault(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ENVIRONMENTS_QUERY_KEY] })
    },
  })

  // Nothing to show until we have at least one environment.
  if (!isAuthenticated || !environments || environments.length === 0) {
    return null
  }

  const canSetDefault = isAdmin || hasPermission('manage_environments')
  const active = environments.find((e) => e.id === activeId) ?? environments[0]

  const handleSelect = (env: Environment) => {
    setActiveEnvironmentId(env.id)
  }

  const handleSetDefault = (env: Environment, e: React.MouseEvent) => {
    // Keep the menu open and don't trigger the row's select.
    e.preventDefault()
    e.stopPropagation()
    if (!env.is_default) {
      setDefaultMutation.mutate(env.id)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="h-7 gap-1.5 px-2.5"
          aria-label={`Active environment: ${active.name}`}
        >
          <Layers className="h-3.5 w-3.5 text-fg-3" />
          <span className="vf-mono-xs max-w-[120px] truncate">{active.name}</span>
          {active.is_default && (
            <Star className="h-3 w-3 fill-accent-brand text-accent-brand" aria-label="Default" />
          )}
          <ChevronDown className="h-3.5 w-3.5 text-fg-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-fg-3">Environment</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {environments.map((env) => {
          const isActive = env.id === active.id
          return (
            <DropdownMenuItem
              key={env.id}
              onClick={() => handleSelect(env)}
              className="flex items-center gap-2"
            >
              <Check
                className={cn(
                  'h-4 w-4 shrink-0',
                  isActive ? 'opacity-100 text-accent-brand' : 'opacity-0'
                )}
              />
              <div className="flex min-w-0 flex-1 flex-col">
                <span className="truncate">{env.name}</span>
                <span className="vf-mono-xs text-fg-3">
                  {env.deployed_count}/{env.rule_count} deployed
                  {env.require_deploy_approval ? ' · approval' : ''}
                </span>
              </div>
              {canSetDefault ? (
                <button
                  type="button"
                  onClick={(e) => handleSetDefault(env, e)}
                  className="shrink-0 rounded-[3px] p-1 text-fg-3 hover:bg-bg-3 hover:text-accent-brand"
                  aria-label={
                    env.is_default
                      ? `${env.name} is the team default`
                      : `Set ${env.name} as team default`
                  }
                  title={env.is_default ? 'Team default' : 'Set as team default'}
                  disabled={env.is_default || setDefaultMutation.isPending}
                >
                  <Star
                    className={cn(
                      'h-3.5 w-3.5',
                      env.is_default && 'fill-accent-brand text-accent-brand'
                    )}
                  />
                </button>
              ) : (
                env.is_default && (
                  <Star
                    className="h-3.5 w-3.5 shrink-0 fill-accent-brand text-accent-brand"
                    aria-label="Team default"
                  />
                )
              )}
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
