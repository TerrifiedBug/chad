import { useQuery } from '@tanstack/react-query'
import { environmentsApi } from '@/lib/api'
import { useActiveEnvironmentId } from '@/stores/environment-store'
import { ENVIRONMENTS_QUERY_KEY } from '@/components/EnvironmentSelector'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Layers } from 'lucide-react'

/**
 * Small read-only badge showing the active environment — i.e. which env's
 * deployment state the surrounding view (Rules list, RuleEditor header) is
 * scoped to. Reads the active id from the env store and resolves its name from
 * the cached environment list. Renders nothing until an env is resolvable, so
 * older backends without environments stay clean.
 */
export function EnvironmentBadge({ className }: { className?: string }) {
  const activeId = useActiveEnvironmentId()
  const { data: environments } = useQuery({
    queryKey: [ENVIRONMENTS_QUERY_KEY],
    queryFn: () => environmentsApi.list(),
    retry: false,
  })

  if (!environments || environments.length === 0) return null
  const active = environments.find((e) => e.id === activeId) ?? environments[0]

  return (
    <Badge variant="outline" className={cn('gap-1', className)} aria-label={`Environment: ${active.name}`}>
      <Layers className="h-3 w-3" />
      {active.name}
    </Badge>
  )
}
