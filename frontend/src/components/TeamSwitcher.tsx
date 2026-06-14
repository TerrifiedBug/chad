import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { teamsApi, type Team } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
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
import { Check, ChevronDown, Users } from 'lucide-react'

const ACTIVE_TEAM_KEY = 'chad-active-team'

/**
 * Team picker for the AppHeader (left of the EnvironmentSelector), mirroring
 * VectorFlow's top-bar TeamSelector for shell parity.
 *
 * CHAD scopes data by the user's own team membership (server-side), not by a
 * per-request header, so this control is a UI affordance: it lists the visible
 * teams and persists the highlighted one to localStorage. It deliberately does
 * NOT attach an X-CHAD-Team header (the backend doesn't consume one) so it can
 * never interfere with environment scoping. Hidden when no teams exist.
 */
export function TeamSwitcher() {
  const { isAuthenticated } = useAuth()
  const [activeId, setActiveId] = useState<string | null>(() =>
    localStorage.getItem(ACTIVE_TEAM_KEY)
  )

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: () => teamsApi.list(),
    enabled: isAuthenticated,
    // Degrade quietly: a non-admin (403) or older backend just hides the pill.
    retry: false,
  })

  if (!isAuthenticated || !teams || teams.length === 0) {
    return null
  }

  const active = teams.find((t) => t.id === activeId) ?? teams[0]

  const handleSelect = (team: Team) => {
    setActiveId(team.id)
    localStorage.setItem(ACTIVE_TEAM_KEY, team.id)
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="h-7 gap-1.5 px-2.5"
          aria-label={`Active team: ${active.name}`}
        >
          <Users className="h-3.5 w-3.5 text-fg-3" />
          <span className="vf-mono-xs max-w-[120px] truncate">{active.name}</span>
          <ChevronDown className="h-3.5 w-3.5 text-fg-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        <DropdownMenuLabel className="text-fg-3">Team</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {teams.map((team) => {
          const isActive = team.id === active.id
          return (
            <DropdownMenuItem
              key={team.id}
              onClick={() => handleSelect(team)}
              className="flex items-center gap-2"
            >
              <Check
                className={cn(
                  'h-4 w-4 shrink-0',
                  isActive ? 'opacity-100 text-accent-brand' : 'opacity-0'
                )}
              />
              <span className="truncate">{team.name}</span>
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
