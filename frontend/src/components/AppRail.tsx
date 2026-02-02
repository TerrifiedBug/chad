// frontend/src/components/AppRail.tsx
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  LayoutDashboard,
  Bell,
  ScrollText,
  Target,
  Database,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'

type NavItem = {
  href: string
  label: string
  icon: React.ElementType
  exact?: boolean
  permission?: string
  badge?: number
}

const navItems: NavItem[] = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { href: '/alerts', label: 'Alerts', icon: Bell },
  { href: '/rules', label: 'Rules', icon: ScrollText },
  { href: '/attack', label: 'ATT&CK', icon: Target },
  { href: '/index-patterns', label: 'Index Patterns', icon: Database, permission: 'manage_index_config' },
  { href: '/health', label: 'Health', icon: Activity },
]

const settingsItem: NavItem = {
  href: '/settings',
  label: 'Settings',
  icon: Settings,
  permission: 'manage_settings',
}

interface AppRailProps {
  expanded: boolean
  onExpandedChange: (expanded: boolean) => void
  alertCount?: number
}

export function AppRail({ expanded, onExpandedChange, alertCount }: AppRailProps) {
  const location = useLocation()
  const { hasPermission } = useAuth()

  const visibleItems = navItems.filter(item =>
    !item.permission || hasPermission(item.permission)
  )

  const showSettings = !settingsItem.permission || hasPermission(settingsItem.permission)

  const isActive = (item: NavItem) => {
    if (item.exact) {
      return location.pathname === item.href
    }
    return location.pathname.startsWith(item.href)
  }

  const NavLink = ({ item, badge }: { item: NavItem; badge?: number }) => {
    const active = isActive(item)
    const Icon = item.icon

    const content = (
      <Link
        to={item.href}
        className={cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          'hover:bg-muted',
          active ? 'bg-muted text-foreground' : 'text-muted-foreground',
          !expanded && 'justify-center px-2'
        )}
      >
        <Icon className="h-5 w-5 flex-shrink-0" />
        {expanded && (
          <>
            <span className="flex-1">{item.label}</span>
            {badge !== undefined && badge > 0 && (
              <span className="rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
                {badge > 99 ? '99+' : badge}
              </span>
            )}
          </>
        )}
        {!expanded && badge !== undefined && badge > 0 && (
          <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-primary" />
        )}
      </Link>
    )

    if (!expanded) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>
            <div className="relative">{content}</div>
          </TooltipTrigger>
          <TooltipContent side="right">
            {item.label}
            {badge !== undefined && badge > 0 && ` (${badge})`}
          </TooltipContent>
        </Tooltip>
      )
    }

    return content
  }

  return (
    <TooltipProvider>
      <aside
        className={cn(
          'sticky top-14 flex h-[calc(100vh-3.5rem)] flex-col border-r bg-background transition-all duration-200',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Collapse toggle */}
        <div className={cn('flex items-center border-b p-2', expanded ? 'justify-end' : 'justify-center')}>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => onExpandedChange(!expanded)}
            aria-label={expanded ? 'Collapse navigation' : 'Expand navigation'}
          >
            {expanded ? (
              <ChevronLeft className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>
        </div>

        {/* Main navigation */}
        <nav className="flex-1 space-y-1 p-2">
          {visibleItems.map((item) => (
            <NavLink
              key={item.href}
              item={item}
              badge={item.href === '/alerts' ? alertCount : undefined}
            />
          ))}
        </nav>

        {/* Settings at bottom */}
        {showSettings && (
          <div className="border-t p-2">
            <NavLink item={settingsItem} />
          </div>
        )}
      </aside>
    </TooltipProvider>
  )
}
