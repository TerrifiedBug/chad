// frontend/src/components/AppRail.tsx
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { cn } from '@/lib/utils'
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
          'fixed top-0 left-0 flex h-screen flex-col bg-background transition-all duration-200 z-50',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Main navigation - starts at top */}
        <nav className="flex-1 space-y-1 p-2 pt-3">
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
          <div className="p-2">
            <NavLink item={settingsItem} />
          </div>
        )}

        {/* Clickable border for expand/collapse */}
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>
            <button
              onClick={() => onExpandedChange(!expanded)}
              className="absolute top-0 right-0 w-4 h-full cursor-col-resize transition-colors group flex items-center justify-center"
              aria-label={expanded ? 'Collapse navigation' : 'Expand navigation'}
            >
              {/* Vertical line */}
              <div className="absolute right-0 w-px h-full bg-border" />
              {/* Pill handle indicator */}
              <div className="absolute right-0 translate-x-1/2 w-1.5 h-8 rounded-full bg-border group-hover:bg-primary transition-colors" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right" className="bg-primary text-primary-foreground border-primary">
            {expanded ? 'Collapse' : 'Expand'}
          </TooltipContent>
        </Tooltip>
      </aside>
    </TooltipProvider>
  )
}
