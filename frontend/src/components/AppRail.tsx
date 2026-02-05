// frontend/src/components/AppRail.tsx
import { useState, useEffect, useRef } from 'react'
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
  showStatus?: boolean
}

type NavSection = {
  label: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    label: 'Operations',
    items: [
      { href: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
      { href: '/alerts', label: 'Alerts', icon: Bell },
      { href: '/rules', label: 'Rules', icon: ScrollText },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { href: '/attack', label: 'ATT&CK', icon: Target },
      { href: '/index-patterns', label: 'Index Patterns', icon: Database, permission: 'manage_index_config' },
    ],
  },
  {
    label: 'System',
    items: [
      { href: '/health', label: 'Health', icon: Activity, showStatus: true },
    ],
  },
]

const settingsItem: NavItem = {
  href: '/settings/hub',
  label: 'Settings',
  icon: Settings,
  permission: 'manage_settings',
}

interface AppRailProps {
  expanded: boolean
  onExpandedChange: (expanded: boolean) => void
  alertCount?: number
  healthStatus?: 'healthy' | 'warning' | 'critical'
}

export function AppRail({ expanded, onExpandedChange, alertCount, healthStatus }: AppRailProps) {
  const location = useLocation()
  const { hasPermission } = useAuth()

  // Track previous alert count for animation
  const [prevAlertCount, setPrevAlertCount] = useState(alertCount)
  const [badgeAnimating, setBadgeAnimating] = useState(false)
  const animationTimeoutRef = useRef<number | null>(null)

  useEffect(() => {
    if (alertCount !== prevAlertCount && alertCount !== undefined) {
      setBadgeAnimating(true)
      // Clear any existing timeout
      if (animationTimeoutRef.current) {
        window.clearTimeout(animationTimeoutRef.current)
      }
      animationTimeoutRef.current = window.setTimeout(() => {
        setBadgeAnimating(false)
        setPrevAlertCount(alertCount)
      }, 300)
    }
    return () => {
      if (animationTimeoutRef.current) {
        window.clearTimeout(animationTimeoutRef.current)
      }
    }
  }, [alertCount, prevAlertCount])

  // Filter sections to only include items the user has permission for
  const visibleSections = navSections.map(section => ({
    ...section,
    items: section.items.filter(item =>
      !item.permission || hasPermission(item.permission)
    ),
  })).filter(section => section.items.length > 0)

  const showSettings = !settingsItem.permission || hasPermission(settingsItem.permission)

  const isActive = (item: NavItem) => {
    if (item.exact) {
      return location.pathname === item.href
    }
    return location.pathname.startsWith(item.href)
  }

  const getStatusColor = (status?: 'healthy' | 'warning' | 'critical') => {
    switch (status) {
      case 'critical': return 'bg-red-500'
      case 'warning': return 'bg-yellow-500'
      case 'healthy': return 'bg-green-500'
      default: return 'bg-muted-foreground'
    }
  }

  const NavLink = ({ item, badge }: { item: NavItem; badge?: number }) => {
    const active = isActive(item)
    const Icon = item.icon
    const showHealthDot = item.showStatus && healthStatus

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
        <div className="relative">
          <Icon className="h-5 w-5 flex-shrink-0" />
          {!expanded && showHealthDot && (
            <span className={cn(
              'absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full',
              getStatusColor(healthStatus)
            )} />
          )}
        </div>
        {expanded && (
          <>
            <span className="flex-1">{item.label}</span>
            {showHealthDot && (
              <span className={cn(
                'h-2 w-2 rounded-full',
                getStatusColor(healthStatus)
              )} />
            )}
            {badge !== undefined && badge > 0 && (
              <span className={cn(
                "rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground",
                badgeAnimating && "animate-bounce-once"
              )}>
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
            {showHealthDot && ` - System ${healthStatus}`}
          </TooltipContent>
        </Tooltip>
      )
    }

    return content
  }

  const SectionLabel = ({ label }: { label: string }) => {
    if (!expanded) return null
    return (
      <div className="px-3 pt-4 pb-1 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        {label}
      </div>
    )
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
        <nav className="flex-1 p-2 pt-1 overflow-y-auto">
          {visibleSections.map((section, idx) => (
            <div key={section.label}>
              {idx > 0 && !expanded && <div className="my-2 mx-2 border-t border-border" />}
              <SectionLabel label={section.label} />
              <div className="space-y-1">
                {section.items.map((item) => (
                  <NavLink
                    key={item.href}
                    item={item}
                    badge={item.href === '/alerts' ? alertCount : undefined}
                  />
                ))}
              </div>
            </div>
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
