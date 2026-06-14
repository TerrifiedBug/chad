// frontend/src/components/AppRail.tsx
import { useState, useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { useVersion } from '@/hooks/use-version'
import { deploymentRequestsApi } from '@/lib/api'
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
  ShieldAlert,
  Target,
  Database,
  Activity,
  Settings,
  GitPullRequest,
  Layers,
} from 'lucide-react'

export type NavItem = {
  href: string
  label: string
  icon: React.ElementType
  exact?: boolean
  permission?: string
  /** Item is visible if the user holds ANY of these permissions (OR-gated). */
  permissionsAny?: string[]
  badge?: number
  showStatus?: boolean
}

type NavSection = {
  label: string
  items: NavItem[]
}

export const navSections: NavSection[] = [
  {
    label: 'Operations',
    items: [
      { href: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
      { href: '/alerts', label: 'Alerts', icon: Bell },
      { href: '/ioc-matches', label: 'IOC Matches', icon: ShieldAlert },
      { href: '/rules', label: 'Rules', icon: ScrollText },
      { href: '/approvals', label: 'Approvals', icon: GitPullRequest, permissionsAny: ['deploy_rules', 'approve_deployments'] },
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
      { href: '/environments', label: 'Environments', icon: Layers, permission: 'manage_environments' },
      { href: '/health', label: 'Health', icon: Activity, showStatus: true },
    ],
  },
]

export const settingsItem: NavItem = {
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
  const { version } = useVersion()

  // Pending deployment-approval count for the Approvals nav badge. Only fetched
  // for users who can see the item; degrades to no badge if the call fails.
  const canSeeApprovals =
    hasPermission('deploy_rules') || hasPermission('approve_deployments')
  const { data: deploymentStats } = useQuery({
    queryKey: ['deployment-requests', 'stats'],
    queryFn: () => deploymentRequestsApi.getStats(),
    enabled: canSeeApprovals,
    refetchInterval: 60000,
  })
  const approvalsCount = deploymentStats?.pending

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
    items: section.items.filter(item => {
      if (item.permissionsAny) {
        return item.permissionsAny.some(p => hasPermission(p))
      }
      return !item.permission || hasPermission(item.permission)
    }),
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
          // VF console: active = left 2px accent-brand rule + accent-soft fill
          // + semibold. Inactive items stay muted with a subtle hover.
          'flex items-center gap-3 rounded-[3px] border-l-2 border-transparent px-3 py-2 text-sm font-medium transition-colors',
          'hover:bg-bg-3/60',
          active
            ? 'border-l-accent-brand bg-accent-brand-soft text-foreground font-semibold'
            : 'text-fg-2',
          !expanded && 'justify-center border-l-0 px-2'
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
      <div className="vf-thead px-3 pt-4 pb-1 text-fg-3">
        {label}
      </div>
    )
  }

  return (
    <TooltipProvider>
      <aside
        className={cn(
          'fixed top-0 left-0 flex h-screen flex-col border-r border-line bg-bg-1 transition-all duration-200 z-50',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Rail header: VF puts the product mark in the sidebar header. */}
        <Link
          to="/"
          className={cn(
            'flex h-12 flex-shrink-0 items-center gap-2 border-b border-line px-3',
            !expanded && 'justify-center px-0'
          )}
          aria-label="CHAD home"
        >
          <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-[3px] bg-accent-brand-soft font-mono text-[12px] font-bold text-accent-brand">
            C
          </span>
          {expanded && (
            <span className="font-mono text-sm font-semibold tracking-tight">CHAD</span>
          )}
        </Link>

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
                    badge={
                      item.href === '/alerts'
                        ? alertCount
                        : item.href === '/approvals'
                          ? approvalsCount
                          : undefined
                    }
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

        {/* Footer: version + green "all systems normal" status dot (VF rail). */}
        <div className={cn(
          'flex flex-shrink-0 items-center gap-2 border-t border-line px-3 py-2',
          !expanded && 'justify-center px-0'
        )}>
          <span className="relative flex h-2 w-2 flex-shrink-0">
            <span className="absolute inline-flex h-full w-full rounded-full bg-accent-brand opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-accent-brand" />
          </span>
          {expanded && (
            <span className="vf-mono-xs truncate text-fg-3">
              {version ? `v${version}` : 'All systems normal'}
            </span>
          )}
        </div>

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
