// frontend/src/components/AppRail.tsx
import { useState, useEffect, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { useVersion } from '@/hooks/use-version'
import { deploymentRequestsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import { settingsNavGroups } from '@/config/settingsNav'
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
  ArrowLeft,
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
  href: '/settings',
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
  const navigate = useNavigate()
  const { hasPermission } = useAuth()
  const { version } = useVersion()

  // In settings mode the rail slides from the main nav to a settings nav panel
  // (VF "sidebar becomes the settings list"). Driven purely by the route.
  const isSettingsMode = location.pathname.startsWith('/settings')

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
          // + semibold. Inactive items stay muted with a subtle hover. Density
          // matches VF's SidebarMenuButton (h-[30px], gap-[9px], px-[9px],
          // 13px) so the rail reads as the same product.
          'flex h-[30px] items-center gap-[9px] rounded-[3px] border-l-2 border-transparent px-[9px] text-[13px] font-medium transition-colors',
          'hover:bg-bg-3/60',
          active
            ? 'border-l-accent-brand bg-accent-brand-soft text-foreground font-semibold'
            : 'text-fg-2',
          !expanded && 'justify-center border-l-0 px-2'
        )}
      >
        <div className="relative">
          <Icon className="h-[15px] w-[15px] flex-shrink-0" />
          {!expanded && showHealthDot && (
            <span className={cn(
              'absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full rounded-dot',
              getStatusColor(healthStatus)
            )} />
          )}
        </div>
        {expanded && (
          <>
            <span className="flex-1">{item.label}</span>
            {showHealthDot && (
              <span className={cn(
                'h-2 w-2 rounded-full rounded-dot',
                getStatusColor(healthStatus)
              )} />
            )}
            {badge !== undefined && badge > 0 && (
              <span className={cn(
                // VF: square red badge, mono 11px, capped 99+.
                "inline-flex h-5 min-w-5 items-center justify-center rounded-[3px] bg-destructive px-1.5 font-mono text-[11px] text-destructive-foreground",
                badgeAnimating && "animate-bounce-once"
              )}>
                {badge > 99 ? '99+' : badge}
              </span>
            )}
          </>
        )}
        {!expanded && badge !== undefined && badge > 0 && (
          <span className="absolute right-1 top-1 h-2 w-2 rounded-full rounded-dot bg-destructive" />
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
    // Matches VF's SidebarGroupLabel: h-6, 11px mono, uppercase, normal weight.
    return (
      <div className="flex h-6 items-center px-2 pt-3 font-mono text-[11px] font-normal uppercase tracking-[0.08em] text-fg-2">
        {label}
      </div>
    )
  }

  // Settings nav panel rows (shown when isSettingsMode). Same density/active
  // treatment as the main NavLink, but route-link based with no badges.
  const SettingsNavLink = ({
    item,
  }: {
    item: { href: string; label: string; icon: React.ElementType }
  }) => {
    const active = location.pathname === item.href
    const Icon = item.icon
    const content = (
      <Link
        to={item.href}
        className={cn(
          'flex h-[30px] items-center gap-[9px] rounded-[3px] border-l-2 border-transparent px-[9px] text-[13px] font-medium transition-colors',
          'hover:bg-bg-3/60',
          active
            ? 'border-l-accent-brand bg-accent-brand-soft text-foreground font-semibold'
            : 'text-fg-2',
          !expanded && 'justify-center border-l-0 px-2'
        )}
      >
        <Icon className="h-[15px] w-[15px] flex-shrink-0" />
        {expanded && <span className="flex-1 truncate">{item.label}</span>}
      </Link>
    )
    if (!expanded) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>
            <div className="relative">{content}</div>
          </TooltipTrigger>
          <TooltipContent side="right">{item.label}</TooltipContent>
        </Tooltip>
      )
    }
    return content
  }

  const visibleSettingsGroups = settingsNavGroups
    .map((group) => ({
      ...group,
      items: group.items.filter(
        (item) => !item.permission || hasPermission(item.permission)
      ),
    }))
    .filter((group) => group.items.length > 0)

  return (
    <TooltipProvider>
      <aside
        className={cn(
          'fixed top-0 left-0 flex h-screen flex-col border-r border-line bg-bg-1 transition-all duration-200 z-50',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Rail header: the product mark (main mode) flips to a back-to-app
            affordance in settings mode — VF's "sidebar becomes settings".
            Height matches the AppHeader (52px) so the hairlines stay flush. */}
        {isSettingsMode ? (
          <button
            type="button"
            onClick={() => navigate('/')}
            className={cn(
              'flex h-[52px] flex-shrink-0 items-center gap-2 border-b border-line px-3 text-fg-2 transition-colors hover:text-fg',
              !expanded && 'justify-center px-0'
            )}
            aria-label="Back to app"
          >
            <ArrowLeft className="h-[15px] w-[15px] flex-shrink-0" />
            {expanded && (
              <span className="font-mono text-sm font-semibold tracking-tight">Settings</span>
            )}
          </button>
        ) : (
          <Link
            to="/"
            className={cn(
              'flex h-[52px] flex-shrink-0 items-center gap-2 border-b border-line px-3',
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
        )}

        {/* Sliding nav panels: the main nav and the settings nav are stacked
            siblings; the route slides one in and the other out. */}
        <div className="relative flex-1 overflow-hidden">
          <nav
            className={cn(
              'absolute inset-0 overflow-y-auto p-2 pt-1 transition-transform duration-200 ease-out',
              isSettingsMode
                ? '-translate-x-full opacity-0 pointer-events-none'
                : 'translate-x-0'
            )}
            aria-hidden={isSettingsMode}
          >
            {visibleSections.map((section, idx) => (
              <div key={section.label}>
                {idx > 0 && !expanded && <div className="my-2 mx-2 border-t border-line" />}
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

          <nav
            className={cn(
              'absolute inset-0 overflow-y-auto p-2 pt-1 transition-transform duration-200 ease-out',
              isSettingsMode
                ? 'translate-x-0'
                : 'translate-x-full opacity-0 pointer-events-none'
            )}
            aria-hidden={!isSettingsMode}
          >
            {visibleSettingsGroups.map((group, idx) => (
              <div key={group.label}>
                {idx > 0 && !expanded && <div className="my-2 mx-2 border-t border-line" />}
                <SectionLabel label={group.label} />
                <div className="space-y-1">
                  {group.items.map((item) => (
                    <SettingsNavLink key={item.id} item={item} />
                  ))}
                </div>
              </div>
            ))}
          </nav>
        </div>

        {/* Settings entry (main mode only — in settings mode the rail IS settings) */}
        {showSettings && !isSettingsMode && (
          <div className="p-2">
            <NavLink item={settingsItem} />
          </div>
        )}

        {/* Footer: VF rail shows version (left) + a status dot with "All systems
            normal" (right) on one mono row. When collapsed, only the dot shows. */}
        <div className={cn(
          'flex flex-shrink-0 items-center border-t border-line px-3 py-2',
          expanded ? 'justify-between gap-2' : 'justify-center px-0'
        )}>
          {expanded && (
            <span className="vf-mono-xs truncate text-fg-3">
              {version ? `v${version}` : 'CHAD'}
            </span>
          )}
          <span className="inline-flex items-center gap-1.5">
            <span className="relative flex h-2 w-2 flex-shrink-0">
              <span className="absolute inline-flex h-full w-full rounded-full rounded-dot bg-accent-brand opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full rounded-dot bg-accent-brand" />
            </span>
            {expanded && (
              <span className="vf-mono-xs truncate text-fg-3">All systems normal</span>
            )}
          </span>
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
