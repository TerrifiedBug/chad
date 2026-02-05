// frontend/src/components/SettingsSidebar.tsx
import { Link, useNavigate, useSearchParams, useLocation } from 'react-router-dom'
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
  Wrench,
  Shield,
  Bell,
  Bot,
  Globe,
  Inbox,
  Search,
  Activity,
  HardDrive,
  ArrowLeft,
  Users,
  FileText,
  Key,
  ScrollText,
  KeyRound,
  ShieldCheck,
  Target,
  Webhook,
} from 'lucide-react'

type SettingsItem = {
  id: string
  label: string
  icon: React.ElementType
  permission?: string
}

type SettingsGroup = {
  label: string
  items: SettingsItem[]
  permission?: string // Group-level permission (all items require this)
}

const settingsGroups: SettingsGroup[] = [
  {
    label: 'Configuration',
    permission: 'manage_settings',
    items: [
      { id: 'general', label: 'General', icon: Wrench },
      { id: 'security', label: 'Security', icon: Shield },
      { id: 'sso', label: 'SSO', icon: KeyRound },
      { id: 'notifications', label: 'Notifications', icon: Bell },
      { id: 'ai', label: 'AI', icon: Bot },
    ],
  },
  {
    label: 'Enrichment',
    permission: 'manage_settings',
    items: [
      { id: 'geoip', label: 'GeoIP', icon: Globe },
      { id: 'ti', label: 'Threat Intel', icon: Target },
      { id: 'webhooks', label: 'Webhooks', icon: Webhook },
    ],
  },
  {
    label: 'System',
    permission: 'manage_settings',
    items: [
      { id: 'opensearch', label: 'OpenSearch', icon: Search },
      { id: 'queue', label: 'Queue', icon: Inbox },
      { id: 'health', label: 'Health', icon: Activity },
      { id: 'backup', label: 'Backup', icon: HardDrive },
    ],
  },
]

interface SettingsSidebarProps {
  expanded: boolean
  onExpandedChange: (expanded: boolean) => void
}

// Administration section (link-based, separate pages)
type SettingsLink = {
  href: string
  label: string
  icon: React.ElementType
  permission?: string
}

const adminLinks: SettingsLink[] = [
  { href: '/settings/users', label: 'Users', icon: Users, permission: 'manage_users' },
  { href: '/settings/permissions', label: 'Permissions', icon: ShieldCheck, permission: 'manage_settings' },
  { href: '/settings/audit', label: 'Audit Log', icon: FileText, permission: 'view_audit' },
  { href: '/settings/system-logs', label: 'System Log', icon: ScrollText, permission: 'view_system_logs' },
  { href: '/settings/api-keys', label: 'API Keys', icon: Key, permission: 'manage_api_keys' },
]

export function SettingsSidebar({ expanded, onExpandedChange }: SettingsSidebarProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const { hasPermission } = useAuth()
  const [searchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'general'

  // Filter groups based on permissions
  const visibleGroups = settingsGroups.filter(group =>
    !group.permission || hasPermission(group.permission)
  )

  // Filter admin links based on permissions
  const visibleAdminLinks = adminLinks.filter(link =>
    !link.permission || hasPermission(link.permission)
  )

  const handleSectionClick = (sectionId: string) => {
    navigate('/settings?tab=' + sectionId)
  }

  const handleBack = () => {
    // Navigate to settings hub
    navigate('/settings/hub')
  }

  // Check if we're on main settings page (not a subpage)
  const isMainSettingsPage = location.pathname === '/settings'

  const NavItem = ({ item }: { item: SettingsItem }) => {
    const active = isMainSettingsPage && activeTab === item.id
    const Icon = item.icon

    const content = (
      <button
        onClick={() => handleSectionClick(item.id)}
        className={cn(
          'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          'hover:bg-muted',
          active ? 'bg-muted text-foreground' : 'text-muted-foreground',
          !expanded && 'justify-center px-2'
        )}
      >
        <Icon className="h-5 w-5 flex-shrink-0" />
        {expanded && <span>{item.label}</span>}
      </button>
    )

    if (!expanded) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>{content}</TooltipTrigger>
          <TooltipContent side="right">{item.label}</TooltipContent>
        </Tooltip>
      )
    }

    return content
  }

  const SectionLabel = ({ label }: { label: string }) => {
    if (!expanded) return null
    return (
      <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        {label}
      </div>
    )
  }

  const NavLink = ({ link }: { link: SettingsLink }) => {
    const active = location.pathname === link.href
    const Icon = link.icon

    const content = (
      <Link
        to={link.href}
        className={cn(
          'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          'hover:bg-muted',
          active ? 'bg-muted text-foreground' : 'text-muted-foreground',
          !expanded && 'justify-center px-2'
        )}
      >
        <Icon className="h-5 w-5 flex-shrink-0" />
        {expanded && <span>{link.label}</span>}
      </Link>
    )

    if (!expanded) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>{content}</TooltipTrigger>
          <TooltipContent side="right">{link.label}</TooltipContent>
        </Tooltip>
      )
    }

    return content
  }

  const backButton = (
    <Button
      variant="ghost"
      size={expanded ? 'sm' : 'icon'}
      className={cn('gap-1', !expanded && 'h-8 w-8')}
      onClick={handleBack}
    >
      <ArrowLeft className="h-4 w-4" />
      {expanded && 'Back'}
    </Button>
  )

  return (
    <TooltipProvider>
      <aside
        className={cn(
          'fixed top-0 left-0 flex h-screen flex-col bg-background transition-all duration-200 z-50',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Back button - starts at top */}
        <div className={cn('p-2 pt-3', !expanded && 'flex justify-center')}>
          {!expanded ? (
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>{backButton}</TooltipTrigger>
              <TooltipContent side="right">Back</TooltipContent>
            </Tooltip>
          ) : (
            backButton
          )}
        </div>

        {/* Settings sections */}
        <nav className="flex-1 overflow-y-auto p-2">
          {visibleGroups.map((group, index) => (
            <div key={group.label} className={cn(index > 0 && 'mt-4')}>
              <SectionLabel label={group.label} />
              <div className="space-y-1">
                {group.items.map((item) => (
                  <NavItem key={item.id} item={item} />
                ))}
              </div>
            </div>
          ))}

          {/* Administration section - only show if user has any admin links */}
          {visibleAdminLinks.length > 0 && (
            <div className="mt-4">
              <SectionLabel label="Administration" />
              <div className="space-y-1">
                {visibleAdminLinks.map((link) => (
                  <NavLink key={link.href} link={link} />
                ))}
              </div>
            </div>
          )}
        </nav>

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
