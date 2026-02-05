import { Link, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import {
  Settings2,
  Bot,
  Bell,
  Shield,
  KeyRound,
  Users,
  Globe,
  Target,
  Webhook,
  Database,
  Activity,
  HardDrive,
  ChevronRight,
  Lock,
  FileText,
  ScrollText,
  ArrowLeft,
  Archive,
} from 'lucide-react'
import { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import SettingsContent from '@/pages/Settings'
import UsersPage from '@/pages/Users'
import AuditLogPage from '@/pages/AuditLog'
import SystemLogsPage from '@/pages/SystemLogs'

interface SettingsCategory {
  title: string
  description: string
  icon: LucideIcon
  href: string
  tab?: string
  permission?: string
  badge?: string
}

const settingsCategories: { section: string; items: SettingsCategory[] }[] = [
  {
    section: 'Configuration',
    items: [
      {
        title: 'General',
        description: 'Background sync, version cleanup',
        icon: Settings2,
        href: '/settings/hub?tab=general',
        tab: 'general',
      },
      {
        title: 'AI Assistant',
        description: 'OpenAI, Anthropic, Ollama',
        icon: Bot,
        href: '/settings/hub?tab=ai',
        tab: 'ai',
        badge: 'Beta',
      },
      {
        title: 'Notifications',
        description: 'Email, Slack, Discord webhooks',
        icon: Bell,
        href: '/settings/hub?tab=notifications',
        tab: 'notifications',
      },
    ],
  },
  {
    section: 'Security & Access',
    items: [
      {
        title: 'Security',
        description: 'Sessions, 2FA, rate limiting',
        icon: Shield,
        href: '/settings/hub?tab=security',
        tab: 'security',
        permission: 'manage_settings',
      },
      {
        title: 'SSO',
        description: 'OIDC provider configuration',
        icon: KeyRound,
        href: '/settings/hub?tab=sso',
        tab: 'sso',
        permission: 'manage_settings',
      },
      {
        title: 'Users & Roles',
        description: 'Manage users and role permissions',
        icon: Users,
        href: '/settings/hub?tab=users',
        tab: 'users',
        permission: 'manage_users',
      },
    ],
  },
  {
    section: 'Enrichment & Intelligence',
    items: [
      {
        title: 'GeoIP',
        description: 'MaxMind database updates',
        icon: Globe,
        href: '/settings/hub?tab=geoip',
        tab: 'geoip',
      },
      {
        title: 'Threat Intel',
        description: 'MISP, feeds, IOC sources',
        icon: Target,
        href: '/settings/hub?tab=ti',
        tab: 'ti',
      },
      {
        title: 'Webhooks',
        description: 'Custom enrichment endpoints',
        icon: Webhook,
        href: '/settings/hub?tab=webhooks',
        tab: 'webhooks',
        badge: 'New',
      },
    ],
  },
  {
    section: 'System',
    items: [
      {
        title: 'OpenSearch',
        description: 'Connection status & settings',
        icon: Database,
        href: '/settings/hub?tab=opensearch',
        tab: 'opensearch',
      },
      {
        title: 'Health Monitoring',
        description: 'Thresholds & alerting',
        icon: Activity,
        href: '/settings/hub?tab=health',
        tab: 'health',
      },
      {
        title: 'Queue Settings',
        description: 'Push mode queue config',
        icon: HardDrive,
        href: '/settings/hub?tab=queue',
        tab: 'queue',
      },
      {
        title: 'Backup & Restore',
        description: 'Export/import configuration',
        icon: Archive,
        href: '/settings/hub?tab=backup',
        tab: 'backup',
      },
      {
        title: 'Audit Log',
        description: 'View system audit trail',
        icon: ScrollText,
        href: '/settings/hub?tab=audit',
        tab: 'audit',
        permission: 'view_audit',
      },
      {
        title: 'System Logs',
        description: 'View application logs',
        icon: FileText,
        href: '/settings/hub?tab=system-logs',
        tab: 'system-logs',
        permission: 'view_audit',
      },
    ],
  },
]

// Find category by tab name for header display
function findCategoryByTab(tab: string): SettingsCategory | undefined {
  for (const section of settingsCategories) {
    const found = section.items.find(item => item.tab === tab)
    if (found) return found
  }
  return undefined
}

function SettingsCategoryCard({
  category,
  hasPermission,
}: {
  category: SettingsCategory
  hasPermission: (p: string) => boolean
}) {
  const Icon = category.icon
  const isLocked = category.permission && !hasPermission(category.permission)

  if (isLocked) {
    return (
      <Card className="opacity-60 cursor-not-allowed relative">
        <div className="absolute inset-0 flex items-center justify-center bg-background/50 rounded-lg z-10">
          <Lock className="h-6 w-6 text-muted-foreground" />
        </div>
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="p-2 bg-muted rounded-lg w-fit">
              <Icon className="h-5 w-5 text-muted-foreground" />
            </div>
          </div>
          <CardTitle className="text-base mt-3">{category.title}</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <CardDescription className="text-sm min-h-[40px]">
            {category.description}
          </CardDescription>
        </CardContent>
      </Card>
    )
  }

  return (
    <Link to={category.href} className="group">
      <Card className="card-interactive cursor-pointer hover:border-primary/50 transition-colors h-full">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="p-2 bg-primary/10 rounded-lg w-fit group-hover:bg-primary/20 transition-colors">
              <Icon className="h-5 w-5 text-primary" />
            </div>
            {category.badge && (
              <span
                className={cn(
                  'px-2 py-0.5 text-xs font-medium rounded-full',
                  category.badge === 'New' &&
                    'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
                  category.badge === 'Beta' &&
                    'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
                )}
              >
                {category.badge}
              </span>
            )}
          </div>
          <CardTitle className="text-base mt-3">{category.title}</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <CardDescription className="text-sm min-h-[40px]">
            {category.description}
          </CardDescription>
          <div className="flex items-center text-sm text-primary font-medium mt-3 group-hover:translate-x-1 transition-transform">
            Configure
            <ChevronRight className="h-4 w-4 ml-1" />
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}

export default function SettingsHub() {
  const { hasPermission } = useAuth()
  const [searchParams] = useSearchParams()
  const activeTab = searchParams.get('tab')

  // Render content based on active tab
  const renderTabContent = () => {
    switch (activeTab) {
      case 'users':
        return <UsersPage />
      case 'audit':
        return <AuditLogPage />
      case 'system-logs':
        return <SystemLogsPage />
      default:
        return <SettingsContent />
    }
  }

  // If a tab is specified, render the settings content for that tab
  if (activeTab) {
    const category = findCategoryByTab(activeTab)
    const Icon = category?.icon || Settings2

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link to="/settings/hub">
            <Button variant="ghost" size="sm" className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              Back to Settings
            </Button>
          </Link>
        </div>
        <PageHeader
          title={
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Icon className="h-5 w-5 text-primary" />
              </div>
              <span>{category?.title || 'Settings'}</span>
            </div>
          }
          description={category?.description}
        />
        {renderTabContent()}
      </div>
    )
  }

  // Show the settings hub card grid
  return (
    <div className="space-y-8">
      <PageHeader
        title="Settings"
        description="Configure your CHAD instance"
      />

      {settingsCategories.map((section) => (
        <div key={section.section}>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-4">
            {section.section}
          </h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {section.items.map((category) => (
              <SettingsCategoryCard
                key={category.href}
                category={category}
                hasPermission={hasPermission}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
