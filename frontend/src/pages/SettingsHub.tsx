import { Link } from 'react-router-dom'
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
  Key,
  ScrollText,
} from 'lucide-react'
import { LucideIcon } from 'lucide-react'

interface SettingsCategory {
  title: string
  description: string
  icon: LucideIcon
  href: string
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
        href: '/settings?tab=general',
      },
      {
        title: 'AI Assistant',
        description: 'OpenAI, Anthropic, Ollama',
        icon: Bot,
        href: '/settings?tab=ai',
        badge: 'Beta',
      },
      {
        title: 'Notifications',
        description: 'Email, Slack, Discord webhooks',
        icon: Bell,
        href: '/settings?tab=notifications',
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
        href: '/settings?tab=security',
        permission: 'manage_settings',
      },
      {
        title: 'SSO',
        description: 'OIDC provider configuration',
        icon: KeyRound,
        href: '/settings?tab=sso',
        permission: 'manage_settings',
      },
      {
        title: 'Users',
        description: 'Manage users & roles',
        icon: Users,
        href: '/settings/users',
        permission: 'manage_users',
      },
      {
        title: 'Permissions',
        description: 'Role permissions',
        icon: Lock,
        href: '/settings/permissions',
        permission: 'manage_users',
      },
      {
        title: 'API Keys',
        description: 'Manage API access',
        icon: Key,
        href: '/settings/api-keys',
        permission: 'manage_api_keys',
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
        href: '/settings?tab=geoip',
      },
      {
        title: 'Threat Intel',
        description: 'MISP, feeds, IOC sources',
        icon: Target,
        href: '/settings?tab=ti',
      },
      {
        title: 'Webhooks',
        description: 'Custom enrichment endpoints',
        icon: Webhook,
        href: '/settings?tab=webhooks',
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
        href: '/settings?tab=opensearch',
      },
      {
        title: 'Health Monitoring',
        description: 'Thresholds & alerting',
        icon: Activity,
        href: '/settings?tab=health',
      },
      {
        title: 'Queue Settings',
        description: 'Push mode queue config',
        icon: HardDrive,
        href: '/settings?tab=queue',
      },
      {
        title: 'Backup & Restore',
        description: 'Export/import configuration',
        icon: HardDrive,
        href: '/settings?tab=backup',
      },
      {
        title: 'Audit Log',
        description: 'View system audit trail',
        icon: ScrollText,
        href: '/settings/audit',
        permission: 'view_audit',
      },
      {
        title: 'System Logs',
        description: 'View application logs',
        icon: FileText,
        href: '/settings/system-logs',
        permission: 'view_audit',
      },
    ],
  },
]

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
    <Link to={category.href}>
      <Card className="card-interactive cursor-pointer hover:border-primary/50">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="p-2 bg-primary/10 rounded-lg w-fit">
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
