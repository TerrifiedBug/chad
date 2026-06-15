// frontend/src/config/settingsNav.ts
//
// Single source of truth for the Settings navigation. Consumed by:
//  - AppRail's slide-in settings panel (VF "sidebar becomes settings nav")
//  - the SettingsHub overview tile grid
//  - the CommandPalette (settings sub-sections)
//
// Each section is its own route at /settings/<id>. Keeping one config here
// means the rail panel, the hub grid, and the palette never drift apart.
import {
  Settings2,
  Bot,
  Bell,
  Shield,
  KeyRound,
  Users,
  Building2,
  Globe,
  Target,
  Webhook,
  Database,
  Activity,
  HardDrive,
  ScrollText,
  FileText,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export type SettingsNavItem = {
  id: string
  label: string
  description: string
  icon: LucideIcon
  href: string
  permission?: string
  badge?: string
}

export type SettingsNavGroup = {
  label: string
  items: SettingsNavItem[]
}

export const settingsNavGroups: SettingsNavGroup[] = [
  {
    label: 'Configuration',
    items: [
      { id: 'general', label: 'General', description: 'Background sync, version cleanup', icon: Settings2, href: '/settings/general' },
      { id: 'ai', label: 'AI Assistant', description: 'OpenAI, Anthropic, Ollama', icon: Bot, href: '/settings/ai', badge: 'Beta' },
      { id: 'notifications', label: 'Notifications', description: 'Email, Slack, Discord webhooks', icon: Bell, href: '/settings/notifications' },
    ],
  },
  {
    label: 'Security & Access',
    items: [
      { id: 'security', label: 'Security', description: 'Sessions, 2FA, rate limiting', icon: Shield, href: '/settings/security', permission: 'manage_settings' },
      { id: 'sso', label: 'SSO & Provisioning', description: 'OIDC providers, group sync, SCIM', icon: KeyRound, href: '/settings/sso', permission: 'manage_settings' },
      { id: 'users', label: 'Users & Roles', description: 'Manage users and role permissions', icon: Users, href: '/settings/users', permission: 'manage_users' },
      { id: 'organizations', label: 'Organizations', description: 'Tenants for multi-tenant / MSSP', icon: Building2, href: '/settings/organizations', permission: 'manage_users' },
    ],
  },
  {
    label: 'Enrichment & Intelligence',
    items: [
      { id: 'geoip', label: 'GeoIP', description: 'MaxMind database updates', icon: Globe, href: '/settings/geoip' },
      { id: 'ti', label: 'Threat Intel', description: 'MISP, feeds, IOC sources', icon: Target, href: '/settings/ti' },
      { id: 'webhooks', label: 'Webhooks', description: 'Custom enrichment endpoints', icon: Webhook, href: '/settings/webhooks', badge: 'New' },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'opensearch', label: 'OpenSearch', description: 'Connection status & settings', icon: Database, href: '/settings/opensearch' },
      { id: 'health', label: 'Health Monitoring', description: 'Thresholds & alerting', icon: Activity, href: '/settings/health' },
      { id: 'queue', label: 'Queue Settings', description: 'Push mode queue config', icon: HardDrive, href: '/settings/queue' },
      { id: 'backup', label: 'Backup & Restore', description: 'Export/import configuration', icon: HardDrive, href: '/settings/backup' },
      { id: 'audit', label: 'Audit Log', description: 'View system audit trail', icon: ScrollText, href: '/settings/audit', permission: 'view_audit' },
      { id: 'system-logs', label: 'System Logs', description: 'View application logs', icon: FileText, href: '/settings/system-logs', permission: 'view_audit' },
    ],
  },
]

// Flat list of every settings section.
export const allSettingsNavItems: SettingsNavItem[] = settingsNavGroups.flatMap(
  (g) => g.items
)

// Valid section ids (used by the route page to reject unknown sections).
export const settingsSectionIds: string[] = allSettingsNavItems.map((i) => i.id)

export function findSettingsNavItem(id: string): SettingsNavItem | undefined {
  return allSettingsNavItems.find((i) => i.id === id)
}
