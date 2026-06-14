import type { ComponentType } from 'react'
import { useParams, Navigate } from 'react-router-dom'
import { PageHeader } from '@/components/PageHeader'
import SettingsContent from '@/pages/Settings'
import UsersPage from '@/pages/Users'
import AuditLogPage from '@/pages/AuditLog'
import SystemLogsPage from '@/pages/SystemLogs'
import SsoSettings from '@/pages/settings/SsoSettings'
import { findSettingsNavItem } from '@/config/settingsNav'

/**
 * One settings section, addressed by its own route (/settings/<section>).
 *
 * Sections backed by a dedicated full page render that page directly (it owns
 * its header). The remaining "inline" sections are rendered by the Settings
 * mega-page, driven by the route's section id, wrapped in a section header.
 */
const COMPONENT_SECTIONS: Record<string, ComponentType> = {
  users: UsersPage,
  audit: AuditLogPage,
  'system-logs': SystemLogsPage,
  sso: SsoSettings,
}

export default function SettingsSection() {
  const { section = 'general' } = useParams<{ section: string }>()
  const item = findSettingsNavItem(section)

  // Unknown section → bounce back to the overview.
  if (!item) return <Navigate to="/settings" replace />

  const Dedicated = COMPONENT_SECTIONS[section]
  if (Dedicated) return <Dedicated />

  return (
    <div className="space-y-6">
      <PageHeader title={item.label} description={item.description} />
      <SettingsContent activeTab={section} />
    </div>
  )
}
