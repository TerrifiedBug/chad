import { Link } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { ChevronRight, Lock } from 'lucide-react'
import { settingsNavGroups, type SettingsNavItem } from '@/config/settingsNav'

/**
 * Settings overview at /settings — a tile grid of every section, driven by the
 * shared settingsNav config. Each tile links to its own /settings/<id> route.
 * The left rail simultaneously slides into the matching settings nav panel.
 */
function SettingsCategoryCard({
  category,
  hasPermission,
}: {
  category: SettingsNavItem
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
          <div className="p-2 bg-muted rounded-lg w-fit">
            <Icon className="h-5 w-5 text-muted-foreground" />
          </div>
          <CardTitle className="text-base mt-3">{category.label}</CardTitle>
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
          <CardTitle className="text-base mt-3">{category.label}</CardTitle>
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
      <PageHeader title="Settings" description="Configure your CHAD instance" />

      {settingsNavGroups.map((group) => (
        <div key={group.label}>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-4">
            {group.label}
          </h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {group.items.map((category) => (
              <SettingsCategoryCard
                key={category.id}
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
