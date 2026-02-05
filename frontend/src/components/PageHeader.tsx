import { Link } from 'react-router-dom'
import { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Breadcrumb } from '@/components/Breadcrumb'
import { cn } from '@/lib/utils'

interface PageHeaderAction {
  label: string
  icon?: LucideIcon
  onClick?: () => void
  href?: string
  variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'secondary'
  className?: string
}

interface PageHeaderBadge {
  label: string
  variant?: 'default' | 'secondary' | 'destructive' | 'outline'
}

interface BreadcrumbItem {
  label: string
  href?: string
}

interface PageHeaderProps {
  title: React.ReactNode
  description?: string
  badge?: PageHeaderBadge
  actions?: PageHeaderAction[] | React.ReactNode
  breadcrumb?: BreadcrumbItem[]
  children?: React.ReactNode
  className?: string
}

export function PageHeader({
  title,
  description,
  badge,
  actions,
  breadcrumb,
  children,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn('space-y-1', className)}>
      {breadcrumb && breadcrumb.length > 0 && (
        <Breadcrumb items={breadcrumb} className="mb-2" />
      )}

      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
            {badge && (
              <Badge variant={badge.variant || 'secondary'}>{badge.label}</Badge>
            )}
          </div>
          {description && (
            <p className="text-muted-foreground">{description}</p>
          )}
        </div>

        {actions && (
          <div className="flex items-center gap-2 flex-shrink-0">
            {Array.isArray(actions) ? (
              actions.map((action, index) => {
                const Icon = action.icon
                const buttonContent = (
                  <>
                    {Icon && <Icon className="h-4 w-4 mr-2" />}
                    {action.label}
                  </>
                )

                if (action.href) {
                  return (
                    <Button
                      key={index}
                      variant={action.variant || 'outline'}
                      asChild
                      className={action.className}
                    >
                      <Link to={action.href}>{buttonContent}</Link>
                    </Button>
                  )
                }

                return (
                  <Button
                    key={index}
                    variant={action.variant || 'outline'}
                    onClick={action.onClick}
                    className={action.className}
                  >
                    {buttonContent}
                  </Button>
                )
              })
            ) : (
              actions
            )}
          </div>
        )}
      </div>

      {children && <div className="mt-4">{children}</div>}
    </div>
  )
}
