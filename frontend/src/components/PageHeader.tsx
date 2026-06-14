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
  /**
   * Optional VF-style meta row: mono 11px stats separated by a centered dot.
   * Strings/numbers are joined with the dot separator; pass nodes to render
   * custom content. Additive — existing callers don't set it.
   */
  meta?: React.ReactNode[]
  children?: React.ReactNode
  className?: string
}

export function PageHeader({
  title,
  description,
  badge,
  actions,
  breadcrumb,
  meta,
  children,
  className,
}: PageHeaderProps) {
  const metaItems = meta?.filter((m) => m !== null && m !== undefined && m !== '')

  return (
    <div className={cn('space-y-1', className)}>
      {breadcrumb && breadcrumb.length > 0 && (
        <Breadcrumb items={breadcrumb} className="mb-2" />
      )}

      {/* VF console: items-end with a hairline bottom border. */}
      <div className="flex items-end justify-between gap-4 border-b border-line pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            {/* 22px mono, tight tracking. title stays ReactNode for callers
                that pass composed content. */}
            <h1 className="font-mono text-[22px] font-semibold leading-tight tracking-tight">
              {title}
            </h1>
            {badge && (
              <Badge variant={badge.variant || 'secondary'}>{badge.label}</Badge>
            )}
          </div>
          {description && (
            <p className="text-[13px] text-fg-2">{description}</p>
          )}
          {metaItems && metaItems.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 pt-0.5">
              {metaItems.map((item, index) => (
                <span key={index} className="flex items-center gap-2">
                  {index > 0 && <span className="text-fg-3" aria-hidden>·</span>}
                  <span className="vf-meta text-fg-2">{item}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        {actions && (
          <div className="flex flex-shrink-0 items-center gap-2">
            {Array.isArray(actions) ? (
              actions.map((action, index) => {
                const Icon = action.icon
                const buttonContent = (
                  <>
                    {Icon && <Icon className="mr-2 h-4 w-4" />}
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
