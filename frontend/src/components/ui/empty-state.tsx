import { cn } from '@/lib/utils'
import { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Link } from 'react-router-dom'
import React from 'react'

interface EmptyStateAction {
  label: string
  href?: string
  onClick?: () => void
  icon?: LucideIcon
  variant?: 'default' | 'outline' | 'ghost'
}

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode | EmptyStateAction
  tips?: string[]
  className?: string
}

function isEmptyStateAction(action: unknown): action is EmptyStateAction {
  return typeof action === 'object' && action !== null && 'label' in action
}

export function EmptyState({ icon, title, description, action, tips, className }: EmptyStateProps) {
  const renderAction = () => {
    if (!action) return null

    // Check if action is an EmptyStateAction object (has label property)
    if (isEmptyStateAction(action)) {
      const { label, href, onClick, icon: Icon, variant = 'default' } = action

      const buttonContent = (
        <>
          {Icon && <Icon className="h-4 w-4 mr-2" />}
          {label}
        </>
      )

      if (href) {
        return (
          <div className="mt-4">
            <Button variant={variant} asChild>
              <Link to={href}>{buttonContent}</Link>
            </Button>
          </div>
        )
      }

      return (
        <div className="mt-4">
          <Button variant={variant} onClick={onClick}>
            {buttonContent}
          </Button>
        </div>
      )
    }

    // Otherwise, render as ReactNode
    return <div className="mt-4">{action}</div>
  }

  return (
    <div className={cn('flex flex-col items-center justify-center py-12 text-center', className)}>
      {icon && <div className="mb-4 text-muted-foreground">{icon}</div>}
      <h3 className="text-lg font-medium">{title}</h3>
      {description && <p className="mt-1 text-sm text-muted-foreground max-w-sm">{description}</p>}
      {renderAction()}
      {tips && tips.length > 0 && (
        <div className="mt-6 text-left max-w-md">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Tips</p>
          <ul className="space-y-1">
            {tips.map((tip, index) => (
              <li key={index} className="text-sm text-muted-foreground flex items-start gap-2">
                <span className="text-primary">•</span>
                <span>{tip}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
