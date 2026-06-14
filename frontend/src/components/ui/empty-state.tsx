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

  // VF console glyph-tile: a 64px bordered tile holds the icon, a mono title,
  // helper copy, and `$`-prompt helper lines for the tips. Same props as
  // before (icon/title/description/action/tips/className) so every call site
  // is untouched.
  return (
    <div className={cn('flex flex-col items-center justify-center py-12 text-center', className)}>
      {icon && (
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-[3px] border border-line bg-bg-2 text-fg-2">
          {icon}
        </div>
      )}
      <h3 className="font-mono text-[15px] font-semibold tracking-tight text-fg">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-fg-2">{description}</p>}
      {renderAction()}
      {tips && tips.length > 0 && (
        <div className="mt-6 max-w-md text-left">
          <p className="vf-thead mb-2 text-fg-3">Tips</p>
          <ul className="space-y-1">
            {tips.map((tip, index) => (
              <li key={index} className="flex items-start gap-2 font-mono text-[12px] text-fg-2">
                <span className="select-none text-accent-brand">$</span>
                <span>{tip}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
