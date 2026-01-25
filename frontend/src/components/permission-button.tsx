import { Button } from '@/components/ui/button'
import { useAuth } from '@/hooks/use-auth'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { ReactNode } from 'react'

interface PermissionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  permission?: string
  children: ReactNode
}

export function PermissionButton({
  permission,
  children,
  disabled,
  onClick,
  ...props
}: PermissionButtonProps) {
  const { hasPermission } = useAuth()
  const hasAccess = permission ? hasPermission(permission) : true
  const isDisabled = disabled || !hasAccess

  const button = (
    <Button
      {...props}
      disabled={isDisabled}
      onClick={hasAccess ? onClick : undefined}
    >
      {children}
    </Button>
  )

  // If disabled due to permissions, show tooltip
  if (!hasAccess) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-block">{button}</span>
          </TooltipTrigger>
          <TooltipContent>
            <p>You do not have permission to perform this action</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
  }

  return button
}
