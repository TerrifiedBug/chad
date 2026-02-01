import { cn } from '@/lib/utils'
import { AlertCircle, RefreshCw } from 'lucide-react'
import { Button } from './button'

interface ErrorAlertProps {
  message: string
  className?: string
  onRetry?: () => void
  retryLabel?: string
}

export function ErrorAlert({ message, className, onRetry, retryLabel = 'Retry' }: ErrorAlertProps) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className={cn('flex items-center gap-2 bg-destructive/10 text-destructive text-sm p-4 rounded-md', className)}
    >
      <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <span className="flex-1">{message}</span>
      {onRetry && (
        <Button
          variant="ghost"
          size="sm"
          onClick={onRetry}
          className="h-7 px-2 text-destructive hover:text-destructive hover:bg-destructive/20"
        >
          <RefreshCw className="h-3 w-3 mr-1" />
          {retryLabel}
        </Button>
      )}
    </div>
  )
}
