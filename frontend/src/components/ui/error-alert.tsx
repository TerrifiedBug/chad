import { cn } from '@/lib/utils'
import { AlertCircle } from 'lucide-react'

interface ErrorAlertProps {
  message: string
  className?: string
}

export function ErrorAlert({ message, className }: ErrorAlertProps) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className={cn('flex items-center gap-2 bg-destructive/10 text-destructive text-sm p-4 rounded-md', className)}
    >
      <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
      {message}
    </div>
  )
}
