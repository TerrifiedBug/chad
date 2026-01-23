import { formatDistanceToNow, format } from 'date-fns'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

interface RelativeTimeProps {
  date: string | Date
  className?: string
}

export function RelativeTime({ date, className }: RelativeTimeProps) {
  const dateObj = typeof date === 'string' ? new Date(date) : date
  const relative = formatDistanceToNow(dateObj, { addSuffix: true })
  const full = format(dateObj, "MMM d, yyyy h:mm:ss a '(Local)'")

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={className}>{relative}</span>
      </TooltipTrigger>
      <TooltipContent>
        <span className="font-mono text-xs">{full}</span>
      </TooltipContent>
    </Tooltip>
  )
}
