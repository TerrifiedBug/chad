import { format } from 'date-fns'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from './ui/tooltip'

interface TimestampTooltipProps {
  timestamp: string | null
  children: React.ReactElement
}

export function TimestampTooltip({ timestamp, children }: TimestampTooltipProps) {
  if (!timestamp) return children

  try {
    const date = new Date(timestamp)
    const fullDate = format(date, 'MMM d, yyyy HH:mm:ss UTC')

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-block cursor-help">{children}</span>
        </TooltipTrigger>
        <TooltipContent>
          <p className="font-mono text-xs">{fullDate}</p>
        </TooltipContent>
      </Tooltip>
    )
  } catch {
    return children
  }
}
