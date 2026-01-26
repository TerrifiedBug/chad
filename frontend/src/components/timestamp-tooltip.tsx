import { format } from 'date-fns'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
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
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-block cursor-help">{children}</span>
          </TooltipTrigger>
          <TooltipContent>
            <p>{fullDate}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
  } catch {
    return children
  }
}
