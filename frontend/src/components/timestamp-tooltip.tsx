import { format } from 'date-fns'

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
      <div title={fullDate} className="inline-block cursor-help">
        {children}
      </div>
    )
  } catch {
    return children
  }
}
