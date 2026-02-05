import { FileCode, ExternalLink, FileText, LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

type RuleSource = 'sigmahq' | 'misp' | 'user'

const SOURCE_CONFIG: Record<RuleSource, { icon: LucideIcon; color: string; label: string }> = {
  sigmahq: { icon: FileCode, color: 'text-blue-500', label: 'SigmaHQ' },
  misp: { icon: ExternalLink, color: 'text-purple-500', label: 'MISP' },
  user: { icon: FileText, color: 'text-muted-foreground', label: 'User' },
}

interface SourceIconProps {
  source: RuleSource | string
  showLabel?: boolean
  size?: 'sm' | 'default'
  className?: string
}

export function SourceIcon({ source, showLabel = true, size = 'default', className }: SourceIconProps) {
  const config = SOURCE_CONFIG[source as RuleSource] || SOURCE_CONFIG.user
  const Icon = config.icon
  const iconSize = size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4'

  return (
    <div className={cn('flex items-center gap-1.5', className)}>
      <Icon className={cn(iconSize, config.color)} />
      {showLabel && <span className="text-xs text-muted-foreground">{config.label}</span>}
    </div>
  )
}
