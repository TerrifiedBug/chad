// frontend/src/components/SettingsSidebar.tsx
import { useNavigate, useSearchParams } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  ChevronLeft,
  ChevronRight,
  Wrench,
  Shield,
  Bell,
  Bot,
  Globe,
  Inbox,
  Search,
  Activity,
  HardDrive,
  ArrowLeft,
} from 'lucide-react'

type SettingsSection = {
  id: string
  label: string
  icon: React.ElementType
}

const settingsSections: SettingsSection[] = [
  { id: 'general', label: 'General', icon: Wrench },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'ai', label: 'AI', icon: Bot },
  { id: 'enrichment', label: 'Enrichment', icon: Globe },
  { id: 'queue', label: 'Queue', icon: Inbox },
  { id: 'opensearch', label: 'OpenSearch', icon: Search },
  { id: 'health', label: 'Health', icon: Activity },
  { id: 'backup', label: 'Backup', icon: HardDrive },
]

interface SettingsSidebarProps {
  expanded: boolean
  onExpandedChange: (expanded: boolean) => void
}

export function SettingsSidebar({ expanded, onExpandedChange }: SettingsSidebarProps) {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'general'

  const handleSectionClick = (sectionId: string) => {
    setSearchParams({ tab: sectionId })
  }

  const handleBack = () => {
    // Navigate to previous page or dashboard
    if (window.history.length > 2) {
      navigate(-1)
    } else {
      navigate('/')
    }
  }

  const NavItem = ({ section }: { section: SettingsSection }) => {
    const active = activeTab === section.id
    const Icon = section.icon

    const content = (
      <button
        onClick={() => handleSectionClick(section.id)}
        className={cn(
          'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          'hover:bg-muted',
          active ? 'bg-muted text-foreground' : 'text-muted-foreground',
          !expanded && 'justify-center px-2'
        )}
      >
        <Icon className="h-5 w-5 flex-shrink-0" />
        {expanded && <span>{section.label}</span>}
      </button>
    )

    if (!expanded) {
      return (
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>{content}</TooltipTrigger>
          <TooltipContent side="right">{section.label}</TooltipContent>
        </Tooltip>
      )
    }

    return content
  }

  return (
    <TooltipProvider>
      <aside
        className={cn(
          'sticky top-14 flex h-[calc(100vh-3.5rem)] flex-col border-r bg-background transition-all duration-200',
          expanded ? 'w-[200px]' : 'w-14'
        )}
      >
        {/* Back button and collapse toggle */}
        <div className={cn('flex items-center p-2', expanded ? 'justify-between' : 'flex-col gap-2')}>
          {expanded ? (
            <>
              <Button
                variant="ghost"
                size="sm"
                className="gap-1"
                onClick={handleBack}
              >
                <ArrowLeft className="h-4 w-4" />
                Settings
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => onExpandedChange(!expanded)}
                aria-label="Collapse navigation"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
            </>
          ) : (
            <>
              <Tooltip delayDuration={0}>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleBack}
                  >
                    <ArrowLeft className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Back</TooltipContent>
              </Tooltip>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => onExpandedChange(!expanded)}
                aria-label="Expand navigation"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </>
          )}
        </div>

        {/* Settings sections */}
        <nav className="flex-1 space-y-1 p-2">
          {settingsSections.map((section) => (
            <NavItem key={section.id} section={section} />
          ))}
        </nav>
      </aside>
    </TooltipProvider>
  )
}
