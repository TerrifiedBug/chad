import { useEffect, useCallback } from 'react'
import { IndexPattern } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { X, Settings, Table2, Key } from 'lucide-react'

export type PanelTab = 'settings' | 'mappings' | 'endpoint'

interface IndexPatternPanelProps {
  pattern: IndexPattern | null
  isNew: boolean
  isOpen: boolean
  activeTab: PanelTab
  onClose: () => void
  onTabChange: (tab: PanelTab) => void
  onSave?: (data: Partial<IndexPattern>) => Promise<void>
  onDelete?: () => void
}

export function IndexPatternPanel({
  pattern,
  isNew,
  isOpen,
  activeTab,
  onClose,
  onTabChange,
}: IndexPatternPanelProps) {
  // Handle escape key to close panel
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    },
    [isOpen, onClose]
  )

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  const title = isNew
    ? 'Create Index Pattern'
    : pattern?.name || 'Index Pattern'

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        side="right"
        className="w-full sm:w-[500px] sm:max-w-[500px] p-0 flex flex-col"
      >
        {/* Header */}
        <SheetHeader className="px-6 py-4 border-b flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <SheetTitle className="text-lg font-semibold">
                {title}
              </SheetTitle>
              {pattern && !isNew && (
                <Badge
                  variant={pattern.mode === 'push' ? 'default' : 'secondary'}
                  className="text-xs"
                >
                  {pattern.mode === 'push' ? 'Push' : 'Pull'}
                </Badge>
              )}
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              className="h-8 w-8"
              aria-label="Close panel"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </SheetHeader>

        {/* Tabs */}
        <Tabs
          value={activeTab}
          onValueChange={(value) => onTabChange(value as PanelTab)}
          className="flex-1 flex flex-col overflow-hidden"
        >
          <TabsList className="mx-6 mt-4 grid w-auto grid-cols-3">
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span className="hidden sm:inline">Settings</span>
            </TabsTrigger>
            <TabsTrigger
              value="mappings"
              className="flex items-center gap-2"
              disabled={isNew}
            >
              <Table2 className="h-4 w-4" />
              <span className="hidden sm:inline">Mappings</span>
            </TabsTrigger>
            <TabsTrigger
              value="endpoint"
              className="flex items-center gap-2"
              disabled={isNew}
            >
              <Key className="h-4 w-4" />
              <span className="hidden sm:inline">Endpoint</span>
            </TabsTrigger>
          </TabsList>

          {/* Tab Contents */}
          <div className="flex-1 overflow-y-auto px-6 py-4">
            <TabsContent value="settings" className="mt-0 h-full">
              {/* SettingsTab placeholder - will be implemented in Phase 2 */}
              <div className="text-sm text-muted-foreground">
                Settings tab content (Phase 2)
              </div>
            </TabsContent>

            <TabsContent value="mappings" className="mt-0 h-full">
              {/* FieldMappingsTab placeholder - will be implemented in Phase 3 */}
              <div className="text-sm text-muted-foreground">
                Field mappings tab content (Phase 3)
              </div>
            </TabsContent>

            <TabsContent value="endpoint" className="mt-0 h-full">
              {/* EndpointTab placeholder - will be implemented in Phase 4 */}
              <div className="text-sm text-muted-foreground">
                Endpoint tab content (Phase 4)
              </div>
            </TabsContent>
          </div>
        </Tabs>
      </SheetContent>
    </Sheet>
  )
}
