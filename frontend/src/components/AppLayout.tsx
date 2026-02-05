// frontend/src/components/AppLayout.tsx
import { useState, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { AppHeader } from '@/components/AppHeader'
import { AppRail } from '@/components/AppRail'
import { SettingsSidebar } from '@/components/SettingsSidebar'
import { KeyboardShortcutsHelp } from '@/components/KeyboardShortcutsHelp'
import { useKeyboardShortcuts } from '@/hooks/use-keyboard-shortcuts'
import { useLocalStorage } from '@/hooks/use-local-storage'
import { useMediaQuery } from '@/hooks/use-media-query'
import {
  Sheet,
  SheetContent,
} from '@/components/ui/sheet'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false)
  const [railExpanded, setRailExpanded] = useLocalStorage('rail-expanded', true)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const isMobile = useMediaQuery('(max-width: 767px)')

  // Use SettingsSidebar for settings pages (except the hub which uses AppRail)
  const useSettingsSidebar = location.pathname.startsWith('/settings') && location.pathname !== '/settings/hub'

  const focusSearch = useCallback(() => {
    const searchInput = document.querySelector<HTMLInputElement>(
      'input[type="search"], input[placeholder*="Search"], input[placeholder*="search"]'
    )
    if (searchInput) {
      searchInput.focus()
      searchInput.select()
    }
  }, [])

  const refreshPage = useCallback(() => {
    navigate(location.pathname + location.search, { replace: true })
    window.dispatchEvent(new CustomEvent('app:refresh'))
  }, [navigate, location.pathname, location.search])

  const toggleRail = useCallback(() => {
    setRailExpanded(prev => !prev)
  }, [setRailExpanded])

  useKeyboardShortcuts({
    shortcuts: [
      {
        key: '/',
        description: 'Focus search input',
        handler: focusSearch,
      },
      {
        key: '?',
        description: 'Show keyboard shortcuts',
        modifiers: { shift: true },
        handler: () => setShowShortcutsHelp(true),
      },
      {
        key: 'r',
        description: 'Refresh current page data',
        handler: refreshPage,
      },
      {
        key: '[',
        description: 'Toggle navigation rail',
        handler: toggleRail,
      },
    ],
  })

  const SidebarComponent = useSettingsSidebar ? SettingsSidebar : AppRail

  return (
    <div className="min-h-screen bg-background">
      <AppHeader
        onMobileMenuToggle={() => setMobileMenuOpen(true)}
        showMobileMenu={isMobile}
        railExpanded={railExpanded}
      />

      {/* Desktop sidebar (fixed position) */}
      {!isMobile && (
        <SidebarComponent
          expanded={railExpanded}
          onExpandedChange={setRailExpanded}
        />
      )}

      {/* Mobile sidebar (Sheet) */}
      {isMobile && (
        <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
          <SheetContent side="left" className="w-[200px] p-0">
            <SidebarComponent expanded={true} onExpandedChange={() => {}} />
          </SheetContent>
        </Sheet>
      )}

      {/* Main content - offset by sidebar width on desktop */}
      <main
        className={cn(
          'min-w-0 overflow-x-hidden px-6 py-8 transition-all duration-200',
          railExpanded ? 'md:ml-[200px]' : 'md:ml-14'
        )}
      >
        <div className="mx-auto max-w-screen-2xl">
          {children}
        </div>
      </main>

      <KeyboardShortcutsHelp
        open={showShortcutsHelp}
        onOpenChange={setShowShortcutsHelp}
      />
    </div>
  )
}
