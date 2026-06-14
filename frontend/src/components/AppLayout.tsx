// frontend/src/components/AppLayout.tsx
import { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useActiveEnvironmentId } from '@/stores/environment-store'
import { cn } from '@/lib/utils'
import { AppHeader } from '@/components/AppHeader'
import { OpenSearchBanner } from '@/components/OpenSearchBanner'
import { AppRail } from '@/components/AppRail'
import { CommandPalette } from '@/components/CommandPalette'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { DeployProgress } from '@/components/rules/DeployProgress'
import { useDeployProgressWs } from '@/components/rules/use-deploy-progress-ws'
import { KeyboardShortcutsHelp } from '@/components/KeyboardShortcutsHelp'
import { useKeyboardShortcuts } from '@/hooks/use-keyboard-shortcuts'
import { useLocalStorage } from '@/hooks/use-local-storage'
import { useMediaQuery } from '@/hooks/use-media-query'
import { useNavStatus } from '@/hooks/use-nav-status'
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
  const { alertCount, healthStatus } = useNavStatus()

  // Subscribe to bulk-deploy progress over /ws so the persistent panel works
  // even if the user navigates away from the Rules page mid-deploy.
  useDeployProgressWs()

  // On environment switch, redirect out of any resource *detail* route back to
  // its list (e.g. /rules/:id -> /rules). A detail view shows one env's
  // deployment state; after switching envs that view would be stale / may not
  // even exist in the new env, so we bounce to the list which re-fetches scoped
  // to the now-active env. We track the prior id in a ref so the redirect fires
  // only on an actual change, never on first mount.
  const activeEnvironmentId = useActiveEnvironmentId()
  const prevEnvironmentIdRef = useRef(activeEnvironmentId)
  useEffect(() => {
    const prev = prevEnvironmentIdRef.current
    if (prev !== null && prev !== activeEnvironmentId) {
      // Section detail routes look like /{section}/{id}. The environments pages
      // are intentionally not env-scoped, so they're excluded.
      const match = location.pathname.match(
        /^\/(rules|alerts|index-patterns|correlation)\/([^/]+)$/
      )
      if (match && match[2] !== 'new') {
        navigate(`/${match[1]}`, { replace: true })
      }
    }
    prevEnvironmentIdRef.current = activeEnvironmentId
  }, [activeEnvironmentId, location.pathname, navigate])

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

  return (
    <div className="min-h-screen bg-background">
      <AppHeader
        onMobileMenuToggle={() => setMobileMenuOpen(true)}
        showMobileMenu={isMobile}
        railExpanded={railExpanded}
      />
      <OpenSearchBanner />

      {/* Desktop sidebar (fixed position) */}
      {!isMobile && (
        <AppRail
          expanded={railExpanded}
          onExpandedChange={setRailExpanded}
          alertCount={alertCount}
          healthStatus={healthStatus}
        />
      )}

      {/* Mobile sidebar (Sheet) */}
      {isMobile && (
        <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
          <SheetContent side="left" className="w-[200px] p-0">
            <AppRail expanded={true} onExpandedChange={() => {}} alertCount={alertCount} healthStatus={healthStatus} />
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
          {/* Keyed by route so navigating away from a crashed page resets the boundary. */}
          <ErrorBoundary key={location.pathname}>
            {children}
          </ErrorBoundary>
        </div>
      </main>

      <KeyboardShortcutsHelp
        open={showShortcutsHelp}
        onOpenChange={setShowShortcutsHelp}
      />

      <CommandPalette />

      {/* Persistent bulk-deploy progress panel (renders only during a deploy). */}
      <DeployProgress />
    </div>
  )
}
