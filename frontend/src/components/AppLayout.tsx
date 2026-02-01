import { useState, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Header } from '@/components/Header'
import { KeyboardShortcutsHelp } from '@/components/KeyboardShortcutsHelp'
import { useKeyboardShortcuts } from '@/hooks/use-keyboard-shortcuts'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false)

  const focusSearch = useCallback(() => {
    // Try to find and focus a search input on the page
    const searchInput = document.querySelector<HTMLInputElement>(
      'input[type="search"], input[placeholder*="Search"], input[placeholder*="search"]'
    )
    if (searchInput) {
      searchInput.focus()
      searchInput.select()
    }
  }, [])

  const refreshPage = useCallback(() => {
    // Navigate to the same route to trigger a refresh
    // This will cause React Query or useEffect hooks to re-fetch data
    navigate(location.pathname + location.search, { replace: true })
    // Also dispatch a custom event that pages can listen for
    window.dispatchEvent(new CustomEvent('app:refresh'))
  }, [navigate, location.pathname, location.search])

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
    ],
  })

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="px-6 py-8 mx-auto max-w-screen-2xl">
        {children}
      </main>
      <KeyboardShortcutsHelp
        open={showShortcutsHelp}
        onOpenChange={setShowShortcutsHelp}
      />
    </div>
  )
}
