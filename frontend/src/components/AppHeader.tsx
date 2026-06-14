import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useVersion } from '@/hooks/use-version'
import { useTheme } from '@/hooks/use-theme'
import { NotificationBell } from '@/components/NotificationBell'
import { EnvironmentSelector } from '@/components/EnvironmentSelector'
import { TeamSwitcher } from '@/components/TeamSwitcher'
import { AboutDialog } from '@/components/AboutDialog'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { LogOut, Key, Lock, User, Info, Menu, Sun, Moon, Monitor, Search } from 'lucide-react'

interface AppHeaderProps {
  onMobileMenuToggle?: () => void
  showMobileMenu?: boolean
  railExpanded?: boolean
}

// Get user initial from email or username
function getUserInitial(email: string): string {
  // Try to get first letter of the part before @
  const name = email.split('@')[0]
  return name.charAt(0).toUpperCase()
}

// Humanise a route segment into a breadcrumb label (kebab/uuid-aware).
function humaniseSegment(segment: string): string {
  // Leave obvious ids (uuids / long hex / numeric) untouched-ish.
  if (/^[0-9a-f]{8}-/.test(segment) || /^\d+$/.test(segment)) {
    return segment.length > 10 ? segment.slice(0, 8) + '…' : segment
  }
  return segment
    .split('-')
    .map((w) => (w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(' ')
}

// Open the existing CommandPalette by dispatching the ⌘K event it listens for.
// Keeps CommandPalette self-contained (no prop API change).
function openCommandPalette() {
  window.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true })
  )
}

export function AppHeader({ onMobileMenuToggle, showMobileMenu, railExpanded = true }: AppHeaderProps) {
  const { isAuthenticated, user, logout, hasPermission } = useAuth()
  const { updateAvailable } = useVersion()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const [showAboutDialog, setShowAboutDialog] = useState(false)

  // Route-derived breadcrumb segments ('/'-separated, last one bold).
  const segments = location.pathname.split('/').filter(Boolean)
  const crumbs = segments.length === 0 ? ['Dashboard'] : segments.map(humaniseSegment)

  const cycleTheme = () => {
    if (theme === 'light') setTheme('dark')
    else if (theme === 'dark') setTheme('system')
    else setTheme('light')
  }

  const ThemeIcon = theme === 'dark' ? Moon : theme === 'light' ? Sun : Monitor

  return (
    <>
      <header className="sticky top-0 z-50 h-[52px] border-b border-line bg-bg-1 flex">
        {/* Spacer to align with sidebar - hidden on mobile */}
        <div
          className={cn(
            'hidden md:block transition-all duration-200 flex-shrink-0',
            railExpanded ? 'w-[200px]' : 'w-14'
          )}
        />

        {/* Main header area */}
        <div className="flex-1 flex h-full items-center justify-between gap-4 px-4">
          <div className="flex min-w-0 items-center gap-3">
            {/* Mobile menu button */}
            {isAuthenticated && showMobileMenu !== undefined && (
              <Button
                variant="ghost"
                size="icon"
                className="md:hidden"
                onClick={onMobileMenuToggle}
                aria-label="Toggle navigation menu"
              >
                <Menu className="h-5 w-5" />
              </Button>
            )}

            {/* Route-derived breadcrumbs (mono, '/'-separated, last bold). */}
            <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 truncate">
              {crumbs.map((crumb, i) => (
                <span key={i} className="flex items-center gap-1.5">
                  {i > 0 && <span className="text-fg-3" aria-hidden>/</span>}
                  <span
                    className={cn(
                      'vf-mono-sm truncate',
                      i === crumbs.length - 1 ? 'font-semibold text-fg' : 'text-fg-2'
                    )}
                  >
                    {crumb}
                  </span>
                </span>
              ))}
            </nav>
          </div>

          {/* Center ⌘K search affordance, wired to the existing CommandPalette. */}
          {isAuthenticated && (
            <button
              type="button"
              onClick={openCommandPalette}
              aria-label="Search (Command+K)"
              className="hidden md:flex h-7 min-w-[280px] items-center gap-2 rounded-[3px] border border-line bg-bg-2 px-2.5 text-fg-3 transition-colors hover:border-line-2 hover:text-fg-2"
            >
              <Search className="h-3.5 w-3.5" />
              <span className="vf-mono-xs flex-1 text-left">Search…</span>
              <kbd className="vf-mono-xs rounded-[2px] border border-line px-1 text-fg-3">⌘K</kbd>
            </button>
          )}

          <div className="flex items-center gap-1">
            {/* Team picker (VF parity) then the active-environment selector —
                env scopes which deployment state you view and which env deploys
                target (X-CHAD-Environment). */}
            {isAuthenticated && <TeamSwitcher />}
            {isAuthenticated && <EnvironmentSelector />}
            {isAuthenticated && (
              <Button
                variant="ghost"
                size="icon"
                onClick={cycleTheme}
                aria-label={`Current theme: ${theme}. Click to change.`}
              >
                <ThemeIcon className="h-4 w-4" />
              </Button>
            )}
            {isAuthenticated && <NotificationBell />}

            {isAuthenticated && user && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="rounded-[3px] focus-visible:ring-0 focus-visible:ring-offset-0">
                    {/* VF: 24px squared avatar with mono initials. */}
                    <div className="h-6 w-6 rounded-[3px] bg-accent-brand-soft flex items-center justify-center text-accent-brand font-mono text-[12px] font-semibold">
                      {getUserInitial(user.email)}
                    </div>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>
                    <div className="flex flex-col">
                      <span className="font-medium">{user.email}</span>
                      <span className="text-xs text-muted-foreground capitalize">
                        {user.role} {user.auth_method === 'sso' && '(SSO)'}
                      </span>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => navigate('/account')}>
                    <User className="mr-2 h-4 w-4" />
                    Account
                  </DropdownMenuItem>
                  {hasPermission('manage_api_keys') && (
                    <DropdownMenuItem onClick={() => navigate('/settings/api-keys')}>
                      <Key className="mr-2 h-4 w-4" />
                      API Keys
                    </DropdownMenuItem>
                  )}
                  {user.auth_method === 'local' && (
                    <DropdownMenuItem onClick={() => navigate('/change-password')}>
                      <Lock className="mr-2 h-4 w-4" />
                      Change Password
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => setShowAboutDialog(true)}>
                    <Info className="mr-2 h-4 w-4" />
                    About CHAD
                    {updateAvailable && (
                      <span className="ml-auto h-2 w-2 rounded-full rounded-dot bg-red-500" />
                    )}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={logout}>
                    <LogOut className="mr-2 h-4 w-4" />
                    Logout
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
      </header>

      <AboutDialog open={showAboutDialog} onOpenChange={setShowAboutDialog} />
    </>
  )
}
