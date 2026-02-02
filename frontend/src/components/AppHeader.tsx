import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useVersion } from '@/hooks/use-version'
import { ThemeToggle } from '@/components/ThemeToggle'
import { NotificationBell } from '@/components/NotificationBell'
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
import { LogOut, Settings, Key, Lock, User, Info, Menu } from 'lucide-react'

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

export function AppHeader({ onMobileMenuToggle, showMobileMenu, railExpanded = true }: AppHeaderProps) {
  const { isAuthenticated, user, logout, hasPermission } = useAuth()
  const { version, updateAvailable } = useVersion()
  const navigate = useNavigate()
  const [showAboutDialog, setShowAboutDialog] = useState(false)

  return (
    <>
      <header className="sticky top-0 z-50 h-14 bg-background flex">
        {/* Spacer to align with sidebar - hidden on mobile */}
        <div
          className={cn(
            'hidden md:block transition-all duration-200 flex-shrink-0',
            railExpanded ? 'w-[200px]' : 'w-14'
          )}
        />

        {/* Main header area */}
        <div className="flex-1 flex h-full items-center justify-between px-4">
          <div className="flex items-center gap-3">
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

            {/* Logo - always visible in main header area */}
            <Link to="/" className="flex items-baseline gap-2">
              <span className="text-xl font-bold">CHAD</span>
              {version && (
                <span className="text-xs text-muted-foreground">v{version}</span>
              )}
            </Link>
          </div>

          <div className="flex items-center gap-2">
            {isAuthenticated && <NotificationBell />}

            {isAuthenticated && user && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="rounded-full h-9 w-9">
                    <div className="h-8 w-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground font-medium">
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
                  {hasPermission('manage_settings') && (
                    <DropdownMenuItem onClick={() => navigate('/settings')}>
                      <Settings className="mr-2 h-4 w-4" />
                      Settings
                    </DropdownMenuItem>
                  )}
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
                      <span className="ml-auto h-2 w-2 rounded-full bg-red-500" />
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

            <ThemeToggle />
          </div>
        </div>
      </header>

      <AboutDialog open={showAboutDialog} onOpenChange={setShowAboutDialog} />
    </>
  )
}
