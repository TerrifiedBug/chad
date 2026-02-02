import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useVersion } from '@/hooks/use-version'
import { ThemeToggle } from '@/components/ThemeToggle'
import { NotificationBell } from '@/components/NotificationBell'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { cn } from '@/lib/utils'
import { ChevronDown, LogOut, Settings, Key, Lock, User, Menu } from 'lucide-react'

type NavItem = {
  href: string
  label: string
  exact?: boolean
  permission?: string
}

const navItems: NavItem[] = [
  { href: '/', label: 'Dashboard', exact: true },
  { href: '/alerts', label: 'Alerts' },
  { href: '/rules', label: 'Rules' },
  { href: '/attack', label: 'ATT&CK' },
  { href: '/index-patterns', label: 'Index Patterns', permission: 'manage_index_config' },
  { href: '/health', label: 'Health' },
  { href: '/settings', label: 'Settings', permission: 'manage_settings' },
]

export function Header() {
  const { isAuthenticated, user, logout, hasPermission } = useAuth()
  const { version, updateAvailable } = useVersion()
  const location = useLocation()
  const navigate = useNavigate()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  // Filter nav items based on permissions
  const visibleNavItems = navItems.filter(item => {
    if (!item.permission) return true
    return hasPermission(item.permission)
  })

  const handleMobileNavClick = (href: string) => {
    navigate(href)
    setMobileMenuOpen(false)
  }

  return (
    <header className="border-b">
      <div className="flex h-16 w-full items-center justify-between px-6">
        <div className="flex items-center gap-4 md:gap-8">
          {/* Mobile menu button */}
          {isAuthenticated && (
            <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open navigation menu">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-64">
                <SheetHeader>
                  <SheetTitle>Navigation</SheetTitle>
                </SheetHeader>
                <nav className="flex flex-col gap-2 mt-6" aria-label="Mobile navigation">
                  {visibleNavItems.map((item) => {
                    const isActive = item.exact
                      ? location.pathname === item.href
                      : location.pathname.startsWith(item.href)
                    return (
                      <button
                        key={item.href}
                        onClick={() => handleMobileNavClick(item.href)}
                        aria-current={isActive ? 'page' : undefined}
                        className={cn(
                          'text-sm font-medium transition-colors hover:text-primary text-left px-2 py-2 rounded-md',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                          isActive ? 'text-foreground bg-muted' : 'text-muted-foreground'
                        )}
                      >
                        {item.label}
                        {item.href === '/settings' && updateAvailable && (
                          <span className="ml-1 inline-block h-2 w-2 rounded-full bg-red-500" aria-label="Update available" />
                        )}
                      </button>
                    )
                  })}
                </nav>
              </SheetContent>
            </Sheet>
          )}

          <Link to="/" className="text-xl font-bold flex items-baseline gap-2">
            CHAD
            {version && (
              <span className="text-xs text-muted-foreground font-normal">
                v{version}
              </span>
            )}
          </Link>

          {/* Desktop navigation */}
          {isAuthenticated && (
            <nav className="hidden md:flex items-center gap-6" aria-label="Main navigation">
              {visibleNavItems.map((item) => {
                const isActive = item.exact
                  ? location.pathname === item.href
                  : location.pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    aria-current={isActive ? 'page' : undefined}
                    className={cn(
                      'text-sm font-medium transition-colors hover:text-primary',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded-sm',
                      isActive ? 'text-foreground' : 'text-muted-foreground'
                    )}
                  >
                    {item.label}
                    {item.href === '/settings' && updateAvailable && (
                      <span className="ml-1 h-2 w-2 rounded-full bg-red-500" aria-label="Update available" />
                    )}
                  </Link>
                )
              })}
            </nav>
          )}
        </div>
        <div className="flex items-center gap-4">
          {isAuthenticated && <NotificationBell aria-label="Notifications" />}
          {isAuthenticated && user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="gap-1" aria-label={`User menu for ${user.email}`}>
                  {user.email}
                  <ChevronDown className="h-4 w-4" aria-hidden="true" />
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
  )
}
