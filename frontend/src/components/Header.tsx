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
import { cn } from '@/lib/utils'
import { ChevronDown, LogOut, Settings, Key, Lock, User } from 'lucide-react'

const navItems = [
  { href: '/', label: 'Dashboard', exact: true },
  { href: '/alerts', label: 'Alerts' },
  { href: '/live', label: 'Live' },
  { href: '/rules', label: 'Rules' },
  { href: '/correlation', label: 'Correlation' },
  { href: '/sigmahq', label: 'SigmaHQ', permission: 'manage_sigmahq' },
  { href: '/attack', label: 'ATT&CK' },
  { href: '/index-patterns', label: 'Index Patterns', permission: 'manage_settings' },
  { href: '/field-mappings', label: 'Field Mappings', permission: 'manage_settings' },
  { href: '/health', label: 'Health', permission: 'manage_settings' },
  { href: '/settings', label: 'Settings', permission: 'manage_settings' },
]

export function Header() {
  const { isAuthenticated, user, logout, hasPermission } = useAuth()
  const { version, updateAvailable } = useVersion()
  const location = useLocation()
  const navigate = useNavigate()

  // Filter nav items based on permissions
  const visibleNavItems = navItems.filter(item => {
    if (!item.permission) return true
    return hasPermission(item.permission)
  })

  return (
    <header className="border-b">
      <div className="flex h-16 w-full items-center justify-between px-6">
        <div className="flex items-center gap-8">
          <Link to="/" className="text-xl font-bold flex items-baseline gap-2">
            CHAD
            {version && (
              <span className="text-xs text-muted-foreground font-normal">
                v{version}
              </span>
            )}
          </Link>
          {isAuthenticated && (
            <nav className="flex items-center gap-6">
              {visibleNavItems.map((item) => {
                const isActive = 'exact' in item && item.exact
                  ? location.pathname === item.href
                  : location.pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    className={cn(
                      'text-sm font-medium transition-colors hover:text-primary flex items-center',
                      isActive ? 'text-foreground' : 'text-muted-foreground'
                    )}
                  >
                    {item.label}
                    {item.href === '/settings' && updateAvailable && (
                      <span className="ml-1 h-2 w-2 rounded-full bg-red-500" />
                    )}
                  </Link>
                )
              })}
            </nav>
          )}
        </div>
        <div className="flex items-center gap-4">
          {isAuthenticated && <NotificationBell />}
          {isAuthenticated && user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="gap-1">
                  {user.email}
                  <ChevronDown className="h-4 w-4" />
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
