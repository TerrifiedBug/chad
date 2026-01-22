import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { ThemeToggle } from '@/components/ThemeToggle'
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
import { ChevronDown, LogOut, Settings, Key, Lock } from 'lucide-react'

const navItems = [
  { href: '/', label: 'Dashboard', exact: true },
  { href: '/alerts', label: 'Alerts' },
  { href: '/rules', label: 'Rules' },
  { href: '/sigmahq', label: 'SigmaHQ' },
  { href: '/index-patterns', label: 'Index Patterns' },
  { href: '/settings', label: 'Settings', adminOnly: true },
]

export function Header() {
  const { isAuthenticated, isAdmin, user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  // Filter nav items based on role
  const visibleNavItems = navItems.filter(item => !item.adminOnly || isAdmin)

  return (
    <header className="border-b">
      <div className="flex h-16 w-full items-center justify-between px-6">
        <div className="flex items-center gap-8">
          <Link to="/" className="text-xl font-bold">
            CHAD
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
                      'text-sm font-medium transition-colors hover:text-primary',
                      isActive ? 'text-foreground' : 'text-muted-foreground'
                    )}
                  >
                    {item.label}
                  </Link>
                )
              })}
            </nav>
          )}
        </div>
        <div className="flex items-center gap-4">
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
                {isAdmin && (
                  <DropdownMenuItem onClick={() => navigate('/settings')}>
                    <Settings className="mr-2 h-4 w-4" />
                    Settings
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onClick={() => navigate('/settings/api-keys')}>
                  <Key className="mr-2 h-4 w-4" />
                  API Keys
                </DropdownMenuItem>
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
