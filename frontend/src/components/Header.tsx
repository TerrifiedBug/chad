import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { ThemeToggle } from '@/components/ThemeToggle'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const navItems = [
  { href: '/alerts', label: 'Alerts' },
  { href: '/rules', label: 'Rules' },
  { href: '/index-patterns', label: 'Index Patterns' },
]

export function Header() {
  const { isAuthenticated, logout } = useAuth()
  const location = useLocation()

  return (
    <header className="border-b">
      <div className="flex h-16 w-full items-center justify-between px-6">
        <div className="flex items-center gap-8">
          <Link to="/" className="text-xl font-bold">
            CHAD
          </Link>
          {isAuthenticated && (
            <nav className="flex items-center gap-6">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    'text-sm font-medium transition-colors hover:text-primary',
                    location.pathname.startsWith(item.href)
                      ? 'text-foreground'
                      : 'text-muted-foreground'
                  )}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          )}
        </div>
        <div className="flex items-center gap-4">
          {isAuthenticated && (
            <Button variant="ghost" size="sm" onClick={logout}>
              Logout
            </Button>
          )}
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
