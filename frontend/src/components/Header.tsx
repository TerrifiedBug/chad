import { useAuth } from '@/hooks/use-auth'
import { ThemeToggle } from '@/components/ThemeToggle'
import { Button } from '@/components/ui/button'

export function Header() {
  const { isAuthenticated, logout } = useAuth()

  return (
    <header className="border-b">
      <div className="container flex h-16 items-center justify-between px-4">
        <h1 className="text-xl font-bold">CHAD</h1>
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
