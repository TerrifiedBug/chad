import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { authApi, SsoStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ThemeToggle } from '@/components/ThemeToggle'
import { Loader2 } from 'lucide-react'

export default function LoginPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { login, isAuthenticated } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [ssoStatus, setSsoStatus] = useState<SsoStatus | null>(null)
  const [ssoLoading, setSsoLoading] = useState(true)

  // Check for SSO error in URL params
  useEffect(() => {
    const ssoError = searchParams.get('sso_error')
    if (ssoError) {
      setError(ssoError)
      // Clean up URL
      window.history.replaceState({}, '', '/login')
    }
  }, [searchParams])

  // Load SSO status
  useEffect(() => {
    const loadSsoStatus = async () => {
      try {
        const status = await authApi.getSsoStatus()
        setSsoStatus(status)
      } catch {
        // SSO not available, that's fine
        setSsoStatus({ enabled: false, configured: false, provider_name: 'SSO' })
      } finally {
        setSsoLoading(false)
      }
    }
    loadSsoStatus()
  }, [])

  // Redirect if already authenticated
  if (isAuthenticated) {
    navigate('/', { replace: true })
    return null
  }

  const handleSsoLogin = () => {
    // Redirect to SSO login endpoint
    window.location.href = authApi.getSsoLoginUrl()
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl">CHAD</CardTitle>
          <CardDescription>
            Cyber Hunting And Detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <div className="text-destructive text-sm">{error}</div>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>

          {/* SSO Login */}
          {ssoLoading ? (
            <div className="mt-6 pt-6 border-t flex items-center justify-center">
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            </div>
          ) : ssoStatus?.enabled && ssoStatus?.configured ? (
            <div className="mt-6 pt-6 border-t">
              <div className="relative mb-4">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">Or</span>
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={handleSsoLogin}
              >
                Sign in with {ssoStatus.provider_name}
              </Button>
            </div>
          ) : null}

          <div className="mt-6 pt-6 border-t flex items-center justify-center">
            <ThemeToggle />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
