import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { authApi, SsoStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ThemeToggle } from '@/components/ThemeToggle'
import { TwoFactorSetup } from '@/components/TwoFactorSetup'
import { Loader2, Shield } from 'lucide-react'

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
  // 2FA state
  const [requires2FA, setRequires2FA] = useState(false)
  const [twoFactorToken, setTwoFactorToken] = useState('')
  const [twoFactorCode, setTwoFactorCode] = useState('')
  // 2FA setup required state
  const [requires2FASetup, setRequires2FASetup] = useState(false)

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
      const response = await authApi.loginRaw(email, password)

      if (response.requires_2fa && response['2fa_token']) {
        setTwoFactorToken(response['2fa_token'])
        setRequires2FA(true)
      } else if (response.access_token && response.requires_2fa_setup) {
        // User logged in but needs to set up 2FA
        localStorage.setItem('chad-token', response.access_token)
        setRequires2FASetup(true)
      } else if (response.access_token) {
        await login(email, password)
        navigate('/')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handle2FASubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const response = await authApi.login2FA(twoFactorToken, twoFactorCode)
      localStorage.setItem('chad-token', response.access_token)
      window.location.href = '/'
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid 2FA code')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/50 p-4">
      <Card className="w-full max-w-md shadow-xl animate-in fade-in slide-in-from-bottom-4 duration-500">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto mb-3 p-3 rounded-full bg-primary/10 w-fit">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-3xl font-bold tracking-tight">CHAD</CardTitle>
          <CardDescription className="text-sm text-muted-foreground/80">
            Cyber Hunting And Detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Hidden TOTP field always in DOM for password manager detection */}
          {!requires2FA && (
            <input
              type="text"
              name="totp"
              autoComplete="one-time-code"
              className="sr-only"
              tabIndex={-1}
              aria-hidden="true"
            />
          )}
          {requires2FA ? (
            <form onSubmit={handle2FASubmit} className="space-y-4" autoComplete="off">
              <div className="text-center mb-4">
                <p className="text-sm text-muted-foreground">
                  Enter the 6-digit code from your authenticator app, or an 8-character backup code
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="2fa-code">Verification Code</Label>
                <Input
                  id="2fa-code"
                  name="totp"
                  type="text"
                  inputMode="numeric"
                  maxLength={8}
                  placeholder="000000"
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value.toUpperCase())}
                  className="text-center text-2xl tracking-[0.5em] placeholder:tracking-normal"
                  autoComplete="one-time-code"
                  autoFocus
                />
              </div>

              {error && (
                <div className="text-destructive text-sm">{error}</div>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={isLoading || (twoFactorCode.length !== 6 && twoFactorCode.length !== 8)}
              >
                {isLoading ? 'Verifying...' : 'Verify'}
              </Button>

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => {
                  setRequires2FA(false)
                  setTwoFactorCode('')
                  setTwoFactorToken('')
                  setError('')
                }}
              >
                Back to Login
              </Button>
            </form>
          ) : ssoStatus?.sso_only ? (
            // SSO-Only Mode: Show only SSO login
            <div className="space-y-4">
              {/* Header message */}
              <div className="text-center py-8">
                <Shield className="h-12 w-12 mx-auto mb-4 text-primary" />
                <h3 className="text-lg font-semibold mb-2">
                  SSO Authentication Required
                </h3>
                <p className="text-sm text-muted-foreground">
                  Please sign in using {ssoStatus.provider_name || 'SSO'} to access CHAD.
                </p>
              </div>

              {/* SSO Login Button */}
              {ssoLoading ? (
                <div className="flex items-center justify-center">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              ) : ssoStatus?.enabled && ssoStatus?.configured ? (
                <Button
                  type="button"
                  variant="default"
                  className="w-full"
                  onClick={handleSsoLogin}
                >
                  <Shield className="h-4 w-4 mr-2" />
                  Sign in with {ssoStatus.provider_name}
                </Button>
              ) : (
                /* Fallback: SSO not configured */
                <div className="text-destructive text-sm text-center p-4 bg-destructive/10 rounded-md">
                  <Shield className="h-8 w-8 mx-auto mb-2" />
                  <p className="font-medium">Authentication Error</p>
                  <p className="mt-1">
                    SSO-only mode is enabled, but SSO is not configured.
                    <br />
                    Please contact your administrator.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <>
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
            </>
          )}
        </CardContent>
      </Card>

      {/* 2FA Setup Required Dialog */}
      <TwoFactorSetup
        open={requires2FASetup}
        onOpenChange={setRequires2FASetup}
        onComplete={() => {
          window.location.href = '/'
        }}
      />
    </div>
  )
}
