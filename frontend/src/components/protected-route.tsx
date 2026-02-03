import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'
import { useEffect, useRef } from 'react'

interface ProtectedRouteProps {
  children: React.ReactNode
  permission?: string
  redirectTo?: string
}

export function ProtectedRoute({
  children,
  permission,
  redirectTo = '/dashboard',
}: ProtectedRouteProps) {
  const { hasPermission, isAuthenticated, isLoading, user } = useAuth()
  const location = useLocation()
  const { showToast } = useToast()
  const hasLoggedRef = useRef<string>('')

  const logKey = `${location.pathname}-${permission}`

  useEffect(() => {
    if (!isAuthenticated || !permission || hasPermission(permission)) {
      return
    }
    if (hasLoggedRef.current === logKey) {
      return
    }
    hasLoggedRef.current = logKey

    fetch('/api/audit/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'route_access_denied',
        details: {
          route: location.pathname,
          reason: `Insufficient permissions: ${permission} required`,
          user_role: user?.role || 'unknown',
        }
      })
    }).catch(console.error)

    showToast('You do not have permission to access this page', 'error')
  }, [isAuthenticated, permission, hasPermission, location.pathname, user?.role, logKey, showToast])

  // Show loading state while checking auth
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  // Not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  // Authenticated but missing permission
  if (permission && !hasPermission(permission)) {
    return <Navigate to={redirectTo} replace />
  }

  return <>{children}</>
}
