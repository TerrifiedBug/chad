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
    const logKey = `${location.pathname}-${permission}`

    useEffect(() => {
      // Only log and show toast once per route access
      if (hasLoggedRef.current !== logKey) {
        hasLoggedRef.current = logKey

        // Log access denied attempt
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
        }).catch(console.error) // Silently fail if audit logging fails

        // Show toast notification
        showToast('You do not have permission to access this page', 'error')
      }
    }, [location.pathname, permission, user?.role, logKey, showToast])

    return <Navigate to={redirectTo} replace />
  }

  return <>{children}</>
}
