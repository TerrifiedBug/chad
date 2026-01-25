import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { useToast } from '@/components/ui/toast-provider'

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
  const { hasPermission, isAuthenticated, isLoading } = useAuth()
  const location = useLocation()
  const { showToast } = useToast()

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
    // Show toast notification
    showToast('You do not have permission to access this page', 'error')
    return <Navigate to={redirectTo} replace />
  }

  return <>{children}</>
}
