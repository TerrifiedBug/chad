import { useMemo } from 'react'

interface UsePermissionsOptions {
  permissions?: string[]
  role?: string
  loading?: boolean
}

interface UsePermissionsResult {
  can: (permission: string) => boolean
}

/**
 * Permission checking hook.
 * Admin role has all permissions.
 * Otherwise, checks against provided permissions list.
 */
export function usePermissions(options: UsePermissionsOptions = {}): UsePermissionsResult {
  const { permissions = [], role, loading = false } = options

  const can = useMemo(() => {
    return (permission: string): boolean => {
      if (loading) return false
      if (role === 'admin') return true
      return permissions.includes(permission)
    }
  }, [permissions, role, loading])

  return { can }
}
