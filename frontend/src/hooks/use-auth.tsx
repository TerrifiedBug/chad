import { createContext, useContext, useEffect, useState } from 'react'
import { api, authApi, settingsApi, CurrentUser } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  setupCompleted: boolean
  isOpenSearchConfigured: boolean
  user: CurrentUser | null
  isAdmin: boolean
  hasPermission: (permission: string) => boolean
  canManageRules: () => boolean
  canDeployRules: () => boolean
  canManageSettings: () => boolean
  canManageUsers: () => boolean
  canManageApiKeys: () => boolean
  canViewAudit: () => boolean
  canManageSigmahq: () => boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  setup: (email: string, password: string) => Promise<void>
  setOpenSearchConfigured: (configured: boolean) => void
  refreshUser: () => Promise<void>
}

interface SetupStatusResponse {
  setup_completed: boolean
}

interface TokenResponse {
  access_token: string
  token_type: string
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [setupCompleted, setSetupCompleted] = useState(false)
  const [isOpenSearchConfigured, setIsOpenSearchConfigured] = useState(false)
  const [user, setUser] = useState<CurrentUser | null>(null)

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      // Check for SSO exchange code in URL (returned from SSO callback)
      const urlParams = new URLSearchParams(window.location.search)
      const ssoCode = urlParams.get('sso_code')
      if (ssoCode) {
        // Exchange code for token via POST
        try {
          const response = await api.post<TokenResponse>('/auth/sso/exchange', { code: ssoCode })
          localStorage.setItem('chad-token', response.access_token)
        } catch {
          // Exchange failed - clear the code
          console.error('SSO code exchange failed')
        }
        // Clean up URL (remove the code from URL bar)
        window.history.replaceState({}, '', '/')
      }

      const status = await api.get<SetupStatusResponse>('/auth/setup-status')
      setSetupCompleted(status.setup_completed)

      const token = localStorage.getItem('chad-token')

      if (!token || !status.setup_completed) {
        setIsAuthenticated(false)
        setIsOpenSearchConfigured(false)
        return
      }

      // Validate token, get user info, and check OpenSearch status
      // This will throw if the token is invalid
      try {
        const [userData, osStatus] = await Promise.all([
          authApi.getMe(),
          settingsApi.getOpenSearchStatus(),
        ])
        setUser(userData)
        setIsOpenSearchConfigured(osStatus.configured)
        setIsAuthenticated(true)
      } catch {
        // Token is invalid or expired - clear it
        localStorage.removeItem('chad-token')
        setIsAuthenticated(false)
        setIsOpenSearchConfigured(false)
        setUser(null)
      }
    } catch {
      setSetupCompleted(false)
      setIsAuthenticated(false)
      setIsOpenSearchConfigured(false)
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (email: string, password: string) => {
    const response = await api.post<TokenResponse>('/auth/login', { email, password })
    localStorage.setItem('chad-token', response.access_token)
    // Get user info and check OpenSearch status BEFORE setting authenticated
    // This prevents the OpenSearch wizard from flashing briefly
    const [userData, osStatus] = await Promise.all([
      authApi.getMe(),
      settingsApi.getOpenSearchStatus(),
    ])
    setUser(userData)
    setIsOpenSearchConfigured(osStatus.configured)
    setIsAuthenticated(true)
  }

  const logout = () => {
    localStorage.removeItem('chad-token')
    setIsAuthenticated(false)
    setIsOpenSearchConfigured(false)
    setUser(null)
  }

  const setup = async (email: string, password: string) => {
    const response = await api.post<TokenResponse>('/auth/setup', {
      admin_email: email,
      admin_password: password,
    })
    localStorage.setItem('chad-token', response.access_token)
    setSetupCompleted(true)
    setIsAuthenticated(true)
    // OpenSearch not configured yet after setup
    setIsOpenSearchConfigured(false)
    // Get user info after setup
    const userData = await authApi.getMe()
    setUser(userData)
  }

  const refreshUser = async () => {
    try {
      const userData = await authApi.getMe()
      setUser(userData)
    } catch {
      // If refresh fails, the user might have been logged out
      logout()
    }
  }

  // Permission helper functions
  const hasPermission = (permission: string): boolean => {
    if (!user?.permissions) return false
    return user.permissions[permission] === true
  }

  const canManageRules = () => hasPermission('manage_rules')
  const canDeployRules = () => hasPermission('deploy_rules')
  const canManageSettings = () => hasPermission('manage_settings')
  const canManageUsers = () => hasPermission('manage_users')
  const canManageApiKeys = () => hasPermission('manage_api_keys')
  const canViewAudit = () => hasPermission('view_audit')
  const canManageSigmahq = () => hasPermission('manage_sigmahq')

  return (
    <AuthContext.Provider value={{
      isAuthenticated,
      isLoading,
      setupCompleted,
      isOpenSearchConfigured,
      user,
      isAdmin: user?.role === 'admin',
      hasPermission,
      canManageRules,
      canDeployRules,
      canManageSettings,
      canManageUsers,
      canManageApiKeys,
      canViewAudit,
      canManageSigmahq,
      login,
      logout,
      setup,
      setOpenSearchConfigured: setIsOpenSearchConfigured,
      refreshUser,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
