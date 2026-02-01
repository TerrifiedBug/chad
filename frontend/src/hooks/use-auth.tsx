import { createContext, useContext, useEffect, useState } from 'react'
import { api, authApi, settingsApi, CurrentUser } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  isStartingUp: boolean
  connectionFailed: boolean
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
  retryConnection: () => void
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
  const [isStartingUp, setIsStartingUp] = useState(false)
  const [connectionFailed, setConnectionFailed] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [setupCompleted, setSetupCompleted] = useState(false)
  const [isOpenSearchConfigured, setIsOpenSearchConfigured] = useState(false)
  const [user, setUser] = useState<CurrentUser | null>(null)

  useEffect(() => {
    checkAuthWithRetry()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- Only run on mount
  }, [])

  // Check if error is a connection/startup error (502, 503, network error)
  const isConnectionError = (error: unknown): boolean => {
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return true // Network error
    }
    const message = error instanceof Error ? error.message : String(error)
    return message.includes('502') || message.includes('503') || message.includes('Failed to fetch')
  }

  // Retry auth check with exponential backoff during startup
  const checkAuthWithRetry = async (retryCount = 0, maxRetries = 10) => {
    const baseDelay = 2000 // 2 seconds

    try {
      setConnectionFailed(false)
      await checkAuth()
    } catch (error) {
      if (isConnectionError(error) && retryCount < maxRetries) {
        setIsStartingUp(true)
        const delay = Math.min(baseDelay * Math.pow(1.5, retryCount), 15000) // Max 15 seconds
        console.log(`Backend starting up, retrying in ${delay}ms (attempt ${retryCount + 1}/${maxRetries})`)
        setTimeout(() => checkAuthWithRetry(retryCount + 1, maxRetries), delay)
      } else if (isConnectionError(error)) {
        // Connection error and max retries exceeded - show connection failed state
        setIsStartingUp(false)
        setIsLoading(false)
        setConnectionFailed(true)
        setIsAuthenticated(false)
      } else {
        // Not a connection error - could be a real error, treat as setup not completed
        setIsStartingUp(false)
        setIsLoading(false)
        setSetupCompleted(false)
        setIsAuthenticated(false)
      }
    }
  }

  // Allow manual retry of connection
  const retryConnection = () => {
    setIsLoading(true)
    setConnectionFailed(false)
    checkAuthWithRetry(0, 10)
  }

  const checkAuth = async () => {
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

    // This call will throw if backend is unavailable (502/503/network error)
    const status = await api.get<SetupStatusResponse>('/auth/setup-status')
    setSetupCompleted(status.setup_completed)
    setIsStartingUp(false)

    const token = localStorage.getItem('chad-token')

    if (!token || !status.setup_completed) {
      setIsAuthenticated(false)
      setIsOpenSearchConfigured(false)
      setIsLoading(false)
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
    setIsLoading(false)
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
      isStartingUp,
      connectionFailed,
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
      retryConnection,
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
