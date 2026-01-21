import { createContext, useContext, useEffect, useState } from 'react'
import { api, settingsApi } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  setupCompleted: boolean
  isOpenSearchConfigured: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  setup: (email: string, password: string) => Promise<void>
  setOpenSearchConfigured: (configured: boolean) => void
}

interface SetupData {
  admin_email: string
  admin_password: string
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

  useEffect(() => {
    checkAuth()
  }, [])

  const checkOpenSearchStatus = async () => {
    try {
      const response = await settingsApi.getOpenSearchStatus()
      setIsOpenSearchConfigured(response.configured)
    } catch {
      // If not authenticated yet, this will fail - that's ok
      setIsOpenSearchConfigured(false)
    }
  }

  const checkAuth = async () => {
    try {
      const status = await api.get<SetupStatusResponse>('/auth/setup-status')
      setSetupCompleted(status.setup_completed)

      const token = localStorage.getItem('chad-token')
      const authenticated = !!token && status.setup_completed
      setIsAuthenticated(authenticated)

      // Check OpenSearch status if authenticated
      if (authenticated) {
        await checkOpenSearchStatus()
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
    setIsAuthenticated(true)
    // Check OpenSearch status after login
    await checkOpenSearchStatus()
  }

  const logout = () => {
    localStorage.removeItem('chad-token')
    setIsAuthenticated(false)
    setIsOpenSearchConfigured(false)
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
  }

  return (
    <AuthContext.Provider value={{
      isAuthenticated,
      isLoading,
      setupCompleted,
      isOpenSearchConfigured,
      login,
      logout,
      setup,
      setOpenSearchConfigured: setIsOpenSearchConfigured,
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
