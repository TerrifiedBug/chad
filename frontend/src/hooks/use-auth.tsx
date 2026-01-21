import { createContext, useContext, useEffect, useState } from 'react'
import { api } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  setupCompleted: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  setup: (data: SetupData) => Promise<void>
}

interface SetupData {
  admin_email: string
  admin_password: string
  opensearch_host: string
  opensearch_port: number
  opensearch_username?: string
  opensearch_password?: string
  opensearch_use_ssl: boolean
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

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const status = await api.get<SetupStatusResponse>('/auth/setup-status')
      setSetupCompleted(status.setup_completed)

      const token = localStorage.getItem('chad-token')
      setIsAuthenticated(!!token && status.setup_completed)
    } catch {
      setSetupCompleted(false)
      setIsAuthenticated(false)
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (email: string, password: string) => {
    const response = await api.post<TokenResponse>('/auth/login', { email, password })
    localStorage.setItem('chad-token', response.access_token)
    setIsAuthenticated(true)
  }

  const logout = () => {
    localStorage.removeItem('chad-token')
    setIsAuthenticated(false)
  }

  const setup = async (data: SetupData) => {
    const response = await api.post<TokenResponse>('/auth/setup', data)
    localStorage.setItem('chad-token', response.access_token)
    setSetupCompleted(true)
    setIsAuthenticated(true)
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, setupCompleted, login, logout, setup }}>
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
