import { createContext, useContext, useEffect, useState } from 'react'
import { modeApi, ModeResponse } from '@/lib/api'

interface ModeContextType {
  mode: ModeResponse | null
  isLoading: boolean
  error: string | null
  isPullOnly: boolean
  supportsPush: boolean
  supportsPull: boolean
  refetch: () => Promise<void>
}

const ModeContext = createContext<ModeContextType | null>(null)

export function ModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<ModeResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchMode = async () => {
    try {
      setIsLoading(true)
      const data = await modeApi.getMode()
      setMode(data)
      setError(null)
    } catch (err) {
      console.error('Failed to fetch deployment mode:', err)
      setError('Failed to fetch deployment mode')
      // Default to push mode on error for backward compatibility
      setMode({
        mode: 'push',
        is_pull_only: false,
        supports_push: true,
        supports_pull: true,
      })
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchMode()
  }, [])

  const isPullOnly = mode?.is_pull_only ?? false
  const supportsPush = mode?.supports_push ?? true
  const supportsPull = mode?.supports_pull ?? true

  return (
    <ModeContext.Provider
      value={{
        mode,
        isLoading,
        error,
        isPullOnly,
        supportsPush,
        supportsPull,
        refetch: fetchMode,
      }}
    >
      {children}
    </ModeContext.Provider>
  )
}

export function useMode() {
  const context = useContext(ModeContext)
  if (!context) {
    throw new Error('useMode must be used within a ModeProvider')
  }
  return context
}
