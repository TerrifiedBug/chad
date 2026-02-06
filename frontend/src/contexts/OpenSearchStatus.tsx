import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'
import { healthApi } from '@/lib/api'

interface OpenSearchStatus {
  isAvailable: boolean
  circuitState: 'closed' | 'open' | 'half_open'
  isLoading: boolean
}

const OpenSearchStatusContext = createContext<OpenSearchStatus>({
  isAvailable: true,
  circuitState: 'closed',
  isLoading: true,
})

export function useOpenSearchStatus() {
  return useContext(OpenSearchStatusContext)
}

export function OpenSearchStatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<OpenSearchStatus>({
    isAvailable: true,
    circuitState: 'closed',
    isLoading: true,
  })

  const checkStatus = useCallback(async () => {
    try {
      const result = await healthApi.getOpenSearchStatus()
      setStatus({
        isAvailable: result.available,
        circuitState: result.circuit_state,
        isLoading: false,
      })
    } catch {
      // If health endpoint itself fails, assume available (don't block UI)
      setStatus(prev => ({ ...prev, isLoading: false }))
    }
  }, [])

  useEffect(() => {
    checkStatus()
    const interval = setInterval(checkStatus, 15000)
    return () => clearInterval(interval)
  }, [checkStatus])

  return (
    <OpenSearchStatusContext.Provider value={status}>
      {children}
    </OpenSearchStatusContext.Provider>
  )
}
