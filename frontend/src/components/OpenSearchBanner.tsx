import { AlertTriangle, CheckCircle2 } from 'lucide-react'
import { useOpenSearchStatus } from '@/contexts/OpenSearchStatus'
import { useEffect, useState } from 'react'

export function OpenSearchBanner() {
  const { isAvailable, isLoading } = useOpenSearchStatus()
  const [showRecovered, setShowRecovered] = useState(false)
  const [wasUnavailable, setWasUnavailable] = useState(false)

  useEffect(() => {
    if (!isAvailable && !isLoading) {
      setWasUnavailable(true)
    }
    if (isAvailable && wasUnavailable) {
      setShowRecovered(true)
      const timer = setTimeout(() => {
        setShowRecovered(false)
        setWasUnavailable(false)
      }, 5000)
      return () => clearTimeout(timer)
    }
  }, [isAvailable, isLoading, wasUnavailable])

  if (isLoading) return null

  if (showRecovered) {
    return (
      <div className="bg-green-500/10 border-b border-green-500/20 px-6 py-2">
        <div className="mx-auto max-w-screen-2xl flex items-center gap-2 text-sm text-green-700 dark:text-green-400">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>OpenSearch connection restored. Data is now live.</span>
        </div>
      </div>
    )
  }

  if (isAvailable) return null

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/20 px-6 py-2">
      <div className="mx-auto max-w-screen-2xl flex items-center gap-2 text-sm text-amber-700 dark:text-amber-400">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>OpenSearch is unavailable — showing cached data. Some actions are disabled.</span>
      </div>
    </div>
  )
}
