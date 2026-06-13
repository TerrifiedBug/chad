import { useEffect, useMemo, useState } from 'react'
import { alertsApi } from '@/lib/api'
import { useHealthStatus } from '@/hooks/useHealthStatus'

export type NavHealthStatus = 'healthy' | 'warning' | 'critical'

/**
 * Provides live data for the navigation rail: the count of new (unacknowledged)
 * alerts and an overall health status. Both degrade gracefully — if OpenSearch
 * or the health endpoint is unavailable the corresponding value is left
 * undefined so the rail simply omits the badge/dot rather than erroring.
 */
export function useNavStatus(enabled = true): {
  alertCount?: number
  healthStatus?: NavHealthStatus
} {
  const { healthData } = useHealthStatus()
  const [alertCount, setAlertCount] = useState<number | undefined>(undefined)

  useEffect(() => {
    if (!enabled) return
    let cancelled = false

    const load = async () => {
      try {
        const counts = await alertsApi.getCounts({ exclude_ioc: true })
        if (!cancelled) setAlertCount(counts.by_status?.new ?? 0)
      } catch {
        // OpenSearch may be unavailable; leave the badge absent rather than error.
      }
    }

    load()
    const interval = setInterval(load, 60000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [enabled])

  const healthStatus = useMemo<NavHealthStatus | undefined>(() => {
    const services = healthData?.services
    if (!services || services.length === 0) return undefined
    if (services.some((s) => s.status === 'unhealthy')) return 'critical'
    if (services.some((s) => s.status === 'warning' || s.status === 'degraded')) return 'warning'
    return 'healthy'
  }, [healthData])

  return { alertCount, healthStatus }
}
