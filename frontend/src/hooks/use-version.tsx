import { useState, useEffect } from 'react'
import { settingsApi } from '@/lib/api'

export type VersionInfo = {
  version: string | null
  updateAvailable: boolean
  latestVersion: string | null
  releaseUrl: string | null
  loading: boolean
  error: string | null
  checkForUpdates: () => Promise<void>
}

export function useVersion(): VersionInfo {
  const [version, setVersion] = useState<string | null>(null)
  const [updateAvailable, setUpdateAvailable] = useState(false)
  const [latestVersion, setLatestVersion] = useState<string | null>(null)
  const [releaseUrl, setReleaseUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const checkVersion = async () => {
    try {
      setLoading(true)
      setError(null)

      // Get current version
      const versionResponse = await settingsApi.getVersion()
      setVersion(versionResponse.version)

      // Check for updates
      const updateResponse = await settingsApi.checkForUpdates()
      setUpdateAvailable(updateResponse.update_available)
      setLatestVersion(updateResponse.latest)
      setReleaseUrl(updateResponse.release_url || null)
    } catch (err) {
      console.error('Failed to check version', err)
      setError(err instanceof Error ? err.message : 'Failed to check version')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    checkVersion()

    // Check twice daily (every 12 hours)
    const interval = setInterval(checkVersion, 12 * 60 * 60 * 1000)
    return () => clearInterval(interval)
  }, [])

  return {
    version,
    updateAvailable,
    latestVersion,
    releaseUrl,
    loading,
    error,
    checkForUpdates: checkVersion,
  }
}
