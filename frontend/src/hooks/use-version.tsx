import { useState, useEffect, useCallback } from 'react'
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

  // Load cached version info (no GitHub API call)
  const loadCachedVersion = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // Get current version
      const versionResponse = await settingsApi.getVersion()
      setVersion(versionResponse.version)

      // Get cached update check (no GitHub API call)
      const updateResponse = await settingsApi.checkForUpdates()
      setUpdateAvailable(updateResponse.update_available)
      setLatestVersion(updateResponse.latest)
      setReleaseUrl(updateResponse.release_url || null)
    } catch (err) {
      console.error('Failed to load version info', err)
      setError(err instanceof Error ? err.message : 'Failed to load version info')
    } finally {
      setLoading(false)
    }
  }, [])

  // Force a fresh check against GitHub (user-initiated)
  const checkForUpdates = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // Force fresh check against GitHub
      const updateResponse = await settingsApi.checkForUpdatesNow()
      setUpdateAvailable(updateResponse.update_available)
      setLatestVersion(updateResponse.latest)
      setReleaseUrl(updateResponse.release_url || null)
    } catch (err) {
      console.error('Failed to check for updates', err)
      setError(err instanceof Error ? err.message : 'Failed to check for updates')
    } finally {
      setLoading(false)
    }
  }, [])

  // Load cached version on mount (no automatic polling)
  useEffect(() => {
    loadCachedVersion()
  }, [loadCachedVersion])

  return {
    version,
    updateAvailable,
    latestVersion,
    releaseUrl,
    loading,
    error,
    checkForUpdates,
  }
}
