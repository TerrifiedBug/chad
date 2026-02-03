import { useState, useEffect, useCallback } from 'react'
import { settingsApi } from '@/lib/api'

type VersionState = {
  version: string | null
  updateAvailable: boolean
  latestVersion: string | null
  releaseUrl: string | null
  loading: boolean
  error: string | null
}

export type VersionInfo = VersionState & {
  checkForUpdates: () => Promise<void>
}

const initialState: VersionState = {
  version: null,
  updateAvailable: false,
  latestVersion: null,
  releaseUrl: null,
  loading: true,
  error: null,
}

export function useVersion(): VersionInfo {
  const [state, setState] = useState<VersionState>(initialState)

  const loadCachedVersion = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const [versionResponse, updateResponse] = await Promise.all([
        settingsApi.getVersion(),
        settingsApi.checkForUpdates(),
      ])
      setState({
        version: versionResponse.version,
        updateAvailable: updateResponse.update_available,
        latestVersion: updateResponse.latest,
        releaseUrl: updateResponse.release_url || null,
        loading: false,
        error: null,
      })
    } catch (err) {
      console.error('Failed to load version info', err)
      setState(prev => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : 'Failed to load version info',
      }))
    }
  }, [])

  const checkForUpdates = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const updateResponse = await settingsApi.checkForUpdatesNow()
      setState(prev => ({
        ...prev,
        updateAvailable: updateResponse.update_available,
        latestVersion: updateResponse.latest,
        releaseUrl: updateResponse.release_url || null,
        loading: false,
        error: null,
      }))
    } catch (err) {
      console.error('Failed to check for updates', err)
      setState(prev => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : 'Failed to check for updates',
      }))
    }
  }, [])

  useEffect(() => {
    loadCachedVersion()
  }, [loadCachedVersion])

  return { ...state, checkForUpdates }
}
