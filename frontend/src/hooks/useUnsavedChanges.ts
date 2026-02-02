import { useEffect, useCallback, useRef } from 'react'
import { useBlocker } from 'react-router-dom'

/**
 * Hook to detect and warn about unsaved changes
 * - Blocks navigation with React Router
 * - Warns on browser refresh/close
 */
export function useUnsavedChanges(
  hasUnsavedChanges: boolean,
  message = 'You have unsaved changes. Are you sure you want to leave?'
) {
  const hasUnsavedChangesRef = useRef(hasUnsavedChanges)

  // Keep ref in sync
  useEffect(() => {
    hasUnsavedChangesRef.current = hasUnsavedChanges
  }, [hasUnsavedChanges])

  // Block React Router navigation
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      hasUnsavedChanges && currentLocation.pathname !== nextLocation.pathname
  )

  // Handle blocker state
  useEffect(() => {
    if (blocker.state === 'blocked') {
      const confirmed = window.confirm(message)
      if (confirmed) {
        blocker.proceed()
      } else {
        blocker.reset()
      }
    }
  }, [blocker, message])

  // Block browser refresh/close
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChangesRef.current) {
        e.preventDefault()
        // Modern browsers ignore custom messages
        e.returnValue = message
        return message
      }
    }

    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => window.removeEventListener('beforeunload', handleBeforeUnload)
  }, [message])

  // Allow programmatic navigation bypass
  const bypassBlock = useCallback(() => {
    if (blocker.state === 'blocked') {
      blocker.proceed()
    }
  }, [blocker])

  return { blocker, bypassBlock }
}
