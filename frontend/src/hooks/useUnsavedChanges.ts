import { useEffect, useRef, useCallback } from 'react'

/**
 * Hook to detect and warn about unsaved changes
 * - Warns on browser refresh/close via beforeunload
 * - Does NOT block React Router navigation (requires data router)
 * - Use confirmNavigation() to check before programmatic navigation
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

  // Helper for programmatic navigation checks
  const confirmNavigation = useCallback(() => {
    if (hasUnsavedChangesRef.current) {
      return window.confirm(message)
    }
    return true
  }, [message])

  return { confirmNavigation, hasUnsavedChanges }
}
