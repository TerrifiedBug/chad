import { useEffect, useCallback } from 'react'

export interface KeyboardShortcut {
  key: string
  description: string
  handler: () => void
  modifiers?: {
    ctrl?: boolean
    meta?: boolean
    shift?: boolean
    alt?: boolean
  }
}

interface UseKeyboardShortcutsOptions {
  shortcuts: KeyboardShortcut[]
  enabled?: boolean
}

/**
 * Hook for handling global keyboard shortcuts.
 * Automatically ignores shortcuts when user is typing in an input field.
 */
export function useKeyboardShortcuts({ shortcuts, enabled = true }: UseKeyboardShortcutsOptions) {
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input fields
      const target = event.target as HTMLElement
      const isTyping =
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable ||
        target.closest('[role="textbox"]')

      // For '/' and '?' we still want to trigger even in some contexts
      // unless the user is actively typing
      const isSearchKey = event.key === '/'
      const isHelpKey = event.key === '?'

      if (isTyping && !isSearchKey && !isHelpKey) {
        return
      }

      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.modifiers?.ctrl ? event.ctrlKey : !event.ctrlKey
        const metaMatch = shortcut.modifiers?.meta ? event.metaKey : !event.metaKey
        const shiftMatch = shortcut.modifiers?.shift ? event.shiftKey : !event.shiftKey
        const altMatch = shortcut.modifiers?.alt ? event.altKey : !event.altKey

        if (
          event.key.toLowerCase() === shortcut.key.toLowerCase() &&
          ctrlMatch &&
          metaMatch &&
          shiftMatch &&
          altMatch
        ) {
          // For search shortcut, only trigger if not in an input
          if (isSearchKey && isTyping) {
            return
          }

          event.preventDefault()
          shortcut.handler()
          return
        }
      }
    },
    [shortcuts]
  )

  useEffect(() => {
    if (!enabled) return

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [enabled, handleKeyDown])
}

// Common shortcuts configuration
export const defaultShortcuts = {
  focusSearch: { key: '/', description: 'Focus search input' },
  showHelp: { key: '?', description: 'Show keyboard shortcuts', modifiers: { shift: true } },
  refresh: { key: 'r', description: 'Refresh current page data' },
} as const
