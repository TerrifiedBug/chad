import { useEffect, useRef } from 'react'
import type { DeployProgressMessage } from '@/lib/api'
import { WS_BASE, isDelegatedAuth } from '@/lib/api'
import { applyProgress } from './deploy-progress-store'

/**
 * Opens the shared /ws socket and routes `deploy_progress` messages into the
 * deploy-progress store. Mirrors the SystemLogs/Health pattern (their own /ws
 * sockets dispatching by message.type) rather than adding a new WS transport.
 *
 * Mount this once near the app root so bulk-deploy progress is captured even if
 * the user navigates away from the Rules page mid-deploy.
 */
export function useDeployProgressWs(enabled: boolean = true) {
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!enabled) return
    // Only connect when authenticated — the socket requires a token in standalone mode.
    // In delegated mode, the same-origin cookie carries auth.
    const delegated = isDelegatedAuth()
    // In delegated mode auth rides the same-origin cookie; force the token to
    // null so a stale localStorage 'chad-token' is never attached as a Bearer
    // subprotocol (which would defeat the backend's cookie fallback).
    const token = delegated ? null : localStorage.getItem('chad-token')
    if (!delegated && !token) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = token ? new WebSocket(`${protocol}//${window.location.host}${WS_BASE}`, ['Bearer', token]) : new WebSocket(`${protocol}//${window.location.host}${WS_BASE}`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        if (message?.type === 'deploy_progress') {
          applyProgress(message as DeployProgressMessage)
        }
      } catch {
        // Ignore parse errors — other message types are handled elsewhere.
      }
    }

    ws.onerror = () => {
      wsRef.current = null
    }

    return () => {
      if (wsRef.current === ws) {
        ws.close()
        wsRef.current = null
      }
    }
  }, [enabled])
}
