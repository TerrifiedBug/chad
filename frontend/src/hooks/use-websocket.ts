import { useEffect, useRef, useState, useCallback } from 'react'

interface WebSocketMessage {
  type: string
  data?: unknown
  message?: string
  token?: string
}

interface AlertData {
  alert_id: string
  rule_id: string
  rule_title: string
  severity: string
  timestamp: string
  matched_log: Record<string, unknown>
}

interface NotificationPreferences {
  browser_notifications: boolean
  severities: string[]
}

interface UseWebSocketOptions {
  notificationPreferences?: NotificationPreferences
}

function showBrowserNotification(alert: AlertData) {
  if (!('Notification' in window) || Notification.permission !== 'granted') {
    return
  }

  // Only show notification if tab is not visible
  if (!document.hidden) {
    return
  }

  const severity = alert.severity.toUpperCase()
  const notification = new Notification(`${severity}: ${alert.rule_title}`, {
    body: `New ${alert.severity} alert detected`,
    icon: '/favicon.ico',
    tag: alert.alert_id, // Prevent duplicate notifications for same alert
  })

  // Close notification after 10 seconds
  setTimeout(() => notification.close(), 10000)

  // Focus window when clicked
  notification.onclick = () => {
    window.focus()
    notification.close()
  }
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const [isConnected, setIsConnected] = useState(false)
  const [alerts, setAlerts] = useState<AlertData[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const [error, setError] = useState<string | null>(null)
  const optionsRef = useRef(options)

  // Keep options ref updated
  useEffect(() => {
    optionsRef.current = options
  }, [options])

  const getToken = () => {
    return localStorage.getItem('chad-token')
  }

  const connect = useCallback(() => {
    const token = getToken()
    if (!token) {
      setError('No authentication token available')
      return
    }

    // Determine WebSocket URL
    // Support override via environment variable for proxy/reverse-proxy scenarios
    // Set VITE_WS_URL environment variable to customize (e.g., "wss://backend.example.com/ws/alerts")
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'

    let wsUrl: string
    if (import.meta.env.VITE_WS_URL) {
      // Use configured WebSocket URL (for proxy/custom deployments)
      wsUrl = import.meta.env.VITE_WS_URL
    } else if (window.location.hostname === 'localhost' && window.location.port === '3000') {
      // Development: frontend on :3000, backend on :8000 (no nginx proxy in dev)
      wsUrl = `${protocol}//localhost:8000/ws/alerts`
    } else {
      // Default: WebSocket goes through the same host:port as the frontend
      // This works when nginx/proxy correctly forwards /ws/ to backend
      wsUrl = `${protocol}//${window.location.host}/ws/alerts`
    }

    console.log('Connecting to WebSocket:', wsUrl.replace(token, 'REDACTED'))

    try {
      // Use Sec-WebSocket-Protocol header with Bearer token for authentication
      // This prevents token exposure in URL logs/history
      const ws = new WebSocket(wsUrl, ['Bearer', token])
      wsRef.current = ws

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
        setError(null)
      }

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)

          if (message.type === 'alert') {
            const alertData = message.data as AlertData
            setAlerts((prev) => [alertData, ...prev])

            // Show browser notification if enabled and severity matches
            const prefs = optionsRef.current.notificationPreferences
            if (prefs?.browser_notifications && prefs.severities?.includes(alertData.severity)) {
              showBrowserNotification(alertData)
            }
          } else if (message.type === 'connected') {
            // Don't log server message content to prevent log injection
            console.log('WebSocket connected successfully')
          } else if (message.type === 'pong') {
            // Server responded to our ping with a refreshed token
            // This extends the session while actively viewing live alerts
            if (message.token) {
              localStorage.setItem('chad-token', message.token as string)
              console.debug('Session extended via WebSocket ping')
            }
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }

      ws.onerror = (event) => {
        console.error('WebSocket error:', event)
        setError('WebSocket connection error - check console for details')
      }

      ws.onclose = (event) => {
        // Only log the code, not the reason which could contain user-controlled content
        console.log('WebSocket disconnected, code:', event.code)
        setIsConnected(false)
        wsRef.current = null

        // Don't reconnect if it was a clean close (1000) or authentication failed (1008)
        if (event.code === 1000 || event.code === 1008) {
          console.log('WebSocket closed cleanly, not reconnecting')
          return
        }

        // Attempt to reconnect after 5 seconds
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current)
        }
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log('Attempting to reconnect WebSocket...')
          connect()
        }, 5000)
      }
    } catch (err) {
      console.error('Failed to create WebSocket connection:', err)
      setError(`Failed to connect: ${err}`)
    }
  }, []) // getToken is defined inside, options accessed via ref

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    setIsConnected(false)
  }, [])

  const clearAlerts = useCallback(() => {
    setAlerts([])
  }, [])

  // Auto-connect on mount
  useEffect(() => {
    connect()

    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  // Send ping/pong to keep connection alive
  useEffect(() => {
    if (!isConnected) return

    const interval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping')
      }
    }, 30000) // Send ping every 30 seconds

    return () => clearInterval(interval)
  }, [isConnected])

  return {
    isConnected,
    alerts,
    error,
    clearAlerts,
    reconnect: connect,
    disconnect,
  }
}
