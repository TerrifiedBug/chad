import { useEffect, useRef, useState, useCallback } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

interface AlertData {
  alert_id: string
  rule_id: string
  rule_title: string
  severity: string
  timestamp: string
  matched_log: Record<string, unknown>
}

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false)
  const [alerts, setAlerts] = useState<AlertData[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const [error, setError] = useState<string | null>(null)

  const getToken = () => {
    return localStorage.getItem('chad-token')
  }

  const connect = useCallback(() => {
    const token = getToken()
    if (!token) {
      setError('No authentication token available')
      return
    }

    // Determine WebSocket URL based on current location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'

    // For development, use the backend port
    let wsUrl: string
    if (window.location.hostname === 'localhost' && window.location.port === '3000') {
      // Development: frontend on :3000, backend on :8000
      wsUrl = `${protocol}//localhost:8000/ws/alerts?token=${token}`
    } else if (window.location.hostname === 'localhost' && window.location.port === '8000') {
      // Accessing frontend via backend port
      wsUrl = `${protocol}//localhost:8000/ws/alerts?token=${token}`
    } else {
      // Production or other setups
      wsUrl = `${protocol}//${window.location.host}/ws/alerts?token=${token}`
    }

    console.log('Connecting to WebSocket:', wsUrl.replace(/token=[^&]+/, 'token=REDACTED'))

    try {
      const ws = new WebSocket(wsUrl)
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
            console.log('Alert received via WebSocket:', message.data)
            setAlerts((prev) => [message.data, ...prev])
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
        console.log('WebSocket disconnected:', event.code, event.reason)
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
  }, []) // getToken is defined inside, so no deps needed

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
