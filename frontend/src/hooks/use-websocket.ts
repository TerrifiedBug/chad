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
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts?token=${token}`

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
        setError('WebSocket connection error')
      }

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        setIsConnected(false)
        wsRef.current = null

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
      setError('Failed to connect to WebSocket')
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
