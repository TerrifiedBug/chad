import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { setDelegatedAuth } from '@/lib/api'
import { useWebSocket } from '@/hooks/use-websocket'

class FakeWebSocket {
  static instances: FakeWebSocket[] = []
  static OPEN = 1
  url: string
  protocols: string | string[] | undefined
  onopen: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onerror: ((e: unknown) => void) | null = null
  onclose: ((e: { code: number }) => void) | null = null
  readyState = 0
  constructor(url: string, protocols?: string | string[]) {
    this.url = url
    this.protocols = protocols
    FakeWebSocket.instances.push(this)
  }
  send() {}
  close() {}
}

describe('useWebSocket auth modes', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    localStorage.clear()
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })

  afterEach(() => {
    setDelegatedAuth(false)
    vi.unstubAllGlobals()
  })

  it('connects without a subprotocol in delegated mode (cookie rides the handshake)', () => {
    setDelegatedAuth(true)

    const { unmount } = renderHook(() => useWebSocket())

    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0].url).toContain('/ws/alerts')
    expect(FakeWebSocket.instances[0].protocols).toBeUndefined()
    unmount()
  })

  it('keeps the Sec-WebSocket-Protocol Bearer fallback in standalone mode', () => {
    localStorage.setItem('chad-token', 'standalone-token')

    const { unmount } = renderHook(() => useWebSocket())

    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0].protocols).toEqual(['Bearer', 'standalone-token'])
    unmount()
  })

  it('omits the Bearer subprotocol in delegated mode even when a stale token lingers', () => {
    // A leftover standalone token must never be attached in delegated mode — the
    // backend would try to decode it as a JWT and the cookie fallback never fires.
    localStorage.setItem('chad-token', 'stale-token')
    setDelegatedAuth(true)

    const { unmount } = renderHook(() => useWebSocket())

    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0].protocols).toBeUndefined()
    unmount()
  })

  it('refuses to connect in standalone mode without a token', () => {
    const { result, unmount } = renderHook(() => useWebSocket())

    expect(FakeWebSocket.instances).toHaveLength(0)
    expect(result.current.error).toBe('No authentication token available')
    unmount()
  })
})
