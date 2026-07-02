import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { setDelegatedAuth } from '@/lib/api'
import { useDeployProgressWs } from '@/components/rules/use-deploy-progress-ws'

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

describe('useDeployProgressWs auth modes', () => {
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

    const { unmount } = renderHook(() => useDeployProgressWs())

    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0].url).toContain('/ws')
    expect(FakeWebSocket.instances[0].protocols).toBeUndefined()
    unmount()
  })

  it('keeps the Sec-WebSocket-Protocol Bearer fallback in standalone mode', () => {
    localStorage.setItem('chad-token', 'standalone-token')

    const { unmount } = renderHook(() => useDeployProgressWs())

    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0].protocols).toEqual(['Bearer', 'standalone-token'])
    unmount()
  })

  it('refuses to connect in standalone mode without a token', () => {
    const { unmount } = renderHook(() => useDeployProgressWs())

    expect(FakeWebSocket.instances).toHaveLength(0)
    unmount()
  })
})
