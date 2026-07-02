/**
 * Suite path-prefix contract: every API call must resolve under /chad/api
 * and the WS base under /chad/ws (suite-nginx routes on these prefixes).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { API_BASE, WS_BASE, api } from '@/lib/api'

const mockFetch = vi.fn()
global.fetch = mockFetch

describe('suite path prefix', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch.mockResolvedValue({
      ok: true,
      headers: new Headers(),
      json: async () => ({}),
    })
  })

  it('exports the suite-prefixed API base', () => {
    expect(API_BASE).toBe('/chad/api')
  })

  it('exports the suite-prefixed WS base', () => {
    expect(WS_BASE).toBe('/chad/ws')
  })

  it('issues requests under /chad/api', async () => {
    await api.get<unknown>('/rules')
    expect(mockFetch).toHaveBeenCalledWith('/chad/api/rules', expect.anything())
  })
})
