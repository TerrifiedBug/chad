import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiClient, setDelegatedAuth, isDelegatedAuth, authHeader, navigation } from '@/lib/api'
import { createMockResponse, createSuccessResponse, createErrorResponse } from './mocks'

global.fetch = vi.fn()

describe('delegated auth mode (suite SSO)', () => {
  let apiClient: ApiClient
  let assignSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.clearAllMocks()
    apiClient = new ApiClient()
    localStorage.clear()
    assignSpy = vi.spyOn(navigation, 'assign').mockImplementation(() => {})
  })

  afterEach(() => {
    setDelegatedAuth(false)
    assignSpy.mockRestore()
  })

  it('does not attach Authorization in delegated mode even when a stale token exists', async () => {
    localStorage.setItem('chad-token', 'stale-token')
    setDelegatedAuth(true)
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ data: 'ok' }))

    await apiClient.get('/rules')

    const [, init] = vi.mocked(global.fetch).mock.calls[0]
    const headers = init?.headers as Record<string, string>
    expect(headers['Authorization']).toBeUndefined()
  })

  it('sends credentials same-origin so the VF session cookie rides along', async () => {
    setDelegatedAuth(true)
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ data: 'ok' }))

    await apiClient.get('/rules')

    const [, init] = vi.mocked(global.fetch).mock.calls[0]
    expect(init?.credentials).toBe('same-origin')
  })

  it('still attaches the Bearer token in standalone mode', async () => {
    localStorage.setItem('chad-token', 'standalone-token')
    setDelegatedAuth(false)
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ data: 'ok' }))

    await apiClient.get('/rules')

    const [, init] = vi.mocked(global.fetch).mock.calls[0]
    const headers = init?.headers as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer standalone-token')
  })

  it('keeps echoing X-CSRF-Token on mutating requests in delegated mode', async () => {
    setDelegatedAuth(true)
    vi.mocked(global.fetch)
      .mockResolvedValueOnce(
        createMockResponse({ ok: true, headers: { 'X-CSRF-Token': 'csrf-abc' }, json: async () => ({}) })
      )
      .mockResolvedValueOnce(createSuccessResponse({ ok: true }))

    await apiClient.get('/rules')
    await apiClient.post('/rules', { title: 't' })

    const [, postInit] = vi.mocked(global.fetch).mock.calls[1]
    const headers = postInit?.headers as Record<string, string>
    expect(headers['X-CSRF-Token']).toBe('csrf-abc')
    expect(headers['Authorization']).toBeUndefined()
  })

  it('redirects a delegated 401 to the origin-root login with callbackUrl', async () => {
    setDelegatedAuth(true)
    vi.mocked(global.fetch).mockResolvedValueOnce(createErrorResponse('Not authenticated', 401))

    await expect(apiClient.get('/rules')).rejects.toThrow('Not authenticated')
    // jsdom pathname is '/', so callbackUrl=%2F
    expect(assignSpy).toHaveBeenCalledWith('/login?callbackUrl=%2F')
  })

  it('does not redirect 401s from pre-login auth endpoints', async () => {
    setDelegatedAuth(true)
    vi.mocked(global.fetch).mockResolvedValueOnce(createErrorResponse('Bad credentials', 401))

    await expect(apiClient.post('/auth/login', { email: 'a', password: 'b' })).rejects.toThrow()
    expect(assignSpy).not.toHaveBeenCalled()
  })

  it('authHeader() is the single token read and respects the mode', () => {
    localStorage.setItem('chad-token', 'tok')
    expect(authHeader()).toEqual({ Authorization: 'Bearer tok' })
    setDelegatedAuth(true)
    expect(authHeader()).toEqual({})
    expect(isDelegatedAuth()).toBe(true)
  })
})
