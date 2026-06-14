import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiClient } from '@/lib/api'
import { __environmentStore } from '@/stores/environment-store'
import { createSuccessResponse } from './mocks'

// Verifies the active-environment store flips the X-CHAD-Environment request
// header on the real ApiClient. Note: this file does NOT mock @/lib/api — it
// exercises the actual client + store wiring.
global.fetch = vi.fn()

describe('X-CHAD-Environment header', () => {
  let apiClient: ApiClient

  beforeEach(() => {
    vi.clearAllMocks()
    apiClient = new ApiClient()
    localStorage.clear()
    __environmentStore.reset()
  })

  afterEach(() => {
    __environmentStore.reset()
  })

  it('attaches the header on GET when an environment is selected', async () => {
    __environmentStore.set('env-staging')
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ ok: true }))

    await apiClient.get('/rules')

    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Record<string, string>
    expect(headers['X-CHAD-Environment']).toBe('env-staging')
  })

  it('attaches the header on POST when an environment is selected', async () => {
    __environmentStore.set('env-prod')
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ success: true }))

    await apiClient.post('/rules', { title: 'x' })

    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Record<string, string>
    expect(headers['X-CHAD-Environment']).toBe('env-prod')
  })

  it('omits the header when no environment is selected', async () => {
    // Store reset in beforeEach -> no active env.
    vi.mocked(global.fetch).mockResolvedValueOnce(createSuccessResponse({ ok: true }))

    await apiClient.get('/rules')

    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Record<string, string>
    expect(headers['X-CHAD-Environment']).toBeUndefined()
  })

  it('updates the header after the active environment changes', async () => {
    __environmentStore.set('env-a')
    vi.mocked(global.fetch).mockResolvedValue(createSuccessResponse({ ok: true }))

    await apiClient.get('/rules')
    let headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Record<string, string>
    expect(headers['X-CHAD-Environment']).toBe('env-a')

    __environmentStore.set('env-b')
    await apiClient.get('/rules')
    headers = vi.mocked(global.fetch).mock.calls[1][1]?.headers as Record<string, string>
    expect(headers['X-CHAD-Environment']).toBe('env-b')
  })
})
