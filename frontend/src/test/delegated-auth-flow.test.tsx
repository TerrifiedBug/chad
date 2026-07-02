import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn() },
    authApi: { getMe: vi.fn() },
    settingsApi: { getOpenSearchStatus: vi.fn() },
  }
})

import { api, authApi, settingsApi, isDelegatedAuth, setDelegatedAuth, navigation } from '@/lib/api'
import { useAuth, AuthProvider } from '@/hooks/use-auth'

const wrapper = ({ children }: { children: React.ReactNode }) => <AuthProvider>{children}</AuthProvider>

const delegatedUser = {
  id: '123',
  email: 'danny@example.com',
  role: 'analyst' as const,
  is_active: true,
  auth_method: 'sso' as const,
  must_change_password: false,
  chad_delegated_auth: true,
}

describe('use-auth in delegated (suite) mode', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    vi.mocked(settingsApi.getOpenSearchStatus).mockResolvedValue({ configured: true })
  })

  afterEach(() => {
    setDelegatedAuth(false)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('authenticates from the VF cookie session with no localStorage token', async () => {
    vi.mocked(api.get).mockResolvedValue({ setup_completed: true, chad_delegated_auth: true })
    vi.mocked(authApi.getMe).mockResolvedValue(delegatedUser)

    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))
    expect(result.current.delegatedAuth).toBe(true)
    expect(isDelegatedAuth()).toBe(true)
    expect(localStorage.getItem('chad-token')).toBeNull()
  })

  it('logs out via the VectorFlow signout endpoint and lands on the suite root', async () => {
    vi.mocked(api.get).mockResolvedValue({ setup_completed: true, chad_delegated_auth: true })
    vi.mocked(authApi.getMe).mockResolvedValue(delegatedUser)
    const assignSpy = vi.spyOn(navigation, 'assign').mockImplementation(() => {})
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ csrfToken: 'vf-csrf' }) } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) } as Response)
    vi.stubGlobal('fetch', fetchMock)

    const { result } = renderHook(() => useAuth(), { wrapper })
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))

    await act(async () => {
      await result.current.logout()
    })

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/auth/csrf', { credentials: 'same-origin' })
    const [signoutUrl, signoutInit] = fetchMock.mock.calls[1]
    expect(signoutUrl).toBe('/api/auth/signout')
    expect(signoutInit.method).toBe('POST')
    expect(signoutInit.credentials).toBe('same-origin')
    expect(String(signoutInit.body)).toContain('csrfToken=vf-csrf')
    expect(assignSpy).toHaveBeenCalledWith('/')
  })

  it('keeps the standalone flow untouched when the flag is absent', async () => {
    localStorage.setItem('chad-token', 'tok')
    vi.mocked(api.get).mockResolvedValue({ setup_completed: true })
    vi.mocked(authApi.getMe).mockResolvedValue({
      id: '1',
      email: 'a@b.c',
      role: 'admin',
      is_active: true,
      auth_method: 'local',
      must_change_password: false,
    })

    const { result } = renderHook(() => useAuth(), { wrapper })
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))
    expect(result.current.delegatedAuth).toBe(false)

    await act(async () => {
      await result.current.logout()
    })
    expect(localStorage.getItem('chad-token')).toBeNull()
  })
})
