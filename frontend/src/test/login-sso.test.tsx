import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const getSsoStatusMock = vi.fn()
const getSsoLoginUrlMock = vi.fn((id?: string) =>
  id ? `/api/auth/sso/login?provider=${id}` : '/api/auth/sso/login'
)

vi.mock('@/lib/api', () => ({
  authApi: {
    getSsoStatus: (...a: unknown[]) => getSsoStatusMock(...a),
    getSsoLoginUrl: (...a: unknown[]) => getSsoLoginUrlMock(...(a as [string?])),
    loginRaw: vi.fn(),
    login2FA: vi.fn(),
  },
}))

// --- Mock auth: not authenticated, login is a no-op ---
vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    login: vi.fn(),
    isAuthenticated: false,
  }),
}))

import LoginPage from '@/pages/Login'

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <LoginPage />
      </ToastProvider>
    </MemoryRouter>
  )
}

describe('LoginPage SSO', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders one button per enabled provider', async () => {
    getSsoStatusMock.mockResolvedValue({
      providers: [
        { id: 'p1', name: 'Okta' },
        { id: 'p2', name: 'Microsoft Entra' },
      ],
      sso_enforced: false,
      enabled: true,
      configured: true,
      provider_name: 'Okta',
    })

    renderPage()

    expect(await screen.findByRole('button', { name: /sign in with okta/i })).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /sign in with microsoft entra/i })
    ).toBeInTheDocument()
    // The password form is still present (not enforced).
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
  })

  it('hides the password form and shows provider buttons when SSO is enforced', async () => {
    getSsoStatusMock.mockResolvedValue({
      providers: [{ id: 'p1', name: 'Okta' }],
      sso_enforced: true,
      enabled: true,
      configured: true,
      provider_name: 'Okta',
    })

    renderPage()

    expect(await screen.findByText(/sso authentication required/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in with okta/i })).toBeInTheDocument()
    // No password field in enforced mode.
    expect(screen.queryByLabelText(/^password$/i)).not.toBeInTheDocument()
  })

  it('falls back to a single legacy provider button when providers array is absent', async () => {
    getSsoStatusMock.mockResolvedValue({
      enabled: true,
      configured: true,
      provider_name: 'Legacy SSO',
    })

    renderPage()

    expect(
      await screen.findByRole('button', { name: /sign in with legacy sso/i })
    ).toBeInTheDocument()
  })
})
