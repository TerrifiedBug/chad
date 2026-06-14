import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const listProvidersMock = vi.fn()
const getEnforcementMock = vi.fn()
const teamsListMock = vi.fn()
const scimGetConfigMock = vi.fn()
const scimSetEnabledMock = vi.fn()
const scimGenerateTokenMock = vi.fn()

vi.mock('@/lib/api', () => ({
  ssoApi: {
    listProviders: (...a: unknown[]) => listProvidersMock(...a),
    createProvider: vi.fn(),
    updateProvider: vi.fn(),
    deleteProvider: vi.fn(),
    testConnection: vi.fn(),
    getEnforcement: (...a: unknown[]) => getEnforcementMock(...a),
    updateEnforcement: vi.fn(),
  },
  scimApi: {
    getConfig: (...a: unknown[]) => scimGetConfigMock(...a),
    setEnabled: (...a: unknown[]) => scimSetEnabledMock(...a),
    generateToken: (...a: unknown[]) => scimGenerateTokenMock(...a),
  },
  teamsApi: {
    list: (...a: unknown[]) => teamsListMock(...a),
  },
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    isAdmin: true,
    hasPermission: () => true,
  }),
}))

import SsoSettings from '@/pages/settings/SsoSettings'

const TOKEN = 'a'.repeat(64)

function renderPage() {
  return render(
    <ToastProvider>
      <SsoSettings />
    </ToastProvider>
  )
}

describe('SCIM panel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listProvidersMock.mockResolvedValue([])
    teamsListMock.mockResolvedValue([])
    getEnforcementMock.mockResolvedValue({ sso_enforced: false })
    scimGetConfigMock.mockResolvedValue({
      enabled: false,
      token_configured: false,
    })
    scimGenerateTokenMock.mockResolvedValue({ token: TOKEN })
  })

  it('renders the SCIM base URL derived from the page origin', async () => {
    renderPage()
    // Base URL is derived client-side as `${origin}/api/scim/v2`.
    expect(
      await screen.findByText(`${window.location.origin}/api/scim/v2`)
    ).toBeInTheDocument()
  })

  it('opens the one-time reveal dialog with the token after Generate Token', async () => {
    const user = userEvent.setup()
    renderPage()

    const generateBtn = await screen.findByRole('button', { name: /generate token/i })
    await user.click(generateBtn)

    // One-time reveal dialog appears with the token + the "won't be shown again" warning.
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(TOKEN)).toBeInTheDocument()
    expect(within(dialog).getByText(/won't be shown again/i)).toBeInTheDocument()
    expect(scimGenerateTokenMock).toHaveBeenCalledTimes(1)
  })
})
