import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const listProvidersMock = vi.fn()
const createProviderMock = vi.fn()
const updateProviderMock = vi.fn()
const deleteProviderMock = vi.fn()
const testConnectionMock = vi.fn()
const getEnforcementMock = vi.fn()
const updateEnforcementMock = vi.fn()
const teamsListMock = vi.fn()
const scimGetConfigMock = vi.fn()
const scimSetEnabledMock = vi.fn()
const scimGenerateTokenMock = vi.fn()

vi.mock('@/lib/api', () => ({
  ssoApi: {
    listProviders: (...a: unknown[]) => listProvidersMock(...a),
    createProvider: (...a: unknown[]) => createProviderMock(...a),
    updateProvider: (...a: unknown[]) => updateProviderMock(...a),
    deleteProvider: (...a: unknown[]) => deleteProviderMock(...a),
    testConnection: (...a: unknown[]) => testConnectionMock(...a),
    getEnforcement: (...a: unknown[]) => getEnforcementMock(...a),
    updateEnforcement: (...a: unknown[]) => updateEnforcementMock(...a),
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

// --- Mock auth: admin with manage_settings ---
vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    isAdmin: true,
    hasPermission: () => true,
  }),
}))

import SsoSettings from '@/pages/settings/SsoSettings'

const provider = {
  id: 'prov-1',
  name: 'Okta',
  enabled: true,
  issuer_url: 'https://example.okta.com/oauth2/default',
  client_id: 'client-123',
  client_secret_set: true,
  token_auth_method: 'client_secret_post' as const,
  scopes: 'openid email profile',
  default_role: 'analyst',
  default_team_id: null,
  require_email_verified: true,
  group_sync_enabled: true,
  groups_claim: 'groups',
  groups_scope: '',
  role_claim: '',
  // Group mappings are embedded directly on the provider (no separate endpoint).
  group_mappings: [],
  last_tested_at: null,
  last_test_success: null,
}

const team = {
  id: 'team-1',
  name: 'SOC Team',
  description: null,
  created_at: new Date('2026-06-14T09:00:00Z').toISOString(),
  updated_at: new Date('2026-06-14T09:00:00Z').toISOString(),
}

function renderPage() {
  return render(
    <ToastProvider>
      <SsoSettings />
    </ToastProvider>
  )
}

describe('SsoSettings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listProvidersMock.mockResolvedValue([provider])
    teamsListMock.mockResolvedValue([team])
    getEnforcementMock.mockResolvedValue({ sso_enforced: false })
    // SCIM panel mounts alongside the providers list.
    scimGetConfigMock.mockResolvedValue({
      enabled: false,
      token_configured: false,
    })
  })

  it('renders the providers list with the provider name and issuer host', async () => {
    renderPage()
    expect(await screen.findByText('Okta')).toBeInTheDocument()
    // Issuer host is shown (not the full URL).
    expect(screen.getByText('example.okta.com')).toBeInTheDocument()
    // Enabled badge.
    expect(screen.getByText('Enabled')).toBeInTheDocument()
  })

  it('opens the provider editor and adds a group-mapping row', async () => {
    const user = userEvent.setup()
    renderPage()

    // Open the editor for the existing provider.
    const editBtn = await screen.findByRole('button', { name: /edit okta/i })
    await user.click(editBtn)

    // Editor dialog is open.
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Edit Provider')).toBeInTheDocument()

    // Group sync is enabled on this provider -> the mapping editor is present.
    // The provider's embedded group_mappings is [] -> no rows yet.
    expect(within(dialog).getByText(/no mappings yet/i)).toBeInTheDocument()

    // Add a mapping row.
    await user.click(within(dialog).getByRole('button', { name: /add mapping/i }))

    // A new row exposes a "Group value 1" input + Team/Role selects.
    await waitFor(() => {
      expect(within(dialog).getByLabelText(/group value 1/i)).toBeInTheDocument()
    })
    expect(within(dialog).getByLabelText(/team 1/i)).toBeInTheDocument()
    expect(within(dialog).getByLabelText(/role 1/i)).toBeInTheDocument()
  })
})
