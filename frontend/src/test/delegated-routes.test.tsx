import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast-provider'

const authState = {
  isAuthenticated: true,
  isLoading: false,
  isStartingUp: false,
  connectionFailed: false,
  setupCompleted: true,
  isOpenSearchConfigured: true,
  backendReady: true,
  delegatedAuth: true,
  accountInactive: false,
  user: {
    id: '1',
    email: 'a@b.c',
    role: 'admin',
    is_active: true,
    auth_method: 'sso',
    must_change_password: false,
  },
  isAdmin: true,
  hasPermission: () => true,
  canManageRules: () => true,
  canDeployRules: () => true,
  canManageSettings: () => true,
  canManageUsers: () => true,
  canManageApiKeys: () => true,
  canViewAudit: () => true,
  canManageSigmahq: () => true,
  login: vi.fn(),
  logout: vi.fn(),
  setup: vi.fn(),
  setOpenSearchConfigured: vi.fn(),
  refreshUser: vi.fn(),
  retryConnection: vi.fn(),
}

vi.mock('@/hooks/use-auth', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useAuth: () => authState,
}))
vi.mock('@/components/AppLayout', () => ({
  AppLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))
vi.mock('@/pages/Login', () => ({ default: () => <div>chad-local-login</div> }))
vi.mock('@/pages/Setup', () => ({ default: () => <div>setup-page</div> }))
vi.mock('@/pages/Dashboard', () => ({ default: () => <div>dashboard-page</div> }))
vi.mock('@/pages/Account', () => ({ default: () => <div>account-page</div> }))
vi.mock('@/pages/SettingsHub', () => ({ default: () => <div>settings-hub</div> }))
vi.mock('@/pages/settings/SettingsSection', () => ({ default: () => <div>settings-section</div> }))

import { AppRoutes } from '@/App'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AppRoutes />
      </ToastProvider>
    </MemoryRouter>
  )
}

describe('delegated-mode route hiding', () => {
  beforeEach(() => {
    authState.delegatedAuth = true
    authState.isAuthenticated = true
    authState.setupCompleted = true
    authState.accountInactive = false
  })

  it('never shows the setup wizard in delegated mode even when setup is incomplete', () => {
    // VF owns onboarding for the suite; CHAD's setup wizard is meaningless here.
    authState.setupCompleted = false
    renderAt('/')
    expect(screen.queryByText('setup-page')).not.toBeInTheDocument()
    expect(screen.getByText('dashboard-page')).toBeInTheDocument()
  })

  it('shows a terminal inactive-account message (not a redirect) when the account is deactivated', () => {
    authState.isAuthenticated = false
    authState.accountInactive = true
    renderAt('/rules')
    expect(screen.getByText(/deactivated/i)).toBeInTheDocument()
    expect(screen.queryByText(/redirecting/i)).not.toBeInTheDocument()
  })

  it('redirects /login to the dashboard when delegated (VF owns login)', () => {
    renderAt('/login')
    expect(screen.getByText('dashboard-page')).toBeInTheDocument()
    expect(screen.queryByText('chad-local-login')).not.toBeInTheDocument()
  })

  it('redirects /settings/sso back to the settings hub when delegated', () => {
    renderAt('/settings/sso')
    expect(screen.getByText('settings-hub')).toBeInTheDocument()
    expect(screen.queryByText('settings-section')).not.toBeInTheDocument()
  })

  it('redirects /change-password to /account when delegated', () => {
    renderAt('/change-password')
    expect(screen.getByText('account-page')).toBeInTheDocument()
  })

  it('shows a redirect placeholder instead of the local login when delegated and unauthenticated', () => {
    authState.isAuthenticated = false
    renderAt('/rules')
    expect(screen.getByText(/redirecting to sign-in/i)).toBeInTheDocument()
    expect(screen.queryByText('chad-local-login')).not.toBeInTheDocument()
  })

  it('still renders the local login page standalone', () => {
    authState.delegatedAuth = false
    renderAt('/login')
    expect(screen.getByText('chad-local-login')).toBeInTheDocument()
  })
})
