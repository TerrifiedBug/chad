import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast-provider'

// Radix DropdownMenu relies on Pointer Capture + scrollIntoView, which jsdom
// does not implement. Polyfill them so the menu opens under test.
beforeAll(() => {
  if (!Element.prototype.hasPointerCapture) {
    Element.prototype.hasPointerCapture = vi.fn(() => false)
    Element.prototype.setPointerCapture = vi.fn()
    Element.prototype.releasePointerCapture = vi.fn()
  }
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = vi.fn()
  }
})

// --- Mock the api layer (environmentsApi) ---
const listMock = vi.fn()
const getMock = vi.fn()
const createMock = vi.fn()
const setDefaultMock = vi.fn()

vi.mock('@/lib/api', () => ({
  environmentsApi: {
    list: (...args: unknown[]) => listMock(...args),
    get: (...args: unknown[]) => getMock(...args),
    create: (...args: unknown[]) => createMock(...args),
    setDefault: (...args: unknown[]) => setDefaultMock(...args),
  },
}))

// --- Mock auth: authenticated admin (can set default) ---
let permissions: Record<string, boolean> = { manage_environments: true }
let isAdmin = true
vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isAdmin,
    hasPermission: (p: string) => permissions[p] === true,
  }),
}))

import { EnvironmentSelector } from '@/components/EnvironmentSelector'
import EnvironmentsPage from '@/pages/Environments'
import {
  __environmentStore,
  getActiveEnvironmentId,
} from '@/stores/environment-store'

const PROD = {
  id: 'env-prod',
  name: 'Production',
  team_id: null,
  is_default: true,
  require_deploy_approval: true,
  description: 'Live detection',
  opensearch_index_prefix: null,
  color: null,
  rule_count: 42,
  deployed_count: 30,
  last_deploy_at: new Date().toISOString(),
}

const STAGING = {
  id: 'env-staging',
  name: 'Staging',
  team_id: 'team-1',
  is_default: false,
  require_deploy_approval: false,
  description: 'Pre-prod testing',
  opensearch_index_prefix: 'staging',
  color: null,
  rule_count: 10,
  deployed_count: 3,
  last_deploy_at: null,
}

// Radix DropdownMenu opens on a primary-button pointerdown, not a plain click.
function openMenu(trigger: HTMLElement) {
  fireEvent.pointerDown(
    trigger,
    new MouseEvent('pointerdown', { bubbles: true, button: 0 } as MouseEventInit)
  )
  fireEvent.pointerUp(
    trigger,
    new MouseEvent('pointerup', { bubbles: true, button: 0 } as MouseEventInit)
  )
}

function renderWithProviders(ui: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ToastProvider>{ui}</ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('EnvironmentSelector', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    permissions = { manage_environments: true }
    isAdmin = true
    __environmentStore.reset()
    listMock.mockResolvedValue([PROD, STAGING])
    setDefaultMock.mockResolvedValue(STAGING)
  })

  it("renders the team's environments in the dropdown", async () => {
    renderWithProviders(<EnvironmentSelector />)

    // Trigger shows the active env (auto-selected default = Production).
    const trigger = await screen.findByRole('button', { name: /active environment: production/i })
    openMenu(trigger)

    expect(await screen.findByText('Staging')).toBeInTheDocument()
    // Production appears in both trigger + menu.
    expect(screen.getAllByText('Production').length).toBeGreaterThan(0)
  })

  it('auto-selects the team default on load', async () => {
    renderWithProviders(<EnvironmentSelector />)
    await screen.findByRole('button', { name: /active environment: production/i })
    expect(getActiveEnvironmentId()).toBe('env-prod')
  })

  it('switching environment updates the store', async () => {
    renderWithProviders(<EnvironmentSelector />)
    const trigger = await screen.findByRole('button', { name: /active environment: production/i })
    openMenu(trigger)

    const staging = await screen.findByText('Staging')
    fireEvent.click(staging)

    await waitFor(() => {
      expect(getActiveEnvironmentId()).toBe('env-staging')
    })
  })

  it('renders nothing when there are no environments', async () => {
    listMock.mockResolvedValue([])
    const { container } = renderWithProviders(<EnvironmentSelector />)
    // No trigger button rendered.
    await waitFor(() => {
      expect(container.querySelector('button')).toBeNull()
    })
  })
})

describe('Environments list page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    permissions = { manage_environments: true }
    isAdmin = true
    __environmentStore.reset()
    listMock.mockResolvedValue([PROD, STAGING])
    createMock.mockResolvedValue(STAGING)
  })

  it('renders a card per environment with counts', async () => {
    renderWithProviders(<EnvironmentsPage />)

    expect(await screen.findByText('Production')).toBeInTheDocument()
    expect(screen.getByText('Staging')).toBeInTheDocument()
    // Rule + deployed counts surface on the cards.
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('30')).toBeInTheDocument()
  })

  it('shows the default + approval badges', async () => {
    renderWithProviders(<EnvironmentsPage />)
    await screen.findByText('Production')
    expect(screen.getByText('Default')).toBeInTheDocument()
    expect(screen.getByText('Approval')).toBeInTheDocument()
  })

  it('opens the New environment dialog for managers', async () => {
    renderWithProviders(<EnvironmentsPage />)
    await screen.findByText('Production')
    fireEvent.click(screen.getByRole('button', { name: /new environment/i }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
  })
})
