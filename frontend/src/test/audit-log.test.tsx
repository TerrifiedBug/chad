import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const listMock = vi.fn()
const getActionsMock = vi.fn()
const getResourceTypesMock = vi.fn()
const exportMock = vi.fn()
const exportChainMock = vi.fn()

vi.mock('@/lib/api', () => ({
  auditApi: {
    list: (...args: unknown[]) => listMock(...args),
    getActions: (...args: unknown[]) => getActionsMock(...args),
    getResourceTypes: (...args: unknown[]) => getResourceTypesMock(...args),
    export: (...args: unknown[]) => exportMock(...args),
    exportChain: (...args: unknown[]) => exportChainMock(...args),
  },
}))

import AuditLogPage from '@/pages/AuditLog'

const activityRow = {
  id: 'audit-1',
  user_id: 'user-1',
  user_email: 'analyst@example.com',
  action: 'rule.create',
  resource_type: 'rule',
  resource_id: 'rule-abc-123',
  details: { name: 'Test Rule' },
  ip_address: '10.0.0.5',
  created_at: new Date('2026-06-14T09:00:00Z').toISOString(),
  prev_hash: null,
  hash: null,
}

const deployRow = {
  id: 'audit-2',
  user_id: 'user-2',
  user_email: 'admin@example.com',
  action: 'rule.deploy',
  resource_type: 'rule',
  resource_id: 'rule-def-456',
  details: { before: { status: 'undeployed' }, after: { status: 'deployed' } },
  ip_address: '10.0.0.6',
  created_at: new Date('2026-06-14T09:05:00Z').toISOString(),
  prev_hash: null,
  hash: null,
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <AuditLogPage />
      </ToastProvider>
    </MemoryRouter>
  )
}

describe('AuditLogPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({
      items: [deployRow, activityRow],
      total: 2,
      limit: 50,
      offset: 0,
    })
    getActionsMock.mockResolvedValue({ actions: ['rule.create', 'rule.deploy'] })
    getResourceTypesMock.mockResolvedValue({ resource_types: ['rule'] })
  })

  it('renders both Activity Log and Deployments tabs', async () => {
    renderPage()
    expect(await screen.findByRole('tab', { name: /activity log/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /deployments/i })).toBeInTheDocument()
  })

  it('opens the detail drawer with Object and Raw JSON sections on row click', async () => {
    renderPage()

    // Wait for rows to load, then click the activity row.
    const row = await screen.findByText('analyst@example.com')
    fireEvent.click(row)

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('Object')).toBeInTheDocument()
    expect(within(drawer).getByText('Raw JSON')).toBeInTheDocument()
    // Copy-to-clipboard control is present.
    expect(within(drawer).getByRole('button', { name: /copy/i })).toBeInTheDocument()
  })

  it('shows a Diff section only when details carry before/after', async () => {
    renderPage()

    // The deploy row carries before/after -> Diff section renders.
    const deployCell = await screen.findByText('admin@example.com')
    fireEvent.click(deployCell)

    const drawer = await screen.findByRole('dialog')
    await waitFor(() => {
      expect(within(drawer).getByText('Diff')).toBeInTheDocument()
    })
  })

  it('filters to deployment actions on the Deployments tab', async () => {
    const user = userEvent.setup()
    renderPage()

    // Both rows visible on Activity Log.
    expect(await screen.findByText('analyst@example.com')).toBeInTheDocument()
    expect(screen.getByText('admin@example.com')).toBeInTheDocument()

    // Switch to Deployments -> only the rule.deploy row remains. Radix tab
    // triggers activate on pointer events, so use userEvent (not fireEvent).
    await user.click(screen.getByRole('tab', { name: /deployments/i }))
    await waitFor(() => {
      expect(screen.queryByText('analyst@example.com')).not.toBeInTheDocument()
    })
    expect(screen.getByText('admin@example.com')).toBeInTheDocument()
  })
})
