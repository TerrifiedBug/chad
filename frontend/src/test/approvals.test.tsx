import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const listMock = vi.fn()
const getMock = vi.fn()
const getStatsMock = vi.fn()
const approveMock = vi.fn()
const rejectMock = vi.fn()
const cancelMock = vi.fn()

vi.mock('@/lib/api', () => ({
  deploymentRequestsApi: {
    list: (...args: unknown[]) => listMock(...args),
    get: (...args: unknown[]) => getMock(...args),
    getStats: (...args: unknown[]) => getStatsMock(...args),
    approve: (...args: unknown[]) => approveMock(...args),
    reject: (...args: unknown[]) => rejectMock(...args),
    cancel: (...args: unknown[]) => cancelMock(...args),
  },
}))

// --- Mock auth: current user id + approve_deployments permission are configurable ---
let currentUserId = 'reviewer-1'
let permissions: Record<string, boolean> = { approve_deployments: true }
vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    user: { id: currentUserId },
    hasPermission: (p: string) => permissions[p] === true,
  }),
}))

import ApprovalsPage from '@/pages/Approvals'

const REQUESTER_ID = 'maker-1'

const baseRequest = {
  id: 'req-1',
  status: 'pending',
  requested_by: REQUESTER_ID,
  requester_email: 'maker@example.com',
  reviewed_by: null,
  reviewer_email: null,
  change_reason: 'Deploy the new rule',
  review_note: null,
  team_id: null,
  created_at: new Date().toISOString(),
  reviewed_at: null,
  applied_at: null,
  item_count: 1,
  rule_titles: ['Suspicious PowerShell'],
  age_seconds: 30,
}

const detailRequest = {
  ...baseRequest,
  items: [
    {
      id: 'item-1',
      kind: 'sigma',
      rule_id: 'rule-1',
      correlation_rule_id: null,
      rule_title: 'Suspicious PowerShell',
      version_number: 2,
      apply_status: null,
      apply_error: null,
      proposed_yaml: 'title: new',
      deployed_yaml: 'title: old',
      is_stale: false,
    },
  ],
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <ApprovalsPage />
      </ToastProvider>
    </QueryClientProvider>
  )
}

describe('ApprovalsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    currentUserId = 'reviewer-1'
    permissions = { approve_deployments: true }
    listMock.mockResolvedValue([baseRequest])
    getMock.mockResolvedValue(detailRequest)
    getStatsMock.mockResolvedValue({
      pending: 1,
      approved: 0,
      applied: 0,
      rejected: 0,
      cancelled: 0,
      stale: 0,
      failed: 0,
      avg_review_seconds: null,
    })
  })

  it('renders the queue of deployment requests', async () => {
    renderPage()
    expect(await screen.findByText('Suspicious PowerShell')).toBeInTheDocument()
    expect(screen.getByText('maker@example.com')).toBeInTheDocument()
  })

  it('enables Approve for a different reviewer', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('Suspicious PowerShell'))

    const dialog = await screen.findByRole('dialog')
    await waitFor(() => {
      expect(within(dialog).getByRole('button', { name: /approve/i })).toBeInTheDocument()
    })
    expect(within(dialog).getByRole('button', { name: /approve/i })).toBeEnabled()
  })

  it('disables Approve when the current user is the requester (self-review)', async () => {
    // Current user IS the requester -> self-review must block approval.
    currentUserId = REQUESTER_ID
    renderPage()
    fireEvent.click(await screen.findByText('Suspicious PowerShell'))

    const dialog = await screen.findByRole('dialog')
    await waitFor(() => {
      expect(within(dialog).getByRole('button', { name: /approve/i })).toBeInTheDocument()
    })
    expect(within(dialog).getByRole('button', { name: /approve/i })).toBeDisabled()
  })

  it('disables Approve when the user lacks approve_deployments', async () => {
    permissions = { approve_deployments: false }
    renderPage()
    fireEvent.click(await screen.findByText('Suspicious PowerShell'))

    const dialog = await screen.findByRole('dialog')
    await waitFor(() => {
      expect(within(dialog).getByRole('button', { name: /approve/i })).toBeInTheDocument()
    })
    expect(within(dialog).getByRole('button', { name: /approve/i })).toBeDisabled()
  })
})
