import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer (deploymentRequestsApi + environmentsApi) ---
const listMock = vi.fn()
const getMock = vi.fn()
const getStatsMock = vi.fn()
const approveMock = vi.fn()
const rejectMock = vi.fn()
const cancelMock = vi.fn()
const envListMock = vi.fn()

vi.mock('@/lib/api', () => ({
  deploymentRequestsApi: {
    list: (...args: unknown[]) => listMock(...args),
    get: (...args: unknown[]) => getMock(...args),
    getStats: (...args: unknown[]) => getStatsMock(...args),
    approve: (...args: unknown[]) => approveMock(...args),
    reject: (...args: unknown[]) => rejectMock(...args),
    cancel: (...args: unknown[]) => cancelMock(...args),
  },
  environmentsApi: {
    list: (...args: unknown[]) => envListMock(...args),
  },
}))

// EnvironmentSelector re-exports the query key Approvals imports; stub it so the
// api mock above is all the page needs.
vi.mock('@/components/EnvironmentSelector', () => ({
  ENVIRONMENTS_QUERY_KEY: 'environments',
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    user: { id: 'reviewer-1' },
    hasPermission: () => true,
  }),
}))

import ApprovalsPage from '@/pages/Approvals'

// A promotion request: carries target_environment_id (→ Production).
const promotionRequest = {
  id: 'req-promo',
  status: 'pending',
  requested_by: 'maker-1',
  requester_email: 'maker@example.com',
  reviewed_by: null,
  reviewer_email: null,
  change_reason: 'Promote to prod',
  review_note: null,
  team_id: null,
  created_at: new Date().toISOString(),
  reviewed_at: null,
  applied_at: null,
  item_count: 1,
  rule_titles: ['Suspicious PowerShell'],
  age_seconds: 30,
  target_environment_id: 'env-prod',
}

const promotionDetail = {
  ...promotionRequest,
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

describe('ApprovalsPage — promotion target-env badge', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue([promotionRequest])
    getMock.mockResolvedValue(promotionDetail)
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
    envListMock.mockResolvedValue([
      {
        id: 'env-prod',
        name: 'Production',
        team_id: null,
        is_default: false,
        require_deploy_approval: true,
        description: null,
        opensearch_index_prefix: null,
        color: null,
        rule_count: 1,
        deployed_count: 1,
      },
    ])
  })

  it('shows the target-env badge on a promotion request row', async () => {
    renderPage()
    // The badge resolves "Production" from the env list for the target_environment_id.
    expect(await screen.findByLabelText('Promote to Production')).toBeInTheDocument()
  })

  it('shows the target-env badge in the request detail panel', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('Suspicious PowerShell'))

    const dialog = await screen.findByRole('dialog')
    await waitFor(() => {
      expect(within(dialog).getByLabelText('Promote to Production')).toBeInTheDocument()
    })
  })
})
