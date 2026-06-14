import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui/toast-provider'

// Radix Select relies on Pointer Capture + scrollIntoView, which jsdom does not
// implement. Polyfill them so the dropdown opens under test.
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

// --- Mock the API layer ---
const envListMock = vi.fn()
const promoteMock = vi.fn()
const checkEligibilityMock = vi.fn()
const deployPreviewMock = vi.fn()

vi.mock('@/lib/api', () => ({
  environmentsApi: {
    list: (...args: unknown[]) => envListMock(...args),
    promote: (...args: unknown[]) => promoteMock(...args),
  },
  rulesApi: {
    checkDeploymentEligibility: (...args: unknown[]) => checkEligibilityMock(...args),
    deployPreview: (...args: unknown[]) => deployPreviewMock(...args),
  },
}))

// EnvironmentSelector re-exports the query key the dialog imports; stub it so the
// api mock above does not need EnvironmentSelector's full dependency tree.
vi.mock('@/components/EnvironmentSelector', () => ({
  ENVIRONMENTS_QUERY_KEY: 'environments',
}))

import { PromoteDialog } from '@/components/rules/PromoteDialog'

const DEV = {
  id: 'env-dev',
  name: 'Development',
  team_id: null,
  is_default: true,
  require_deploy_approval: false,
  description: null,
  opensearch_index_prefix: null,
  color: null,
  rule_count: 5,
  deployed_count: 3,
}
const PROD = {
  ...DEV,
  id: 'env-prod',
  name: 'Production',
  is_default: false,
  require_deploy_approval: true,
}

function renderDialog(props: Partial<React.ComponentProps<typeof PromoteDialog>> = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <PromoteDialog
          open
          onOpenChange={() => {}}
          rules={[{ id: 'rule-1', title: 'Suspicious PowerShell' }]}
          sourceEnvironmentId="env-dev"
          {...props}
        />
      </ToastProvider>
    </QueryClientProvider>
  )
}

// Walk the flow: pick the target env, advance through preflight + diff to the
// reason step, fill the reason, then advance to confirm.
async function walkToConfirm() {
  // Target step: open the Select and pick Production.
  fireEvent.click(await screen.findByLabelText('Target environment'))
  fireEvent.click(await screen.findByRole('option', { name: /Production/i }))
  fireEvent.click(screen.getByRole('button', { name: /next/i }))

  // Preflight → Diff.
  expect(await screen.findByText(/1 of 1 rule eligible/i)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /next/i }))

  // Diff → Reason.
  expect(await screen.findByText('title: new')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /next/i }))

  // Reason → Confirm.
  const reason = await screen.findByLabelText(/reason for promotion/i)
  fireEvent.change(reason, { target: { value: 'ready for prod' } })
  fireEvent.click(screen.getByRole('button', { name: /next/i }))
}

describe('PromoteDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    envListMock.mockResolvedValue([DEV, PROD])
    checkEligibilityMock.mockResolvedValue({ eligible: ['rule-1'], ineligible: [] })
    deployPreviewMock.mockResolvedValue({
      current_deployed_query: 'title: old',
      proposed_query: 'title: new',
      validation: { success: true, errors: [] },
      eligibility: { eligible: true, reason: null, unmapped_fields: [] },
      needs_redeploy: true,
      deployed_version: 1,
      current_version: 2,
    })
    promoteMock.mockResolvedValue({ pendingApproval: false, results: [] })
  })

  it('renders the target-env select, walks preflight + diff, and promotes', async () => {
    const onPromoted = vi.fn()
    renderDialog({ onPromoted })

    await walkToConfirm()

    // Target requires approval → confirm button reads "Submit for approval".
    fireEvent.click(await screen.findByRole('button', { name: /submit for approval/i }))

    // 202-less result here (gate mocked OFF) → promote called with the right body.
    await waitFor(() => {
      expect(promoteMock).toHaveBeenCalledWith('env-prod', {
        rule_ids: ['rule-1'],
        source_environment_id: 'env-dev',
        change_reason: 'ready for prod',
      })
    })
    await waitFor(() => expect(onPromoted).toHaveBeenCalled())
  })

  it('excludes the source/active env from the target options', async () => {
    renderDialog()
    fireEvent.click(await screen.findByLabelText('Target environment'))
    // Production is offered; the source env (Development) is not.
    expect(await screen.findByRole('option', { name: /Production/i })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /Development/i })).not.toBeInTheDocument()
  })

  it('handles the 202 pending-approval result', async () => {
    promoteMock.mockResolvedValue({
      pendingApproval: true,
      requestId: 'req-9',
      message: 'filed',
    })
    const onSubmittedForApproval = vi.fn()
    renderDialog({ onSubmittedForApproval })

    await walkToConfirm()
    fireEvent.click(await screen.findByRole('button', { name: /submit for approval/i }))

    await waitFor(() => expect(onSubmittedForApproval).toHaveBeenCalled())
    expect(promoteMock).toHaveBeenCalled()
  })

  it('blocks advancing past preflight when no rule is eligible', async () => {
    checkEligibilityMock.mockResolvedValue({
      eligible: [],
      ineligible: [{ id: 'rule-1', reason: 'Unmapped fields: foo' }],
    })
    renderDialog()

    fireEvent.click(await screen.findByLabelText('Target environment'))
    fireEvent.click(await screen.findByRole('option', { name: /Production/i }))
    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    expect(await screen.findByText(/0 of 1 rule eligible/i)).toBeInTheDocument()
    expect(screen.getByText(/Unmapped fields: foo/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
  })
})
