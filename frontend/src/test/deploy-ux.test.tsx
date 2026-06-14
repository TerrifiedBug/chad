import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const deployPreviewMock = vi.fn()
const deployMock = vi.fn()

vi.mock('@/lib/api', async () => {
  // Keep the real error class so `instanceof` checks in components still work.
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    rulesApi: {
      deployPreview: (...args: unknown[]) => deployPreviewMock(...args),
      deploy: (...args: unknown[]) => deployMock(...args),
    },
  }
})

import { DeployDialog } from '@/components/rules/DeployDialog'
import { DeployProgress } from '@/components/rules/DeployProgress'
import { getDeployBadge } from '@/components/rules/DeployStatusBadge'
import { __deployProgressStore } from '@/components/rules/deploy-progress-store'

const okPreview = {
  current_deployed_query: 'title: old',
  proposed_query: 'title: new',
  validation: { success: true, errors: [] },
  eligibility: { eligible: true, reason: null, unmapped_fields: [] },
  needs_redeploy: true,
  deployed_version: 1,
  current_version: 2,
  dry_run: { total_scanned: 1000, total_matches: 5, truncated: false, error: null },
}

function renderDialog(props: Partial<React.ComponentProps<typeof DeployDialog>> = {}) {
  return render(
    <ToastProvider>
      <DeployDialog
        open
        onOpenChange={() => {}}
        ruleId="rule-1"
        ruleTitle="Suspicious PowerShell"
        {...props}
      />
    </ToastProvider>
  )
}

describe('DeployDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    deployPreviewMock.mockResolvedValue(okPreview)
    deployMock.mockResolvedValue({
      pendingApproval: false,
      result: {
        success: true,
        rule_id: 'rule-1',
        deployed_version: 2,
        deployed_at: '2026-06-14T10:00:00Z',
      },
    })
  })

  it('runs the preflight, walks the steps, shows the diff, and deploys', async () => {
    const onDeployed = vi.fn()
    renderDialog({ onDeployed })

    // Preflight: validation + eligibility pass.
    expect(await screen.findByText('Validation passed')).toBeInTheDocument()
    expect(screen.getByText('Eligible for deployment')).toBeInTheDocument()
    // Dry-run summary folded in.
    expect(screen.getByText('Dry-run (last 24h)')).toBeInTheDocument()

    // Step → Diff (shows proposed line from the YamlDiff renderer).
    fireEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(await screen.findByText(/proposed query/i)).toBeInTheDocument()
    expect(screen.getByText('title: new')).toBeInTheDocument()

    // Step → Reason.
    fireEvent.click(screen.getByRole('button', { name: /next/i }))
    const reason = await screen.findByLabelText(/reason for deploy/i)
    fireEvent.change(reason, { target: { value: 'ready for prod' } })

    // Step → Confirm.
    fireEvent.click(screen.getByRole('button', { name: /next/i }))
    fireEvent.click(await screen.findByRole('button', { name: /^deploy$/i }))

    await waitFor(() => {
      expect(deployMock).toHaveBeenCalledWith('rule-1', 'ready for prod')
    })
    await waitFor(() => expect(onDeployed).toHaveBeenCalled())
  })

  it('blocks advancing past preflight when validation fails', async () => {
    deployPreviewMock.mockResolvedValue({
      ...okPreview,
      validation: { success: false, errors: [{ type: 'error', message: 'bad condition' }] },
    })
    renderDialog()

    expect(await screen.findByText('Validation failed')).toBeInTheDocument()
    expect(screen.getByText('bad condition')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
  })

  it('handles the 202 pending-approval result', async () => {
    deployMock.mockResolvedValue({
      pendingApproval: true,
      requestId: 'req-9',
      message: 'filed',
    })
    const onSubmittedForApproval = vi.fn()
    renderDialog({ requiresApproval: true, onSubmittedForApproval })

    await screen.findByText('Validation passed')
    fireEvent.click(screen.getByRole('button', { name: /next/i })) // diff
    fireEvent.click(await screen.findByRole('button', { name: /next/i })) // reason
    const reason = await screen.findByLabelText(/reason for deploy/i)
    fireEvent.change(reason, { target: { value: 'needs review' } })
    fireEvent.click(screen.getByRole('button', { name: /next/i })) // confirm

    // Approval notice present on the reason/confirm steps.
    expect(screen.getByText(/submitted for approval/i)).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: /submit for approval/i }))

    await waitFor(() => expect(onSubmittedForApproval).toHaveBeenCalled())
  })
})

describe('DeployProgress panel', () => {
  beforeEach(() => {
    __deployProgressStore.reset()
  })

  it('renders per-rule rows from deploy_progress messages', async () => {
    render(
      <ToastProvider>
        <DeployProgress />
      </ToastProvider>
    )

    // Nothing rendered before a batch starts.
    expect(screen.queryByLabelText(/bulk deploy progress/i)).not.toBeInTheDocument()

    act(() => {
      __deployProgressStore.startBatch([
        { id: 'r1', title: 'Rule One' },
        { id: 'r2', title: 'Rule Two' },
      ])
    })

    expect(await screen.findByText('Rule One')).toBeInTheDocument()
    expect(screen.getByText('Rule Two')).toBeInTheDocument()
    expect(screen.getByText('0 / 2')).toBeInTheDocument()

    // A success transition for r1.
    act(() => {
      __deployProgressStore.applyProgress({
        type: 'deploy_progress',
        rule_id: 'r1',
        rule_title: 'Rule One',
        status: 'success',
      })
    })
    expect(await screen.findByText('1 / 2')).toBeInTheDocument()

    // A failed transition for r2 surfaces the error + completes the batch.
    act(() => {
      __deployProgressStore.applyProgress({
        type: 'deploy_progress',
        rule_id: 'r2',
        rule_title: 'Rule Two',
        status: 'failed',
        error: 'boom',
      })
    })
    expect(await screen.findByText('2 / 2')).toBeInTheDocument()
    expect(screen.getByText('boom')).toBeInTheDocument()
    expect(screen.getByText('Deploy complete')).toBeInTheDocument()
  })
})

describe('getDeployBadge', () => {
  it('returns Deployed vN for a live current rule', () => {
    const b = getDeployBadge({ status: 'deployed', deployed_version: 3, needs_redeploy: false })
    expect(b.kind).toBe('deployed')
    expect(b.label).toBe('Deployed v3')
  })

  it('returns Needs redeploy when modified since deploy', () => {
    const b = getDeployBadge({ status: 'deployed', deployed_version: 3, needs_redeploy: true })
    expect(b.kind).toBe('needs_redeploy')
    expect(b.label).toBe('Needs redeploy')
  })

  it('returns Pending approval when an open request exists (highest precedence)', () => {
    const b = getDeployBadge({
      status: 'deployed',
      deployed_version: 3,
      needs_redeploy: true,
      has_open_request: true,
    })
    expect(b.kind).toBe('pending_approval')
    expect(b.label).toBe('Pending approval')
  })

  it('returns Snoozed (indefinite) for an indefinitely snoozed rule', () => {
    const b = getDeployBadge({ status: 'snoozed', snooze_indefinite: true })
    expect(b.kind).toBe('snoozed')
    expect(b.label).toBe('Snoozed (indefinite)')
  })

  it('returns Undeployed for an undeployed rule', () => {
    const b = getDeployBadge({ status: 'undeployed' })
    expect(b.kind).toBe('undeployed')
    expect(b.label).toBe('Undeployed')
  })
})
