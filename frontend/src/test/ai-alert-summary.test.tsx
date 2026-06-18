import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui/toast-provider'

// --- Mock the API layer ---
const summarizeAlertMock = vi.fn()

vi.mock('@/lib/api', () => ({
  aiCopilotApi: {
    summarizeAlert: (...args: unknown[]) => summarizeAlertMock(...args),
  },
}))

import { AiAlertSummaryCard } from '@/components/ai/AiAlertSummaryCard'

const LOG_DOC = { event: { action: 'logon-failed' }, user: { name: 'alice' } }

function renderCard(props: Partial<React.ComponentProps<typeof AiAlertSummaryCard>> = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AiAlertSummaryCard logDocument={LOG_DOC} {...props} />
      </ToastProvider>
    </QueryClientProvider>
  )
}

describe('AiAlertSummaryCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('summarizes the alert and renders the summary plus recommended actions', async () => {
    summarizeAlertMock.mockResolvedValue({
      summary: 'A failed logon for alice on host-1 indicates possible brute force.',
      recommended_actions: ['Check source IP reputation', 'Lock the account if unrecognized'],
    })

    renderCard()

    fireEvent.click(screen.getByRole('button', { name: /summarize with ai/i }))

    await waitFor(() =>
      expect(summarizeAlertMock).toHaveBeenCalledWith(LOG_DOC)
    )

    expect(
      await screen.findByText(/possible brute force/i)
    ).toBeInTheDocument()
    expect(screen.getByText('Check source IP reputation')).toBeInTheDocument()
    expect(screen.getByText('Lock the account if unrecognized')).toBeInTheDocument()
  })

  it('shows an error toast when the API call fails', async () => {
    summarizeAlertMock.mockRejectedValue(new Error('AI provider not configured'))

    renderCard()
    fireEvent.click(screen.getByRole('button', { name: /summarize with ai/i }))

    expect(
      await screen.findByText('AI provider not configured')
    ).toBeInTheDocument()
  })

  it('disables the trigger button when disabled prop is set', () => {
    renderCard({ disabled: true })
    expect(screen.getByRole('button', { name: /summarize with ai/i })).toBeDisabled()
  })
})
