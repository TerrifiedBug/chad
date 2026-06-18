import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ToastProvider } from '@/components/ui/toast-provider'

vi.mock('@/lib/api', () => ({
  reportSchedulesApi: { list: () => Promise.resolve([]) },
  statsApi: {
    getRulePrecision: () => Promise.resolve({
      window_days: 30,
      opensearch_available: true,
      rules: [
        {
          rule_id: 'r1', rule_title: 'Noisy Rule', total: 100, resolved: 10,
          false_positive: 80, open: 10, precision_pct: 11.1, fp_rate_pct: 80.0,
          alerts_per_day: 3.3,
        },
      ],
    }),
  },
}))

import Reports from '@/pages/Reports'

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ToastProvider>
          <Reports />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Rule precision leaderboard', () => {
  it('renders the leaderboard rows from statsApi', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('Noisy Rule')).toBeInTheDocument())
    expect(screen.getByText('80%')).toBeInTheDocument()
    expect(screen.getByText('Rule precision leaderboard')).toBeInTheDocument()
  })
})
