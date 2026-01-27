import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SigmaHQPage } from '../SigmaHQ'
import { sigmahqApi } from '@/lib/api'

// Mock the API
vi.mock('@/lib/api', () => ({
  sigmahqApi: {
    importRule: vi.fn(),
    getStatus: vi.fn(() => Promise.resolve({ cloned: true })),
    getCategories: vi.fn(() => Promise.resolve({ categories: [] })),
  },
}))

describe('SigmaHQ Import Duplicate Prevention', () => {
  it('prevents multiple rapid clicks', async () => {
    const { user } = render(<SigmaHQPage />)

    // Mock successful import
    sigmahqApi.importRule.mockResolvedValue({
      success: true,
      rule_id: '123',
      title: 'Test Rule'
    })

    // Click import button 3 times rapidly
    const importButton = await screen.findByText('Import')
    fireEvent.click(importButton)
    fireEvent.click(importButton)
    fireEvent.click(importButton)

    // Verify API called only once
    await waitFor(() => {
      expect(sigmahqApi.importRule).toHaveBeenCalledTimes(1)
    })
  })
})
