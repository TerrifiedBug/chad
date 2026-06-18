import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const suggestExceptionsMock = vi.fn()

vi.mock('@/lib/api', () => ({
  aiCopilotApi: {
    suggestExceptions: (...a: unknown[]) => suggestExceptionsMock(...a),
  },
}))

import { ExceptionSuggestPanel } from '@/components/rules/ExceptionSuggestPanel'

describe('ExceptionSuggestPanel', () => {
  beforeEach(() => {
    suggestExceptionsMock.mockReset()
  })

  it('lists suggestions and fires onUse', async () => {
    suggestExceptionsMock.mockResolvedValue({
      suggestions: [
        {
          field: 'user.name',
          operator: 'equals',
          value: 'svc_backup',
          rationale: 'service account',
          risk: 'could hide real svc abuse',
        },
      ],
    })
    const onUse = vi.fn()
    render(
      <ExceptionSuggestPanel
        ruleYaml="title: t"
        falsePositiveExamples={[{ 'user.name': 'svc_backup' }]}
        onUse={onUse}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: /suggest exceptions/i }))
    expect(await screen.findByText('user.name')).toBeInTheDocument()
    expect(screen.getByText('svc_backup')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /^use$/i }))
    expect(onUse).toHaveBeenCalledWith({
      field: 'user.name',
      operator: 'equals',
      value: 'svc_backup',
    })
  })
})
