import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { YamlDiff } from '@/components/YamlDiff'

// Regression: deploying a rule with no prior deployed version (or a preview with
// no proposed_query) passed undefined into the diff library, which called
// `.split` internally and crashed the diff page with "e.split is not a function".
describe('YamlDiff', () => {
  it('does not crash when current/proposed are undefined', () => {
    expect(() =>
      render(
        <YamlDiff
          current={undefined as unknown as string}
          proposed={undefined as unknown as string}
        />
      )
    ).not.toThrow()
  })

  it('renders a normal line diff', () => {
    const { container } = render(<YamlDiff current={'a\nb\n'} proposed={'a\nc\n'} />)
    expect(container.textContent).toContain('c')
  })
})
