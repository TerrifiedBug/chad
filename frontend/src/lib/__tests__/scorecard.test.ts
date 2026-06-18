import { describe, it, expect } from 'vitest'
import { formatScorecard } from '../scorecard'

describe('formatScorecard', () => {
  it('labels X of Y resolvable', () => {
    const r = formatScorecard(3, 5)
    expect(r.label).toBe('3 of 5 fields resolvable')
    expect(r.pct).toBe(60)
  })

  it('handles zero total without dividing by zero', () => {
    const r = formatScorecard(0, 0)
    expect(r.pct).toBe(0)
    expect(r.label).toBe('0 of 0 fields resolvable')
  })

  it('tone is good at 100%', () => {
    expect(formatScorecard(4, 4).tone).toBe('good')
  })

  it('tone is warn between 50 and 99%', () => {
    expect(formatScorecard(3, 5).tone).toBe('warn')
  })

  it('tone is bad below 50%', () => {
    expect(formatScorecard(1, 5).tone).toBe('bad')
  })

  it('rounds percentage', () => {
    expect(formatScorecard(1, 3).pct).toBe(33)
  })
})
