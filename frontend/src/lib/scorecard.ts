export type ScorecardTone = 'good' | 'warn' | 'bad'

export function formatScorecard(
  resolvable: number,
  total: number
): { label: string; pct: number; tone: ScorecardTone } {
  const pct = total === 0 ? 0 : Math.round((resolvable / total) * 100)
  let tone: ScorecardTone = 'bad'
  if (pct >= 100) tone = 'good'
  else if (pct >= 50) tone = 'warn'
  return {
    label: `${resolvable} of ${total} fields resolvable`,
    pct,
    tone,
  }
}
