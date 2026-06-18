export type ScorecardTone = 'good' | 'warn' | 'bad'

/**
 * Canonical Sigma detection fields the deterministic preset auto-mapper knows
 * how to resolve. Mirrors the keys of SCHEMA_PRESETS on the backend
 * (app/services/schema_presets.py) — the rule's "required" fields. Auto-map and
 * the scorecard score these, NOT the already-mapped subset, so that auto-map
 * actually has unmapped fields to resolve.
 */
export const REQUIRED_SIGMA_FIELDS: string[] = [
  'SourceIp',
  'DestinationIp',
  'SourcePort',
  'DestinationPort',
  'User',
  'Image',
  'CommandLine',
  'ParentImage',
  'TargetFilename',
]

/**
 * Return the required Sigma fields that are not yet mapped, given the list of
 * already-mapped sigma_field names. These are the fields auto-map should send.
 */
export function unmappedRequiredFields(mappedSigmaFields: string[]): string[] {
  const mapped = new Set(mappedSigmaFields)
  return REQUIRED_SIGMA_FIELDS.filter((f) => !mapped.has(f))
}

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
