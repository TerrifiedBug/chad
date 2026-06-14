import { AuditLogEntry } from '@/lib/api'

/**
 * Client-side tamper-evidence check for the audit hash chain.
 *
 * The backend writes a forward-only SHA-256 chain: each row's `prev_hash` points
 * at the previous row's `hash`. We can't recompute the SHA-256 in the browser
 * (canonicalization lives server-side), but we CAN cheaply confirm the *linkage*
 * of the rows the user is currently looking at — if any adjacent pair's link is
 * broken, the chain has been tampered with or reordered.
 *
 * The list endpoint returns rows newest-first (created_at DESC), so the chain
 * runs backwards through the array: for adjacent rows [newer, older],
 * newer.prev_hash must equal older.hash.
 *
 * Rules:
 * - Legacy rows have NULL hashes (chain didn't exist yet). A run that contains
 *   any NULL-hash row is treated as unverifiable (neutral), not broken — we
 *   never claim "verified" over rows that carry no chain data.
 * - A single hashed row trivially verifies (nothing to contradict it).
 * - An empty list is unverifiable (neutral) — nothing to attest to.
 */
export function verifyChainLinks(rows: AuditLogEntry[]): boolean {
  if (rows.length === 0) return false

  // If any visible row lacks chain data, we can't make a verified claim.
  if (rows.some((r) => !r.hash || !r.prev_hash)) return false

  // Rows are newest-first; each newer row must link to the older one below it.
  for (let i = 0; i < rows.length - 1; i++) {
    const newer = rows[i]
    const older = rows[i + 1]
    if (newer.prev_hash !== older.hash) return false
  }

  return true
}
