/** Must match backend MAX_BULK_OPERATIONS in backend/app/api/alerts.py */
export const BULK_CHUNK_SIZE = 100

export interface BulkProgress {
  completed: number
  total: number
}

export interface BulkResult {
  totalProcessed: number
  totalFailed: number
  errors: string[]
}

/**
 * Split a large bulk operation into sequential chunks of BULK_CHUNK_SIZE.
 *
 * @param ids - Full list of IDs to process
 * @param operation - Async function that processes one batch of IDs
 * @param onProgress - Optional callback after each batch completes
 * @returns Aggregated result with counts and any errors
 */
export async function chunkedBulkOperation(
  ids: string[],
  operation: (batchIds: string[]) => Promise<unknown>,
  onProgress?: (progress: BulkProgress) => void,
): Promise<BulkResult> {
  if (ids.length === 0) {
    return { totalProcessed: 0, totalFailed: 0, errors: [] }
  }

  const total = ids.length
  let totalProcessed = 0
  let totalFailed = 0
  const errors: string[] = []

  for (let i = 0; i < total; i += BULK_CHUNK_SIZE) {
    const batch = ids.slice(i, i + BULK_CHUNK_SIZE)
    try {
      await operation(batch)
      totalProcessed += batch.length
    } catch (err) {
      totalFailed += batch.length
      errors.push(err instanceof Error ? err.message : 'Unknown error')
    }
    onProgress?.({ completed: totalProcessed + totalFailed, total })
  }

  return { totalProcessed, totalFailed, errors }
}
