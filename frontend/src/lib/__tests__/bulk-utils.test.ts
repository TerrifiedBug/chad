import { describe, it, expect, vi } from 'vitest'
import { chunkedBulkOperation, BULK_CHUNK_SIZE } from '../bulk-utils'

describe('chunkedBulkOperation', () => {
  it('sends all items in one batch when <= BULK_CHUNK_SIZE', async () => {
    const ids = Array.from({ length: 50 }, (_, i) => `id-${i}`)
    const operation = vi.fn().mockResolvedValue(undefined)
    const onProgress = vi.fn()

    const result = await chunkedBulkOperation(ids, operation, onProgress)

    expect(operation).toHaveBeenCalledTimes(1)
    expect(operation).toHaveBeenCalledWith(ids)
    expect(result).toEqual({ totalProcessed: 50, totalFailed: 0, errors: [] })
    expect(onProgress).toHaveBeenCalledWith({ completed: 50, total: 50 })
  })

  it('splits into multiple batches when > BULK_CHUNK_SIZE', async () => {
    const ids = Array.from({ length: 250 }, (_, i) => `id-${i}`)
    const operation = vi.fn().mockResolvedValue(undefined)
    const onProgress = vi.fn()

    await chunkedBulkOperation(ids, operation, onProgress)

    expect(operation).toHaveBeenCalledTimes(3)
    expect(operation).toHaveBeenNthCalledWith(1, ids.slice(0, 100))
    expect(operation).toHaveBeenNthCalledWith(2, ids.slice(100, 200))
    expect(operation).toHaveBeenNthCalledWith(3, ids.slice(200, 250))
    expect(onProgress).toHaveBeenCalledTimes(3)
    expect(onProgress).toHaveBeenNthCalledWith(1, { completed: 100, total: 250 })
    expect(onProgress).toHaveBeenNthCalledWith(2, { completed: 200, total: 250 })
    expect(onProgress).toHaveBeenNthCalledWith(3, { completed: 250, total: 250 })
  })

  it('continues on batch failure and reports errors', async () => {
    const ids = Array.from({ length: 200 }, (_, i) => `id-${i}`)
    const operation = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Batch 2 failed'))
    const onProgress = vi.fn()

    const result = await chunkedBulkOperation(ids, operation, onProgress)

    expect(result.totalProcessed).toBe(100)
    expect(result.totalFailed).toBe(100)
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]).toContain('Batch 2 failed')
  })

  it('returns immediately for empty array', async () => {
    const operation = vi.fn()
    const result = await chunkedBulkOperation([], operation)
    expect(operation).not.toHaveBeenCalled()
    expect(result).toEqual({ totalProcessed: 0, totalFailed: 0, errors: [] })
  })

  it('works without onProgress callback', async () => {
    const ids = Array.from({ length: 50 }, (_, i) => `id-${i}`)
    const operation = vi.fn().mockResolvedValue(undefined)
    const result = await chunkedBulkOperation(ids, operation)
    expect(result.totalProcessed).toBe(50)
  })

  it('exports BULK_CHUNK_SIZE as 100', () => {
    expect(BULK_CHUNK_SIZE).toBe(100)
  })
})
