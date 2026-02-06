/**
 * Integration tests for alert API functions
 * Tests React Query cache invalidation and permission handling
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { alertsApi, ALERTS_QUERY_KEY, AlertStatus } from '@/lib/api'
import { queryClient } from '@/lib/api'

// Mock fetch
const mockFetch = vi.fn()
global.fetch = mockFetch

describe('Alerts API - Cache Invalidation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Mock successful responses
    mockFetch.mockResolvedValue({
      ok: true,
      headers: new Headers(),
      json: async () => ({}),
    })
  })

  describe('delete', () => {
    it('should delete alert and invalidate cache', async () => {
      const alertId = '123e4567-e89b-12d3-a456-426614174000'
      const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

      await alertsApi.delete(alertId)

      // Verify DELETE request was made
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts/' + alertId,
        expect.objectContaining({
          method: 'DELETE',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      )

      // Verify cache was invalidated
      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: [ALERTS_QUERY_KEY],
      })
    })

    it('should handle delete errors without invalidating cache', async () => {
      const alertId = '123e4567-e89b-12d3-a456-426614174000'
      const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

      // Mock error response
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      await expect(alertsApi.delete(alertId)).rejects.toThrow('Network error')

      // Cache should NOT be invalidated on error
      expect(invalidateSpy).not.toHaveBeenCalled()
    })
  })

  describe('bulkDelete', () => {
    it('should bulk delete alerts and invalidate cache', async () => {
      const alertIds = [
        '123e4567-e89b-12d3-a456-426614174000',
        '223e4567-e89b-12d3-a456-426614174001',
        '323e4567-e89b-12d3-a456-426614174002',
      ]
      const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

      await alertsApi.bulkDelete({ alert_ids: alertIds })

      // Verify bulk delete request
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts/bulk/delete',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({ alert_ids: alertIds }),
        })
      )

      // Verify cache was invalidated
      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: [ALERTS_QUERY_KEY],
      })
    })

    it('should handle empty alert IDs array', async () => {
      const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

      await alertsApi.bulkDelete({ alert_ids: [] })

      // Should still make request with empty array
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts/bulk/delete',
        expect.objectContaining({
          body: JSON.stringify({ alert_ids: [] }),
        })
      )

      // Cache should be invalidated
      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: [ALERTS_QUERY_KEY],
      })
    })
  })

  describe('bulkUpdateStatus', () => {
    it('should update status and invalidate cache', async () => {
      const alertIds = [
        '123e4567-e89b-12d3-a456-426614174000',
        '223e4567-e89b-12d3-a456-426614174001',
      ]
      const status = 'acknowledged'
      const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

      await alertsApi.bulkUpdateStatus({ alert_ids: alertIds, status })

      // Verify bulk status update request
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts/bulk/status',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({ alert_ids: alertIds, status }),
        })
      )

      // Verify cache was invalidated
      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: [ALERTS_QUERY_KEY],
      })
    })

    it('should support all status values', async () => {
      const statuses: AlertStatus[] = ['new', 'acknowledged', 'resolved', 'false_positive']

      for (const status of statuses) {
        await alertsApi.bulkUpdateStatus({ alert_ids: ['test-id'], status })

        expect(mockFetch).toHaveBeenCalledWith(
          '/api/alerts/bulk/status',
          expect.objectContaining({
            body: JSON.stringify({
              alert_ids: ['test-id'],
              status,
            }),
          })
        )
      }
    })
  })

  describe('list', () => {
    it('should fetch alerts list', async () => {
      const mockAlerts = {
        items: [
          { id: '1', title: 'Alert 1', status: 'new' },
          { id: '2', title: 'Alert 2', status: 'acknowledged' },
        ],
        total: 2,
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers(),
        json: async () => mockAlerts,
      })

      const alerts = await alertsApi.list()

      expect(alerts).toEqual(mockAlerts)
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts',
        expect.anything() // Don't check method since API client doesn't set it for GET
      )
    })

    it('should include auth token in requests', async () => {
      const token = 'test-jwt-token'
      localStorage.setItem('chad-token', token)

      await alertsApi.list()

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/alerts',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Bearer ${token}`,
          }),
        })
      )

      localStorage.removeItem('chad-token')
    })
  })
})

describe('Alerts API - Query Key Constants', () => {
  it('should export ALERTS_QUERY_KEY constant', () => {
    expect(ALERTS_QUERY_KEY).toBe('alerts')
  })

  it('should use query key in cache invalidation', async () => {
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

    await alertsApi.delete('test-id')

    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: [ALERTS_QUERY_KEY],
    })
  })
})

describe('Alerts API - Error Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should throw error on failed delete', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      headers: new Headers(),
      json: async () => ({ detail: 'Permission denied' }),
    })

    await expect(alertsApi.delete('test-id')).rejects.toThrow('Permission denied')
  })

  it('should throw error on failed bulk delete', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      headers: new Headers(),
      json: async () => ({ detail: 'Invalid request' }),
    })

    await expect(alertsApi.bulkDelete({ alert_ids: ['test-id'] })).rejects.toThrow('Invalid request')
  })

  it('should throw error on failed status update', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      headers: new Headers(),
      json: async () => ({ detail: 'Internal server error' }),
    })

    await expect(
      alertsApi.bulkUpdateStatus({ alert_ids: ['test-id'], status: 'acknowledged' })
    ).rejects.toThrow('Internal server error')
  })

  it('should not invalidate cache on permission errors', async () => {
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      headers: new Headers(),
      json: async () => ({ detail: 'Permission denied' }),
    })

    await expect(alertsApi.delete('test-id')).rejects.toThrow()

    // Cache should not be invalidated on permission error
    expect(invalidateSpy).not.toHaveBeenCalled()
  })
})

describe('React Query Integration', () => {
  it('should export queryClient instance', () => {
    expect(queryClient).toBeDefined()
    expect(queryClient instanceof Object).toBe(true)
  })

  it('should have configured default options', () => {
    const defaultOptions = queryClient.getDefaultOptions()

    expect(defaultOptions?.mutations?.retry).toBe(1)
    expect(defaultOptions?.queries?.retry).toBe(1)
    expect(defaultOptions?.queries?.staleTime).toBe(5 * 60 * 1000) // 5 minutes
  })
})
