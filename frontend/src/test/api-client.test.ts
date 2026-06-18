import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiClient, rulesApi } from '@/lib/api';
import { createMockResponse, createSuccessResponse, createErrorResponse, createLegacyErrorResponse } from './mocks';

// Mock fetch
global.fetch = vi.fn();

describe('API Client CSRF Handling', () => {
  let apiClient: ApiClient;

  beforeEach(() => {
    vi.clearAllMocks();
    apiClient = new ApiClient();
    localStorage.clear();
  });

  it('should store CSRF token from response headers', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createMockResponse({
        ok: true,
        headers: {
          'X-CSRF-Token': 'test-csrf-token',
        },
        json: async () => ({ data: 'test' }),
      })
    );

    await apiClient.get('/test');

    // Verify fetch was called
    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(1);
    const call = vi.mocked(global.fetch).mock.calls[0];
    expect(call).toBeDefined();
  });

  it('should include CSRF token in POST requests', async () => {
    // Mock GET request that returns CSRF token
    vi.mocked(global.fetch)
      .mockResolvedValueOnce(
        createMockResponse({
          ok: true,
          headers: {
            'X-CSRF-Token': 'test-csrf-token',
          },
          json: async () => ({ data: 'test' }),
        })
      )
      // Mock POST request
      .mockResolvedValueOnce(createSuccessResponse({ success: true }));

    await apiClient.get('/test'); // Get CSRF token
    await apiClient.post('/submit', { data: 'test' });

    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(2);
    const postCall = vi.mocked(global.fetch).mock.calls[1];
    expect(postCall).toBeDefined();
    const headers = postCall[1]?.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('test-csrf-token');
  });

  it('should not include CSRF token in GET requests', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createSuccessResponse({ data: 'test' })
    );

    await apiClient.get('/test');

    const getCall = vi.mocked(global.fetch).mock.calls[0];
    const headers = getCall[1]?.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBeUndefined();
  });

  it('should include JWT token in requests when available', async () => {
    localStorage.setItem('chad-token', 'test-jwt-token');

    vi.mocked(global.fetch).mockResolvedValueOnce(
      createSuccessResponse({ data: 'test' })
    );

    await apiClient.get('/test');

    const call = vi.mocked(global.fetch).mock.calls[0];
    const headers = call[1]?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer test-jwt-token');
  });

  it('should handle missing CSRF token gracefully', async () => {
    // Mock GET request without CSRF token
    vi.mocked(global.fetch)
      .mockResolvedValueOnce(createSuccessResponse({ data: 'test' }))
      // Mock POST request
      .mockResolvedValueOnce(createSuccessResponse({ success: true }));

    // First request without CSRF token
    await apiClient.get('/test');

    // POST request should still work, just without CSRF token
    await apiClient.post('/submit', { data: 'test' });

    expect(vi.mocked(global.fetch)).toHaveBeenCalledTimes(2);
  });
});

describe('API Client Error Handling', () => {
  let apiClient: ApiClient;

  beforeEach(() => {
    vi.clearAllMocks();
    apiClient = new ApiClient();
  });

  it('should throw error with detail from response', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createErrorResponse('Unauthorized access', 401)
    );

    await expect(apiClient.get('/test')).rejects.toThrow('Unauthorized access');
  });

  it('should throw generic error when response has no detail', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createLegacyErrorResponse('Some error', 400)
    );

    await expect(apiClient.get('/test')).rejects.toThrow('Request failed');
  });

  it('should throw generic error when JSON parsing fails', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createMockResponse({
        ok: false,
        status: 500,
        json: async () => {
          throw new Error('Invalid JSON');
        },
      })
    );

    await expect(apiClient.get('/test')).rejects.toThrow('Request failed');
  });
});

describe('rulesApi.previewException', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('POSTs clauses to the preview endpoint and parses the delta', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      createSuccessResponse({ total_matches: 10, suppressed: 4, remaining: 6 })
    );

    const start = new Date('2026-01-01T00:00:00.000Z');
    const end = new Date('2026-01-02T00:00:00.000Z');
    const result = await rulesApi.previewException('rule-1', start, end, [
      { field: 'user.name', value: 'svc_backup' },
    ]);

    expect(result).toEqual({ total_matches: 10, suppressed: 4, remaining: 6 });

    const call = vi.mocked(global.fetch).mock.calls[0];
    expect(call[0]).toContain('/rules/rule-1/exceptions/preview');
    expect(call[1]?.method).toBe('POST');
    const body = JSON.parse(call[1]?.body as string);
    expect(body.start_date).toBe(start.toISOString());
    expect(body.end_date).toBe(end.toISOString());
    expect(body.clauses).toEqual([
      { field: 'user.name', operator: 'equals', value: 'svc_backup' },
    ]);
  });
});
