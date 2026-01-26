import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiClient } from '@/lib/api';

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
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: {
        get: (name: string) => name === 'X-CSRF-Token' ? 'test-csrf-token' : null,
      },
      json: async () => ({ data: 'test' }),
    } as Response);

    await apiClient.get('/test');

    // Token should be stored in memory for next request
    const secondCall = vi.mocked(global.fetch).mock.calls[1];
    expect(secondCall).toBeDefined();
  });

  it('should include CSRF token in POST requests', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: {
        get: (name: string) => name === 'X-CSRF-Token' ? 'test-csrf-token' : null,
      },
      json: async () => ({ success: true }),
    } as Response);

    await apiClient.get('/test'); // Get CSRF token
    await apiClient.post('/submit', { data: 'test' });

    const postCall = vi.mocked(global.fetch).mock.calls[1];
    expect(postCall).toBeDefined();
    const headers = postCall[1]?.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('test-csrf-token');
  });

  it('should not include CSRF token in GET requests', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: {
        get: (_name: string) => null,
      },
      json: async () => ({ data: 'test' }),
    } as Response);

    await apiClient.get('/test');

    const getCall = vi.mocked(global.fetch).mock.calls[0];
    const headers = getCall[1]?.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBeUndefined();
  });

  it('should include JWT token in requests when available', async () => {
    localStorage.setItem('chad-token', 'test-jwt-token');

    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: {
        get: (_name: string) => null,
      },
      json: async () => ({ data: 'test' }),
    } as Response);

    await apiClient.get('/test');

    const call = vi.mocked(global.fetch).mock.calls[0];
    const headers = call[1]?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer test-jwt-token');
  });

  it('should handle missing CSRF token gracefully', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: {
        get: (_name: string) => null,
      },
      json: async () => ({ data: 'test' }),
    } as Response);

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
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: false,
      json: async () => ({ detail: 'Unauthorized access' }),
    } as Response);

    await expect(apiClient.get('/test')).rejects.toThrow('Unauthorized access');
  });

  it('should throw generic error when response has no detail', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: 'Some error' }),
    } as Response);

    await expect(apiClient.get('/test')).rejects.toThrow('Request failed');
  });

  it('should throw generic error when JSON parsing fails', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: false,
      json: async () => {
        throw new Error('Invalid JSON');
      },
    } as Response);

    await expect(apiClient.get('/test')).rejects.toThrow('Request failed');
  });
});
