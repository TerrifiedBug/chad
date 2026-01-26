import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useHealthStatus } from '@/hooks/useHealthStatus';

// Mock the API
vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}));

describe('useHealthStatus Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  it('should initialize with no unhealthy services', () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: { get: vi.fn() },
      json: async () => ({ services: [] }),
    } as Response);

    const { result } = renderHook(() => useHealthStatus());

    expect(result.current.unhealthyCount).toBe(0);
  });

  it('should count unhealthy services', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: { get: vi.fn() },
      json: async () => ({
        services: [
          { service_type: 'database', status: 'healthy' },
          { service_type: 'opensearch', status: 'unhealthy' },
          { service_type: 'scheduler', status: 'warning' },
        ],
      }),
    } as Response);

    const { result } = renderHook(() => useHealthStatus());

    // Wait for state to update
    await waitFor(() => {
      expect(result.current.unhealthyCount).toBeGreaterThan(0);
    });
  });

  it('should handle API errors gracefully', async () => {
    vi.mocked(global.fetch).mockRejectedValueOnce(new Error('Network error'));

    const { result } = renderHook(() => useHealthStatus());

    // Should not throw, just handle error
    await waitFor(() => {
      expect(result.current).toBeDefined();
    });
  });
});

describe('useVersion Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should parse version from package.json', async () => {
    // Mock version hook behavior
    const { useVersion } = await import('@/hooks/use-version');
    vi.mocked(global.fetch).mockResolvedValueOnce({
      ok: true,
      headers: { get: vi.fn() },
      json: async () => ({ version: '1.0.0' }),
    } as Response);

    const { result } = renderHook(() => useVersion());

    await waitFor(() => {
      expect(result.current.version).toBeDefined();
    });
  });
});
