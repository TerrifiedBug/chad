import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useHealthStatus } from '@/hooks/useHealthStatus';

// Mock the API
vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
  },
  settingsApi: {
    getVersion: vi.fn(),
    checkForUpdates: vi.fn(),
  },
}));

describe('useHealthStatus Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  it('should initialize with no unhealthy services', async () => {
    const { api } = await import('@/lib/api');
    vi.mocked(api.get).mockResolvedValueOnce({
      services: [],
      recent_checks: [],
    });

    const { result } = renderHook(() => useHealthStatus());

    // Wait for the hook to finish loading
    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.unhealthyCount).toBe(0);
  });

  it('should count unhealthy services', async () => {
    const { api } = await import('@/lib/api');
    vi.mocked(api.get).mockResolvedValueOnce({
      services: [
        { service_type: 'database', service_name: 'db', status: 'healthy', last_check: '2024-01-01' },
        { service_type: 'opensearch', service_name: 'os', status: 'unhealthy', last_check: '2024-01-01' },
        { service_type: 'scheduler', service_name: 'sched', status: 'warning', last_check: '2024-01-01' },
      ],
      recent_checks: [],
    });

    const { result } = renderHook(() => useHealthStatus());

    // Wait for state to update
    await waitFor(() => {
      expect(result.current.unhealthyCount).toBeGreaterThan(0);
    });
  });

  it('should handle API errors gracefully', async () => {
    const { api } = await import('@/lib/api');
    vi.mocked(api.get).mockRejectedValueOnce(new Error('Network error'));

    const { result } = renderHook(() => useHealthStatus());

    // Should not throw, just handle error
    await waitFor(() => {
      expect(result.current.error).toBe('Failed to fetch health status');
    });
  });
});

describe('useVersion Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should parse version from package.json', async () => {
    // Mock version hook behavior
    const { settingsApi } = await import('@/lib/api');
    vi.mocked(settingsApi.getVersion).mockResolvedValueOnce({
      version: '1.0.0',
    });

    const { useVersion } = await import('@/hooks/use-version');
    const { result } = renderHook(() => useVersion());

    await waitFor(() => {
      expect(result.current.version).toBeDefined();
    });
  });
});
