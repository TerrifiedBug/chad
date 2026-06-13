import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const getCountsMock = vi.fn();
vi.mock('@/lib/api', () => ({
  alertsApi: { getCounts: (...args: unknown[]) => getCountsMock(...args) },
}));

const healthMock = vi.fn();
vi.mock('@/hooks/useHealthStatus', () => ({
  useHealthStatus: () => healthMock(),
}));

import { useNavStatus } from '@/hooks/use-nav-status';

describe('useNavStatus', () => {
  beforeEach(() => {
    getCountsMock.mockReset();
    healthMock.mockReset();
  });

  it('derives critical health when a service is unhealthy and exposes the new-alert count', async () => {
    getCountsMock.mockResolvedValue({ by_status: { new: 3 } });
    healthMock.mockReturnValue({
      healthData: { services: [{ status: 'healthy' }, { status: 'unhealthy' }] },
    });

    const { result } = renderHook(() => useNavStatus());

    expect(result.current.healthStatus).toBe('critical');
    await waitFor(() => expect(result.current.alertCount).toBe(3));
  });

  it('reports healthy when all services are healthy', () => {
    getCountsMock.mockResolvedValue({ by_status: {} });
    healthMock.mockReturnValue({ healthData: { services: [{ status: 'healthy' }] } });

    const { result } = renderHook(() => useNavStatus());

    expect(result.current.healthStatus).toBe('healthy');
  });

  it('leaves status undefined and does not throw when data is unavailable', () => {
    getCountsMock.mockRejectedValue(new Error('OpenSearch down'));
    healthMock.mockReturnValue({ healthData: null });

    const { result } = renderHook(() => useNavStatus());

    expect(result.current.healthStatus).toBeUndefined();
  });
});
