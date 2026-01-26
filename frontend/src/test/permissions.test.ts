import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, cleanup } from '@testing-library/react';
import { usePermissions } from '@/hooks/usePermissions';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}));

describe('Permission Checks', () => {
  it('should deny access when user lacks permission', () => {
    const { result } = renderHook(() =>
      usePermissions({
        permissions: ['view_rules'],
      })
    );

    expect(result.current.can('manage_rules')).toBe(false);
  });

  it('should grant access when user has permission', () => {
    const { result } = renderHook(() =>
      usePermissions({
        permissions: ['manage_rules', 'view_rules'],
        loading: false,
      })
    );

    expect(result.current.can('manage_rules')).toBe(true);
  });

  it('should grant admin access to all permissions', () => {
    const { result } = renderHook(() =>
      usePermissions({
        role: 'admin',
        loading: false,
      })
    );

    expect(result.current.can('any_permission')).toBe(true);
  });

  it('should handle loading state', () => {
    const { result } = renderHook(() =>
      usePermissions({
        permissions: [],
        loading: true,
      })
    );

    expect(result.current.can('any_action')).toBe(false);
  });
});
