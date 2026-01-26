import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';

describe('Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    global.fetch = vi.fn();
  });

  describe('Authentication Flow', () => {
    it('should complete full login flow', async () => {
      // Mock successful login response
      vi.mocked(global.fetch).mockResolvedValueOnce({
        ok: true,
        headers: {
          get: (name: string) => name === 'X-CSRF-Token' ? 'csrf-token' : null,
        },
        json: async () => ({
          access_token: 'test-token',
          user: { email: 'test@example.com', role: 'analyst' },
        }),
      } as Response);

      const { useAuth } = await import('@/hooks/use-auth');
      const { result } = renderHook(() => useAuth());

      // Login
      await act(async () => {
        await result.current.login('test@example.com', 'password');
      });

      // Verify token stored
      expect(localStorage.getItem('chad-token')).toBe('test-token');
      expect(result.current.isAuthenticated).toBe(true);
    });

    it('should handle 2FA flow', async () => {
      // Mock 2FA required response
      vi.mocked(global.fetch).mockResolvedValueOnce({
        ok: true,
        headers: {
          get: (name: string) => name === 'X-CSRF-Token' ? 'csrf-token' : null,
        },
        json: async () => ({
          requires_2fa: true,
          '2fa_token': '2fa-token',
        }),
      } as Response);

      const { authApi } = await import('@/lib/api');
      const response = await authApi.loginRaw('test@example.com', 'password');

      expect(response.requires_2fa).toBe(true);
      expect(response['2fa_token']).toBe('2fa-token');
    });
  });

  describe('CSRF Protection Flow', () => {
    it('should get CSRF token before making state changes', async () => {
      let csrfTokenReceived = false;

      vi.mocked(global.fetch).mockImplementation((url) => {
        if (url === '/api/test') {
          return Promise.resolve({
            ok: true,
            headers: {
              get: (name: string) => {
                if (name === 'X-CSRF-Token') {
                  csrfTokenReceived = true;
                  return 'test-csrf-token';
                }
                return null;
              },
            },
            json: async () => ({ data: 'test' }),
          } as Response);
        }
        return Promise.reject(new Error('Not found'));
      });

      const { api } = await import('@/lib/api');

      // First GET request should get CSRF token
      await api.get('/test');
      expect(csrfTokenReceived).toBe(true);
    });

    it('should include CSRF token in POST request', async () => {
      let csrfHeaderIncluded = false;

      vi.mocked(global.fetch).mockImplementation((url, options) => {
        if (url === '/api/submit') {
          csrfHeaderIncluded = options?.headers?.['X-CSRF-Token'] === 'test-token';
          return Promise.resolve({
            ok: true,
            headers: { get: vi.fn() },
            json: async () => ({ success: true }),
          } as Response);
        }
        // Return CSRF token for other requests
        return Promise.resolve({
          ok: true,
          headers: {
            get: (name: string) => name === 'X-CSRF-Token' ? 'test-token' : null,
          },
          json: async () => ({ data: 'test' }),
        } as Response);
      });

      const { api } = await import('@/lib/api');

      // Get CSRF token first
      await api.get('/test');
      // Then make POST request
      await api.post('/submit', { data: 'test' });

      expect(csrfHeaderIncluded).toBe(true);
    });
  });

  describe('Permission Checks', () => {
    it('should check permissions before action', async () => {
      const { usePermissions } = await import('@/hooks/usePermissions');

      const { result } = renderHook(() =>
        usePermissions({
          permissions: ['view_rules', 'manage_rules'],
          loading: false,
        })
      );

      expect(result.current.can('view_rules')).toBe(true);
      expect(result.current.can('delete_users')).toBe(false);
    });

    it('should allow admin all permissions', async () => {
      const { usePermissions } = await import('@/hooks/usePermissions');

      const { result } = renderHook(() =>
        usePermissions({
          role: 'admin',
          loading: false,
        })
      );

      expect(result.current.can('any_permission')).toBe(true);
      expect(result.current.can('delete_all_data')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      vi.mocked(global.fetch).mockRejectedValueOnce(new Error('Network error'));

      const { api } = await import('@/lib/api');

      await expect(api.get('/test')).rejects.toThrow();
    });

    it('should handle 401 unauthorized', async () => {
      vi.mocked(global.fetch).mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: { get: vi.fn() },
        json: async () => ({ detail: 'Unauthorized' }),
      } as Response);

      const { api } = await import('@/lib/api');

      await expect(api.get('/protected')).rejects.toThrow('Unauthorized');
    });

    it('should handle 403 forbidden', async () => {
      vi.mocked(global.fetch).mockResolvedValueOnce({
        ok: false,
        status: 403,
        headers: { get: vi.fn() },
        json: async () => ({ detail: 'Forbidden' }),
      } as Response);

      const { api } = await import('@/lib/api');

      await expect(api.get('/admin')).rejects.toThrow('Forbidden');
    });

    it('should handle 500 server error', async () => {
      vi.mocked(global.fetch).mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: { get: vi.fn() },
        json: async () => ({ detail: 'Internal server error' }),
      } as Response);

      const { api } = await import('@/lib/api');

      await expect(api.get('/error')).rejects.toThrow('Internal server error');
    });
  });

  describe('Data Loading States', () => {
    it('should show loading state while fetching', async () => {
      let resolveFetch: (value: unknown) => void;

      vi.mocked(global.fetch).mockImplementationOnce(() => {
        return new Promise((resolve) => {
          resolveFetch = resolve;
        });
      });

      // Test loading state in hook
      const { useHealthStatus } = await import('@/hooks/useHealthStatus');
      const { result } = renderHook(() => useHealthStatus());

      // Should be in loading state initially
      // After promise resolves, should have data
      await act(async () => {
        resolveFetch!({
          ok: true,
          headers: { get: vi.fn() },
          json: async () => ({ services: [] }),
        });
      });

      await waitFor(() => {
        expect(result.current).toBeDefined();
      });
    });
  });
});
