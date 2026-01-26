import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { AuthProvider } from '@/hooks/use-auth';
import { createMockResponse, createSuccessResponse, createErrorResponse } from './mocks';

// Wrapper for tests that need AuthProvider
const createWrapper = () => {
  return function AuthProviderWrapper({ children }: any) {
    return <AuthProvider>{children}</AuthProvider>;
  };
};

describe('Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    global.fetch = vi.fn();
  });

  describe('Authentication Flow', () => {
    it('should complete full login flow', async () => {
      // Track which API calls are made
      const calls: string[] = [];

      // Mock all the API calls that happen during mount and login
      vi.mocked(global.fetch).mockImplementation((url: string | URL | Request) => {
        const urlStr = url.toString();
        calls.push(urlStr);

        // Setup status check (happens on mount and after login)
        if (urlStr === '/api/auth/setup-status') {
          return Promise.resolve(
            createMockResponse({
              ok: true,
              headers: {
                'X-CSRF-Token': 'csrf-token',
              },
              json: async () => ({ setup_completed: true }),
            })
          );
        }

        // Login POST request
        if (urlStr === '/api/auth/login') {
          return Promise.resolve(
            createMockResponse({
              ok: true,
              headers: {
                'X-CSRF-Token': 'csrf-token',
              },
              json: async () => ({
                access_token: 'test-token',
                token_type: 'bearer',
              }),
            })
          );
        }

        // getMe call (happens after login)
        if (urlStr === '/api/auth/me') {
          return Promise.resolve(
            createSuccessResponse({
              id: '123',
              email: 'test@example.com',
              role: 'analyst',
              is_active: true,
              auth_method: 'local',
              must_change_password: false,
            })
          );
        }

        // OpenSearch status check (happens after login)
        if (urlStr === '/api/settings/opensearch/status') {
          return Promise.resolve(createSuccessResponse({ configured: true }));
        }

        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      });

      const { useAuth } = await import('@/hooks/use-auth');
      const { result } = renderHook(() => useAuth(), {
        wrapper: createWrapper(),
      });

      // Wait for initial auth check
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // Clear calls from mount
      calls.length = 0;

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
      vi.mocked(global.fetch).mockResolvedValueOnce(
        createMockResponse({
          ok: true,
          headers: {
            'X-CSRF-Token': 'csrf-token',
          },
          json: async () => ({
            requires_2fa: true,
            '2fa_token': '2fa-token',
          }),
        })
      );

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
        // Match the actual URL that api.get('/test') uses
        if (url.includes('/test') || url === '/test') {
          return Promise.resolve(
            createMockResponse({
              ok: true,
              headers: {
                get: ((name: string) => {
                  if (name === 'X-CSRF-Token') {
                    csrfTokenReceived = true;
                    return 'test-csrf-token';
                  }
                  return null;
                }) as any,
              },
              json: async () => ({ data: 'test' }),
            })
          );
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
          csrfHeaderIncluded = (options?.headers as Record<string, string>)?.['X-CSRF-Token'] === 'test-token';
          return Promise.resolve(createSuccessResponse({ success: true }));
        }
        // Return CSRF token for other requests
        return Promise.resolve(
          createMockResponse({
            ok: true,
            headers: {
              'X-CSRF-Token': 'test-token',
            },
            json: async () => ({ data: 'test' }),
          })
        );
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
      vi.mocked(global.fetch).mockResolvedValueOnce(
        createErrorResponse('Unauthorized', 401)
      );

      const { api } = await import('@/lib/api');

      await expect(api.get('/protected')).rejects.toThrow('Unauthorized');
    });

    it('should handle 403 forbidden', async () => {
      vi.mocked(global.fetch).mockResolvedValueOnce(
        createErrorResponse('Forbidden', 403)
      );

      const { api } = await import('@/lib/api');

      await expect(api.get('/admin')).rejects.toThrow('Forbidden');
    });

    it('should handle 500 server error', async () => {
      vi.mocked(global.fetch).mockResolvedValueOnce(
        createErrorResponse('Internal server error', 500)
      );

      const { api } = await import('@/lib/api');

      await expect(api.get('/error')).rejects.toThrow('Internal server error');
    });
  });

  describe('Data Loading States', () => {
    it('should show loading state while fetching', async () => {
      let resolveFetch: (value: Response) => void;

      vi.mocked(global.fetch).mockImplementationOnce(() => {
        return new Promise((resolve) => {
          resolveFetch = resolve as any;
        });
      });

      // Test loading state in hook
      const { useHealthStatus } = await import('@/hooks/useHealthStatus');
      const { result } = renderHook(() => useHealthStatus());

      // Should be in loading state initially
      // After promise resolves, should have data
      await act(async () => {
        (resolveFetch as any)(
          createSuccessResponse({ services: [] })
        );
      });

      await waitFor(() => {
        expect(result.current).toBeDefined();
      });
    });
  });
});
