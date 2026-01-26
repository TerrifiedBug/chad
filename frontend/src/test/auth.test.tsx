import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, cleanup, waitFor } from '@testing-library/react';
import React from 'react';
import { useAuth, AuthProvider } from '@/hooks/use-auth';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

// Wrapper for tests that need AuthProvider
const createWrapper = () => {
  return function AuthProviderWrapper({ children }: any) {
    return <AuthProvider>{children}</AuthProvider>;
  };
};

// Mock the API
vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
  authApi: {
    getMe: vi.fn(),
  },
  settingsApi: {
    getOpenSearchStatus: vi.fn(),
  },
}));

describe('Authentication Flow', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    localStorage.clear();

    // Mock setup status check that happens on mount
    const { api } = await import('@/lib/api');
    vi.mocked(api.get).mockResolvedValue({
      setup_completed: true,
    });

    // Mock OpenSearch status check
    const { settingsApi } = await import('@/lib/api');
    vi.mocked(settingsApi.getOpenSearchStatus).mockResolvedValue({
      configured: true,
    });
  });

  describe('login', () => {
    it('should store token on successful login', async () => {
      const { api } = await import('@/lib/api');

      // Mock the login POST request
      vi.mocked(api.post).mockResolvedValueOnce({
        access_token: 'test-token',
      });

      // Mock setup status check
      vi.mocked(api.get).mockResolvedValue({
        setup_completed: true,
      });

      const { result } = renderHook(() => useAuth(), {
        wrapper: createWrapper(),
      });

      await act(async () => {
        await result.current.login('test@example.com', 'password');
      });

      expect(localStorage.getItem('chad-token')).toBe('test-token');
    });

    it('should handle login errors', async () => {
      const { api } = await import('@/lib/api');
      vi.mocked(api.post).mockRejectedValueOnce({
        response: { data: { detail: 'Invalid credentials' } },
      });

      const { result } = renderHook(() => useAuth(), {
        wrapper: createWrapper(),
      });

      await act(async () => {
        await expect(
          result.current.login('test@example.com', 'wrong-password')
        ).rejects.toThrow();
      });
    });
  });

  describe('logout', () => {
    it('should clear token on logout', async () => {
      localStorage.setItem('chad-token', 'test-token');

      const { result } = renderHook(() => useAuth(), {
        wrapper: createWrapper(),
      });

      act(() => {
        result.current.logout();
      });

      expect(localStorage.getItem('chad-token')).toBeNull();
    });
  });

  describe('token management', () => {
    it('should restore session from localStorage', async () => {
      const { authApi, api } = await import('@/lib/api');
      localStorage.setItem('chad-token', 'stored-token');

      // Mock the getMe call that happens on mount
      vi.mocked(authApi.getMe).mockResolvedValueOnce({
        id: '123',
        email: 'test@example.com',
        role: 'analyst',
        is_active: true,
        auth_method: 'local',
        must_change_password: false,
      });

      // Mock setup status check
      vi.mocked(api.get).mockResolvedValue({
        setup_completed: true,
      });

      const { result } = renderHook(() => useAuth(), {
        wrapper: createWrapper(),
      });

      // Wait for the hook to check auth
      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true);
      });
    });
  });
});
