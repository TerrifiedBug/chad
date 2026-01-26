import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, cleanup } from '@testing-library/react';
import { useAuth } from '@/hooks/useAuth';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

// Mock the API
vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

describe('Authentication Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  describe('login', () => {
    it('should store token on successful login', async () => {
      const { api } = await import('@/lib/api');
      vi.mocked(api.post).mockResolvedValueOnce({
        access_token: 'test-token',
      });

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.login('test@example.com', 'password');
      });

      expect(localStorage.getItem('token')).toBe('test-token');
    });

    it('should handle login errors', async () => {
      const { api } = await import('@/lib/api');
      vi.mocked(api.post).mockRejectedValueOnce({
        response: { data: { detail: 'Invalid credentials' } },
      });

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await expect(
          result.current.login('test@example.com', 'wrong-password')
        ).rejects.toThrow();
      });
    });
  });

  describe('logout', () => {
    it('should clear token on logout', async () => {
      localStorage.setItem('token', 'test-token');

      const { result } = renderHook(() => useAuth());

      act(() => {
        result.current.logout();
      });

      expect(localStorage.getItem('token')).toBeNull();
    });
  });

  describe('token management', () => {
    it('should restore session from localStorage', () => {
      localStorage.setItem('token', 'stored-token');

      const { result } = renderHook(() => useAuth());

      expect(result.current.token).toBe('stored-token');
      expect(result.current.isAuthenticated).toBe(true);
    });
  });
});
