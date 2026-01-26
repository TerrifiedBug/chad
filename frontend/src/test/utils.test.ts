import { describe, it, expect } from 'vitest';

describe('Utility Functions', () => {
  describe('formatNumber', () => {
    function formatNumber(n: number): string {
      if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
      if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
      return n.toString();
    }

    it('should format small numbers', () => {
      expect(formatNumber(0)).toBe('0');
      expect(formatNumber(999)).toBe('999');
    });

    it('should format thousands', () => {
      expect(formatNumber(1000)).toBe('1.0K');
      expect(formatNumber(1500)).toBe('1.5K');
      expect(formatNumber(999999)).toBe('1000.0K');
    });

    it('should format millions', () => {
      expect(formatNumber(1000000)).toBe('1.0M');
      expect(formatNumber(2500000)).toBe('2.5M');
    });
  });

  describe('formatDateTime', () => {
    function formatDateTime(dateStr: string): string {
      const date = new Date(dateStr);
      return date.toLocaleString();
    }

    it('should format ISO date strings', () => {
      const result = formatDateTime('2025-01-15T10:30:00Z');
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });

    it('should handle invalid date strings', () => {
      const result = new Date('invalid-date').toLocaleString();
      expect(result).toBe('Invalid Date');
    });
  });

  describe('debounce', () => {
    it('should delay function execution', async () => {
      let count = 0;
      const fn = (...args: unknown[]) => {
        const nums = args as number[];
        count += nums.reduce((a, b) => a + b, 0);
      };

      // Simple debounce implementation
      function debounce<T extends (...args: unknown[]) => unknown>(
        func: T,
        wait: number
      ): (...args: Parameters<T>) => void {
        let timeout: ReturnType<typeof setTimeout> | null = null;
        return (...args: Parameters<T>) => {
          if (timeout) clearTimeout(timeout);
          timeout = setTimeout(() => func(...args), wait);
        };
      }

      const debouncedFn = debounce(fn, 100);

      debouncedFn(1);
      debouncedFn(2);
      debouncedFn(3);

      expect(count).toBe(0); // Not called yet

      await new Promise(resolve => setTimeout(resolve, 150));

      expect(count).toBe(3); // Called once with last argument
    });
  });

  describe('date formatting utilities', () => {
    it('should calculate time ago', () => {
      const now = Date.now();
      const oneHourAgo = now - 60 * 60 * 1000;

      function timeAgo(timestamp: number): string {
        const seconds = Math.floor((Date.now() - timestamp) / 1000);
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
      }

      expect(timeAgo(oneHourAgo)).toContain('h ago');
    });
  });
});
