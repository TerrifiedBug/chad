/**
 * Shared API type definitions
 */

// Re-export RuleVersion from lib/api.ts
export type { RuleVersion } from '@/lib/api'

/**
 * Severity levels for alerts and rules
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

/**
 * Base API response wrapper
 */
export interface ApiResponse<T> {
  data: T
  success?: boolean
}

/**
 * Paginated response
 */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}
