/**
 * Standardized error handling for API responses.
 */

export interface ApiError {
  error: {
    code: string
    message: string
    details?: Record<string, unknown>
    request_id: string
  }
}

export interface LegacyApiError {
  detail?: string
  message?: string
}

export type ApiErrorResponse = ApiError | LegacyApiError

/**
 * Check if error response is new format
 */
export function isApiError(error: unknown): error is ApiError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'error' in error &&
    typeof (error as ApiError).error === 'object' &&
    'code' in (error as ApiError).error &&
    'message' in (error as ApiError).error
  )
}

/**
 * Check if error response is legacy format
 */
export function isLegacyError(error: unknown): error is LegacyApiError {
  return (
    typeof error === 'object' &&
    error !== null &&
    ('detail' in error || 'message' in error)
  )
}

/**
 * Extract error message from API response
 * Handles both new and legacy formats
 */
export function getErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    // New standardized format
    return error.error.message
  } else if (isLegacyError(error)) {
    // Legacy format (backward compatibility)
    const detail = error.detail
    const message = error.message

    // Handle detail as object or string
    if (typeof detail === 'string') {
      return detail
    } else if (typeof detail === 'object' && detail !== null) {
      // Extract message from detail object
      return (detail as { message?: string }).message || JSON.stringify(detail)
    }

    // Fallback to message or default
    return message || 'An error occurred'
  } else if (error instanceof Error) {
    return error.message
  }
  return 'An unknown error occurred'
}

/**
 * Extract error code from API response
 * Returns undefined for legacy format
 */
export function getErrorCode(error: unknown): string | undefined {
  if (isApiError(error)) {
    return error.error.code
  }
  return undefined
}

/**
 * Extract request ID from API response
 * Returns undefined for legacy format
 */
export function getRequestId(error: unknown): string | undefined {
  if (isApiError(error)) {
    return error.error.request_id
  }
  return undefined
}

/**
 * Extract error details from API response
 * Returns undefined for legacy format or if no details present
 */
export function getErrorDetails(error: unknown): Record<string, unknown> | undefined {
  if (isApiError(error)) {
    return error.error.details
  }
  return undefined
}

/**
 * Log error with context for debugging
 */
export function logError(error: unknown, context?: string): void {
  const requestId = getRequestId(error)
  const errorCode = getErrorCode(error)
  const details = getErrorDetails(error)

  console.error(`API Error${context ? ` in ${context}` : ''}:`, {
    code: errorCode,
    message: getErrorMessage(error),
    request_id: requestId,
    details,
  })

  // Also log full error object in development for debugging
  if (import.meta.env.DEV) {
    console.debug('Full error object:', error)
  }
}
