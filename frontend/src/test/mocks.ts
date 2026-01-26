import { vi } from 'vitest'

/**
 * Creates a mock Response object with all required properties
 * Use this instead of manual mock objects to avoid TypeScript errors
 */
export function createMockResponse<T>(data: {
  ok: boolean
  status?: number
  headers?: Record<string, string | null>
  json: () => Promise<T>
}): Response {
  const response = {
    ok: data.ok,
    status: data.status ?? (data.ok ? 200 : 400),
    statusText: data.ok ? 'OK' : 'Bad Request',
    redirected: false,
    type: 'basic' as ResponseType,
    url: 'http://localhost',
    headers: {
      get: (name: string) => data.headers?.[name] ?? null,
      set: vi.fn(),
      append: vi.fn(),
      delete: vi.fn(),
      has: vi.fn(),
      forEach: vi.fn(),
      entries: vi.fn(),
      keys: vi.fn(),
      values: vi.fn(),
    },
    json: data.json,
    body: null,
    bodyUsed: false,
    blob: vi.fn(),
    clone: vi.fn(),
    formData: vi.fn(),
    text: vi.fn(),
    arrayBuffer: vi.fn(),
  }

  return response as unknown as Response
}

/**
 * Creates a successful JSON response mock
 */
export function createSuccessResponse<T>(data: T): Response {
  return createMockResponse({
    ok: true,
    status: 200,
    json: async () => data,
  })
}

/**
 * Creates an error response mock
 */
export function createErrorResponse(detail: string, status = 400): Response {
  return createMockResponse({
    ok: false,
    status,
    json: async () => ({ detail }),
  })
}

/**
 * Creates an error response with error field (legacy format)
 */
export function createLegacyErrorResponse(error: string, status = 400): Response {
  return createMockResponse({
    ok: false,
    status,
    json: async () => ({ error }),
  })
}
