const API_BASE = '/api'

class ApiClient {
  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    }
    const token = localStorage.getItem('chad-token')
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    return headers
  }

  async get<T>(path: string): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      headers: this.getHeaders(),
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }))
      throw new Error(error.detail || 'Request failed')
    }
    return response.json()
  }

  async post<T>(path: string, data?: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }))
      throw new Error(error.detail || 'Request failed')
    }
    return response.json()
  }

  async patch<T>(path: string, data: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(data),
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }))
      throw new Error(error.detail || 'Request failed')
    }
    return response.json()
  }

  async delete(path: string): Promise<void> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }))
      throw new Error(error.detail || 'Request failed')
    }
  }
}

export const api = new ApiClient()

// Settings types
export type OpenSearchConfig = {
  host: string
  port: number
  username?: string
  password?: string
  use_ssl: boolean
}

export type ValidationStep = {
  name: string
  success: boolean
  error?: string | null
}

export type OpenSearchTestResponse = {
  success: boolean
  steps: ValidationStep[]
}

export type OpenSearchStatusResponse = {
  configured: boolean
}

// Settings API
export const settingsApi = {
  testOpenSearch: (config: OpenSearchConfig) =>
    api.post<OpenSearchTestResponse>('/settings/opensearch/test', config),
  saveOpenSearch: (config: OpenSearchConfig) =>
    api.post<{ success: boolean }>('/settings/opensearch', config),
  getOpenSearchStatus: () =>
    api.get<OpenSearchStatusResponse>('/settings/opensearch/status'),
}
