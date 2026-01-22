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

// Rule types
export type RuleStatus = 'enabled' | 'disabled' | 'snoozed'

export type Rule = {
  id: string
  title: string
  description: string | null
  yaml_content: string
  severity: string
  status: RuleStatus
  snooze_until: string | null
  index_pattern_id: string
  created_by: string
  created_at: string
  updated_at: string
  deployed_at: string | null
  deployed_version: number | null
}

export type RuleVersion = {
  id: string
  version_number: number
  yaml_content: string
  created_at: string
}

export type RuleDetail = Rule & {
  index_pattern: IndexPattern
  versions: RuleVersion[]
}

export type RuleCreate = {
  title: string
  description?: string
  yaml_content: string
  severity?: string
  index_pattern_id: string
}

export type RuleUpdate = Partial<RuleCreate> & {
  status?: RuleStatus
}

export type ValidationError = {
  type: string
  message: string
  line?: number
  field?: string
}

export type RuleValidateResponse = {
  valid: boolean
  errors: ValidationError[]
  opensearch_query?: Record<string, unknown>
  fields: string[]
}

export type LogMatchResult = {
  log_index: number
  matched: boolean
}

export type RuleTestResponse = {
  matches: LogMatchResult[]
  opensearch_query?: Record<string, unknown>
  errors: ValidationError[]
}

// Rule deployment types
export type RuleDeployResponse = {
  success: boolean
  rule_id: string
  deployed_version: number
  deployed_at: string
}

// Rules API
export const rulesApi = {
  list: (status?: RuleStatus) =>
    api.get<Rule[]>(`/rules${status ? `?status_filter=${status}` : ''}`),
  get: (id: string) =>
    api.get<RuleDetail>(`/rules/${id}`),
  create: (data: RuleCreate) =>
    api.post<Rule>('/rules', data),
  update: (id: string, data: RuleUpdate) =>
    api.patch<Rule>(`/rules/${id}`, data),
  delete: (id: string) =>
    api.delete(`/rules/${id}`),
  validate: (yaml_content: string, index_pattern_id?: string) =>
    api.post<RuleValidateResponse>('/rules/validate', { yaml_content, index_pattern_id }),
  test: (yaml_content: string, sample_logs: Record<string, unknown>[]) =>
    api.post<RuleTestResponse>('/rules/test', { yaml_content, sample_logs }),
  deploy: (id: string) =>
    api.post<RuleDeployResponse>(`/rules/${id}/deploy`),
  undeploy: (id: string) =>
    api.post<{ success: boolean }>(`/rules/${id}/undeploy`),
  rollback: (id: string, version: number) =>
    api.post<RuleDeployResponse>(`/rules/${id}/rollback`, { version }),
}

// Index Pattern types
export type IndexPattern = {
  id: string
  name: string
  pattern: string
  percolator_index: string
  description: string | null
  created_at: string
  updated_at: string
}

export type IndexPatternCreate = {
  name: string
  pattern: string
  percolator_index: string
  description?: string
}

export type IndexPatternUpdate = Partial<IndexPatternCreate>

export type IndexPatternValidateResponse = {
  valid: boolean
  indices: string[]
  total_docs: number
  sample_fields: string[]
  error?: string
}

// Index Patterns API
export const indexPatternsApi = {
  list: () =>
    api.get<IndexPattern[]>('/index-patterns'),
  get: (id: string) =>
    api.get<IndexPattern>(`/index-patterns/${id}`),
  create: (data: IndexPatternCreate) =>
    api.post<IndexPattern>('/index-patterns', data),
  update: (id: string, data: IndexPatternUpdate) =>
    api.patch<IndexPattern>(`/index-patterns/${id}`, data),
  delete: (id: string) =>
    api.delete(`/index-patterns/${id}`),
  validate: (pattern: string) =>
    api.post<IndexPatternValidateResponse>('/index-patterns/validate', { pattern }),
}

// Alert types
export type AlertStatus = 'new' | 'acknowledged' | 'resolved' | 'false_positive'

export type Alert = {
  alert_id: string
  rule_id: string
  rule_title: string
  severity: string
  tags: string[]
  status: AlertStatus
  log_document: Record<string, unknown>
  created_at: string
  updated_at: string
  acknowledged_by: string | null
  acknowledged_at: string | null
}

export type AlertListResponse = {
  total: number
  alerts: Alert[]
}

export type AlertCountsResponse = {
  total: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  last_24h: number
}

// Alerts API
export const alertsApi = {
  list: (params?: {
    status?: AlertStatus
    severity?: string
    rule_id?: string
    limit?: number
    offset?: number
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.status) searchParams.set('status', params.status)
    if (params?.severity) searchParams.set('severity', params.severity)
    if (params?.rule_id) searchParams.set('rule_id', params.rule_id)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.offset) searchParams.set('offset', params.offset.toString())
    const query = searchParams.toString()
    return api.get<AlertListResponse>(`/alerts${query ? `?${query}` : ''}`)
  },
  get: (id: string) =>
    api.get<Alert>(`/alerts/${id}`),
  getCounts: () =>
    api.get<AlertCountsResponse>('/alerts/counts'),
  updateStatus: (id: string, status: AlertStatus) =>
    api.patch<{ success: boolean; status: AlertStatus }>(`/alerts/${id}/status`, { status }),
}
