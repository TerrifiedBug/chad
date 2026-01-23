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

  async put<T>(path: string, data: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'PUT',
      headers: this.getHeaders(),
      body: JSON.stringify(data),
    })
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }))
      throw new Error(error.detail || 'Request failed')
    }
    return response.json()
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
  config?: {
    host: string
    port: number
    username?: string
    password?: string
    use_ssl: boolean
  }
}

export type WebhookTestResponse = {
  success: boolean
  error?: string | null
}

// Settings API
export const settingsApi = {
  testOpenSearch: (config: OpenSearchConfig) =>
    api.post<OpenSearchTestResponse>('/settings/opensearch/test', config),
  saveOpenSearch: (config: OpenSearchConfig) =>
    api.post<{ success: boolean }>('/settings/opensearch', config),
  getOpenSearchStatus: () =>
    api.get<OpenSearchStatusResponse>('/settings/opensearch/status'),
  testWebhook: (url: string, provider: string) =>
    api.post<WebhookTestResponse>('/settings/webhooks/test', { url, provider }),
  getAppUrl: () =>
    api.get<{ url: string }>('/settings/app-url'),
  setAppUrl: (url: string) =>
    api.put<{ success: boolean }>('/settings/app-url', { url }),
}

// Exception types
export type ExceptionOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'regex'
  | 'in_list'

export type RuleException = {
  id: string
  rule_id: string
  field: string
  operator: ExceptionOperator
  value: string
  reason: string | null
  is_active: boolean
  created_by: string
  created_at: string
}

export type RuleExceptionCreate = {
  field: string
  operator?: ExceptionOperator
  value: string
  reason?: string
}

export type RuleExceptionUpdate = {
  field?: string
  operator?: ExceptionOperator
  value?: string
  reason?: string
  is_active?: boolean
}

// Activity types
export type ActivityItem = {
  type: 'version' | 'deploy' | 'undeploy' | 'comment'
  timestamp: string
  user_email: string | null
  data: Record<string, unknown>
}

export type RuleComment = {
  id: string
  rule_id: string
  user_id: string | null
  user_email: string | null
  content: string
  created_at: string
}

// Rule types
export type RuleStatus = 'deployed' | 'undeployed' | 'snoozed'
export type RuleSource = 'user' | 'sigmahq'

export type Rule = {
  id: string
  title: string
  description: string | null
  yaml_content: string
  severity: string
  status: RuleStatus
  snooze_until: string | null
  snooze_indefinite: boolean
  index_pattern_id: string
  created_by: string
  created_at: string
  updated_at: string
  deployed_at: string | null
  deployed_version: number | null
  current_version: number
  needs_redeploy: boolean
  last_edited_by: string | null
  source: RuleSource
  sigmahq_path: string | null
  // Threshold alerting
  threshold_enabled: boolean
  threshold_count: number | null
  threshold_window_minutes: number | null
  threshold_group_by: string | null
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
  status?: RuleStatus
  index_pattern_id: string
  // Threshold alerting
  threshold_enabled?: boolean
  threshold_count?: number | null
  threshold_window_minutes?: number | null
  threshold_group_by?: string | null
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

// Bulk operation result type
export type BulkOperationResult = {
  success: string[]
  failed: { id: string; error: string }[]
}

// Rules API
export const rulesApi = {
  list: (params?: { status?: RuleStatus; source?: RuleSource }) => {
    const searchParams = new URLSearchParams()
    if (params?.status) searchParams.set('status_filter', params.status)
    if (params?.source) searchParams.set('source_filter', params.source)
    const query = searchParams.toString()
    return api.get<Rule[]>(`/rules${query ? `?${query}` : ''}`)
  },
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
  // Exceptions
  listExceptions: (ruleId: string) =>
    api.get<RuleException[]>(`/rules/${ruleId}/exceptions`),
  createException: (ruleId: string, data: RuleExceptionCreate) =>
    api.post<RuleException>(`/rules/${ruleId}/exceptions`, data),
  updateException: (ruleId: string, exceptionId: string, data: RuleExceptionUpdate) =>
    api.patch<RuleException>(`/rules/${ruleId}/exceptions/${exceptionId}`, data),
  deleteException: (ruleId: string, exceptionId: string) =>
    api.delete(`/rules/${ruleId}/exceptions/${exceptionId}`),
  // Snooze
  snooze: (id: string, hours?: number, indefinite?: boolean) =>
    api.post<{ success: boolean; snooze_until: string | null; snooze_indefinite: boolean; status: string }>(
      `/rules/${id}/snooze`,
      { hours, indefinite: indefinite ?? false }
    ),
  unsnooze: (id: string) =>
    api.post<{ success: boolean; status: string }>(`/rules/${id}/unsnooze`),
  // Bulk operations
  bulkEnable: (ruleIds: string[]) =>
    api.post<BulkOperationResult>('/rules/bulk/enable', { rule_ids: ruleIds }),
  bulkDelete: (ruleIds: string[]) =>
    api.post<BulkOperationResult>('/rules/bulk/delete', { rule_ids: ruleIds }),
  bulkDeploy: (ruleIds: string[]) =>
    api.post<BulkOperationResult>('/rules/bulk/deploy', { rule_ids: ruleIds }),
  bulkUndeploy: (ruleIds: string[]) =>
    api.post<BulkOperationResult>('/rules/bulk/undeploy', { rule_ids: ruleIds }),
  // Activity and comments
  getActivity: (ruleId: string, skip?: number, limit?: number) => {
    const params = new URLSearchParams()
    params.set('skip', String(skip || 0))
    params.set('limit', String(limit || 50))
    return api.get<ActivityItem[]>(`/rules/${ruleId}/activity?${params.toString()}`)
  },
  addComment: (ruleId: string, content: string) =>
    api.post<RuleComment>(`/rules/${ruleId}/comments`, { content }),
  getVersion: (ruleId: string, versionNumber: number) =>
    api.get<RuleVersion>(`/rules/${ruleId}/versions/${versionNumber}`),
}

// Index Pattern types
export type IndexPattern = {
  id: string
  name: string
  pattern: string
  percolator_index: string
  description: string | null
  auth_token: string
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
  regenerateToken: (id: string) =>
    api.post<{ auth_token: string }>(`/index-patterns/${id}/regenerate-token`),
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

// Dashboard stats types
export type RecentAlert = {
  alert_id: string
  rule_title: string
  severity: string
  status: string
  created_at: string
}

export type DashboardStats = {
  rules: {
    total: number
    by_status: Record<string, number>
    deployed: number
  }
  alerts: {
    total: number
    by_status: Record<string, number>
    by_severity: Record<string, number>
    today: number
  }
  recent_alerts: RecentAlert[]
  generated_at: string
}

// Stats API
export const statsApi = {
  getDashboard: () =>
    api.get<DashboardStats>('/stats/dashboard'),
  getHealth: () =>
    api.get<{ status: string; opensearch?: unknown; error?: string }>('/stats/health'),
}

// User types
export type UserInfo = {
  id: string
  email: string
  role: string
  is_active: boolean
  created_at: string
  auth_method: 'local' | 'sso'
}

export type UserCreate = {
  email: string
  password: string
  role: string
}

// Users API
export const usersApi = {
  list: async (): Promise<UserInfo[]> => {
    const response = await api.get<{ users: UserInfo[] }>('/users')
    return response.users
  },
  create: (data: UserCreate) =>
    api.post<UserInfo>('/users', data),
  update: (userId: string, data: { role?: string; is_active?: boolean }) =>
    api.patch<UserInfo>(`/users/${userId}`, data),
  resetPassword: (userId: string) =>
    api.post<{ temporary_password: string; message: string }>(
      `/users/${userId}/reset-password`
    ),
  delete: (userId: string) =>
    api.delete(`/users/${userId}`),
}

// Extended Settings API
export const settingsApiExtended = {
  getAll: () =>
    api.get<Record<string, unknown>>('/settings'),
  update: <T>(key: string, value: T) =>
    api.put<{ success: boolean }>(`/settings/${key}`, value),
}

// SSO types
export type SsoStatus = {
  enabled: boolean
  configured: boolean
  provider_name: string
}

// Current user type
export type CurrentUser = {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  auth_method: 'local' | 'sso'
  must_change_password: boolean
}

// Auth API
export const authApi = {
  getSsoStatus: () =>
    api.get<SsoStatus>('/auth/sso/status'),
  getMe: () =>
    api.get<CurrentUser>('/auth/me'),
  // SSO login is handled by redirect, not API call
  getSsoLoginUrl: () => `${API_BASE}/auth/sso/login`,
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post<{ message: string }>('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
}

// SigmaHQ types
export type SigmaHQStatus = {
  cloned: boolean
  commit_hash: string | null
  rule_count: number | null
  repo_url: string | null
}

export type SigmaHQSyncResponse = {
  success: boolean
  message: string
  commit_hash: string | null
  rule_count: number | null
  error: string | null
}

export type SigmaHQCategory = {
  count: number
  children: Record<string, SigmaHQCategory>
}

export type SigmaHQCategoryTree = {
  categories: Record<string, SigmaHQCategory>
}

export type SigmaHQRule = {
  title: string
  status: string
  severity: string
  description: string
  tags: string[]
  path: string
  filename: string
}

export type SigmaHQRulesListResponse = {
  rules: SigmaHQRule[]
  total: number
}

export type SigmaHQRuleContent = {
  path: string
  content: string
  metadata: Record<string, unknown> | null
}

// SigmaHQ API
export const sigmahqApi = {
  getStatus: () =>
    api.get<SigmaHQStatus>('/sigmahq/status'),
  sync: () =>
    api.post<SigmaHQSyncResponse>('/sigmahq/sync'),
  getCategories: () =>
    api.get<SigmaHQCategoryTree>('/sigmahq/rules'),
  listRulesInCategory: (categoryPath: string) =>
    api.get<SigmaHQRulesListResponse>(`/sigmahq/rules/list/${categoryPath}`),
  getRuleContent: (rulePath: string) =>
    api.get<SigmaHQRuleContent>(`/sigmahq/rules/${rulePath}`),
  searchRules: (query: string, limit: number = 100) =>
    api.post<SigmaHQRulesListResponse>('/sigmahq/search', { query, limit }),
  importRule: (rulePath: string, indexPatternId: string) =>
    api.post<{ success: boolean; rule_id: string; title: string; message: string }>(
      '/sigmahq/import',
      { rule_path: rulePath, index_pattern_id: indexPatternId }
    ),
}

// API Key types
export type APIKey = {
  id: string
  name: string
  description: string | null
  key_prefix: string
  user_id: string
  expires_at: string | null
  last_used_at: string | null
  is_active: boolean
  created_at: string
}

export type APIKeyCreate = {
  name: string
  description?: string
  expires_at?: string
}

export type APIKeyCreateResponse = APIKey & {
  key: string // Only returned on creation
}

// API Keys API
export const apiKeysApi = {
  list: () => api.get<APIKey[]>('/api-keys'),
  create: (data: APIKeyCreate) => api.post<APIKeyCreateResponse>('/api-keys', data),
  get: (id: string) => api.get<APIKey>(`/api-keys/${id}`),
  update: (id: string, data: { name?: string; description?: string; is_active?: boolean }) =>
    api.patch<APIKey>(`/api-keys/${id}`, data),
  delete: (id: string) => api.delete(`/api-keys/${id}`),
}

// Audit Log types
export type AuditLogEntry = {
  id: string
  user_id: string | null
  user_email: string | null
  action: string
  resource_type: string
  resource_id: string | null
  details: Record<string, unknown> | null
  ip_address: string | null
  created_at: string
}

export type AuditLogListResponse = {
  items: AuditLogEntry[]
  total: number
  limit: number
  offset: number
}

export const auditApi = {
  list: (params?: {
    user_id?: string
    action?: string
    resource_type?: string
    start_date?: string
    end_date?: string
    limit?: number
    offset?: number
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.user_id) searchParams.set('user_id', params.user_id)
    if (params?.action) searchParams.set('action', params.action)
    if (params?.resource_type) searchParams.set('resource_type', params.resource_type)
    if (params?.start_date) searchParams.set('start_date', params.start_date)
    if (params?.end_date) searchParams.set('end_date', params.end_date)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.offset) searchParams.set('offset', params.offset.toString())
    const query = searchParams.toString()
    return api.get<AuditLogListResponse>(`/audit${query ? `?${query}` : ''}`)
  },
  getActions: () =>
    api.get<{ actions: string[] }>('/audit/actions'),
  getResourceTypes: () =>
    api.get<{ resource_types: string[] }>('/audit/resource-types'),
}

// Permissions types
export type PermissionsResponse = {
  roles: Record<string, Record<string, boolean>>
  descriptions: Record<string, string>
}

// Permissions API
export const permissionsApi = {
  getAll: () =>
    api.get<PermissionsResponse>('/permissions'),
  update: (role: string, permission: string, granted: boolean) =>
    api.put<{ success: boolean }>('/permissions', { role, permission, granted }),
}

// AI Settings types
export type AIProvider = 'disabled' | 'ollama' | 'openai' | 'anthropic'

export type AISettings = {
  ai_provider: AIProvider
  ai_ollama_url: string
  ai_ollama_model: string
  ai_openai_model: string
  ai_anthropic_model: string
  ai_allow_log_samples: boolean
  // Keys are write-only, not returned by GET
}

export type AISettingsUpdate = AISettings & {
  ai_openai_key?: string
  ai_anthropic_key?: string
}

// Health types
export type HealthStatus = 'healthy' | 'warning' | 'critical'

export type IndexHealth = {
  index_pattern_id: string
  index_pattern_name: string
  pattern: string
  status: HealthStatus
  issues: string[]
  latest: {
    queue_depth: number
    avg_latency_ms: number
    logs_per_minute: number
    alerts_per_hour: number
  }
  totals_24h: {
    logs_received: number
    logs_errored: number
    alerts_generated: number
  }
}

export type HealthHistoryPoint = {
  timestamp: string
  logs_received: number
  queue_depth: number
  avg_latency_ms: number
  alerts_generated: number
}

// Health API
export const healthApi = {
  listIndices: () =>
    api.get<IndexHealth[]>('/health/indices'),
  getIndex: (id: string, hours = 24) =>
    api.get<IndexHealth>(`/health/indices/${id}?hours=${hours}`),
  getHistory: (id: string, hours = 24) =>
    api.get<HealthHistoryPoint[]>(`/health/indices/${id}/history?hours=${hours}`),
}
