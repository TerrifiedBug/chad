import { getErrorMessage, logError, isApiError, isLegacyError } from './errors'
import { QueryClient } from '@tanstack/react-query'

// Create React Query client for cache management
export const queryClient = new QueryClient({
  defaultOptions: {
    mutations: {
      retry: 1,
    },
    queries: {
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
})

const API_BASE = '/api'

export class ApiClient {
  private csrfToken: string | null = null

  private updateCsrfToken(response: Response): void {
    // CSRF middleware sends token in X-CSRF-Token response header for JavaScript access
    const token = response.headers.get('X-CSRF-Token')
    if (token) {
      this.csrfToken = token
    }
  }

  private getHeaders(method: string = 'GET'): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    }

    // Add JWT token if available
    const token = localStorage.getItem('chad-token')
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    // Add CSRF token for state-changing methods (POST, PATCH, PUT, DELETE)
    if (method !== 'GET' && method !== 'HEAD' && this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken
    }

    return headers
  }

  async get<T>(path: string): Promise<T> {
    // Add cache-busting for rule detail requests
    const fetchPath = path
    let fetchOptions: RequestInit = { headers: this.getHeaders('GET') }

    // Add cache control headers for rules endpoint to prevent caching
    if (path.includes('/rules/') && !path.includes('/rules/validate') && !path.includes('/rules/test')) {
      fetchOptions = {
        ...fetchOptions,
        cache: 'no-store',
        headers: {
          ...this.getHeaders('GET'),
          'Cache-Control': 'no-cache',
        },
      }
    }

    const response = await fetch(`${API_BASE}${fetchPath}`, fetchOptions)
    this.updateCsrfToken(response)
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'GET ' + path)
      throw new Error(getErrorMessage(error))
    }
    return response.json()
  }

  async post<T>(path: string, data?: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: this.getHeaders('POST'),
      body: data ? JSON.stringify(data) : undefined,
    })
    this.updateCsrfToken(response)
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'POST ' + path)
      throw new Error(getErrorMessage(error))
    }
    return response.json()
  }

  async patch<T>(path: string, data: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'PATCH',
      headers: this.getHeaders('PATCH'),
      body: JSON.stringify(data),
    })
    this.updateCsrfToken(response)
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'PATCH ' + path)
      throw new Error(getErrorMessage(error))
    }
    return response.json()
  }

  async delete(path: string, body?: unknown): Promise<void> {
    const options: RequestInit = {
      method: 'DELETE',
      headers: this.getHeaders('DELETE'),
    }
    if (body) {
      options.body = JSON.stringify(body)
    }
    const response = await fetch(`${API_BASE}${path}`, options)
    this.updateCsrfToken(response)
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'DELETE ' + path)
      throw new Error(getErrorMessage(error))
    }
  }

  async put<T>(path: string, data: unknown): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'PUT',
      headers: this.getHeaders('PUT'),
      body: JSON.stringify(data),
    })
    this.updateCsrfToken(response)
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'PUT ' + path)
      throw new Error(getErrorMessage(error))
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
  verify_certs?: boolean  // Default: true - only disable for dev with self-signed certs
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
    verify_certs?: boolean
  }
}

export type WebhookTestResponse = {
  success: boolean
  error?: string | null
}

// Mode types (deployment mode: push, pull, or hybrid)
export type ModeResponse = {
  mode: string  // 'push' or 'pull'
  is_pull_only: boolean  // True if CHAD_MODE=pull
  supports_push: boolean  // True in full deployment
  supports_pull: boolean  // Always True
}

// Mode API
export const modeApi = {
  getMode: () =>
    api.get<ModeResponse>('/mode'),
}

// Version types
export type VersionResponse = {
  version: string
}

export type UpdateCheckResponse = {
  current: string
  latest: string | null
  update_available: boolean
  release_url?: string | null
}

// Security settings types
export type SecuritySettings = {
  force_2fa_on_signup: boolean
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
  testAI: () =>
    api.post<AITestResponse>('/settings/ai/test', {}),
  getAIStatus: () =>
    api.get<{ configured: boolean; provider: string | null }>('/settings/ai/status'),
  // Version endpoints
  getVersion: () =>
    api.get<VersionResponse>('/settings/version'),
  checkForUpdates: () =>
    api.get<UpdateCheckResponse>('/settings/version/check'),
  // Security settings
  getSecuritySettings: () =>
    api.get<SecuritySettings>('/settings/security'),
  updateSecuritySettings: (data: Partial<SecuritySettings>) =>
    api.put<SecuritySettings>('/settings/security', data),
  // Notification settings
  getMandatoryCommentsSettings: () =>
    api.get<{ mandatory_rule_comments: boolean }>('/notifications/settings/public'),
  // Health settings
  getHealthSettings: () =>
    api.get<HealthSettings>('/health/settings'),
  updateHealthSettings: (data: Partial<HealthSettings>) =>
    api.put<HealthSettings>('/health/settings', data),
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
  group_id: string  // Exceptions with same group_id are ANDed
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
  change_reason: string
  group_id?: string  // If provided, adds to existing group (AND logic)
  alert_id?: string  // If created from an alert, auto-mark as false positive
}

export type RuleExceptionUpdate = {
  field?: string
  operator?: ExceptionOperator
  value?: string
  reason?: string
  is_active?: boolean
  change_reason: string
}

// Activity types
export type ActivityItem = {
  type: 'version' | 'deploy' | 'undeploy' | 'comment' | 'exception' | 'threshold'
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
export type SigmaHQRuleType = 'detection' | 'threat_hunting' | 'emerging_threats'

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
  sigmahq_type: SigmaHQRuleType | null
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
  change_reason: string
  changed_by: string
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
  change_reason?: string
}

export type ValidationError = {
  type: string
  message: string
  line?: number
  field?: string
}

export type FieldMappingInfo = {
  sigma_field: string
  target_field: string | null
}

export type RuleValidateResponse = {
  valid: boolean
  errors: ValidationError[]
  opensearch_query?: Record<string, unknown>
  fields: string[]
  field_mappings?: FieldMappingInfo[]
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

// Error response when deployment fails due to unmapped fields
export type UnmappedFieldsError = {
  error: 'unmapped_fields'
  message: string
  unmapped_fields: string[]
  index_pattern_id: string
}

// Custom error class for unmapped fields
export class DeploymentUnmappedFieldsError extends Error {
  unmapped_fields: string[]
  index_pattern_id: string

  constructor(data: UnmappedFieldsError) {
    super(data.message)
    this.name = 'DeploymentUnmappedFieldsError'
    this.unmapped_fields = data.unmapped_fields
    this.index_pattern_id = data.index_pattern_id
  }
}

// Bulk operation result type
export type BulkOperationResult = {
  success: string[]
  failed: { id: string; error: string }[]
}

// Deployment eligibility types
export type IneligibleRule = {
  id: string
  reason: string
}

export type DeploymentEligibilityResult = {
  eligible: string[]
  ineligible: IneligibleRule[]
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
  checkTitle: (title: string, excludeId?: string) =>
    api.post<{ available: boolean; message?: string }>('/rules/check-title', {
      title,
      exclude_id: excludeId,
    }),
  get: (id: string) =>
    api.get<RuleDetail>(`/rules/${id}`),
  create: (data: RuleCreate) =>
    api.post<Rule>('/rules', data),
  update: (id: string, data: RuleUpdate) =>
    api.patch<Rule>(`/rules/${id}`, data),
  delete: (id: string, changeReason?: string) =>
    api.delete(`/rules/${id}`, changeReason ? { change_reason: changeReason } : undefined),
  validate: (yaml_content: string, index_pattern_id?: string) =>
    api.post<RuleValidateResponse>('/rules/validate', { yaml_content, index_pattern_id }),
  test: (yaml_content: string, sample_logs: Record<string, unknown>[]) =>
    api.post<RuleTestResponse>('/rules/test', { yaml_content, sample_logs }),
  deploy: async (id: string, changeReason: string): Promise<RuleDeployResponse> => {
    const response = await fetch(`${API_BASE}/rules/${id}/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(localStorage.getItem('chad-token')
          ? { Authorization: `Bearer ${localStorage.getItem('chad-token')}` }
          : {}),
      },
      body: JSON.stringify({ change_reason: changeReason }),
    })
    if (!response.ok) {
      let error = await response.json().catch(() => ({ detail: 'Request failed' }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: 'Request failed' }
      }
      logError(error, 'deploy')
      // Check if this is an unmapped fields error (legacy format)
      if ((error as { error?: string }).error === 'unmapped_fields') {
        throw new DeploymentUnmappedFieldsError(error as UnmappedFieldsError)
      }
      throw new Error(getErrorMessage(error))
    }
    return response.json()
  },
  undeploy: (id: string, changeReason: string) =>
    api.post<{ success: boolean }>(`/rules/${id}/undeploy`, { change_reason: changeReason }),
  getLinkedCorrelations: (id: string, deployedOnly: boolean = false) =>
    api.get<{ correlations: { id: string; name: string; deployed: boolean }[] }>(`/rules/${id}/linked-correlations?deployed_only=${deployedOnly}`),
  rollback: (id: string, version: number, reason: string) =>
    api.post<{ success: boolean; new_version_number: number }>(`/rules/${id}/rollback/${version}`, { change_reason: reason }),
  // Exceptions
  listExceptions: (ruleId: string) =>
    api.get<RuleException[]>(`/rules/${ruleId}/exceptions`),
  getIndexFields: (indexPatternId: string) =>
    api.get<{ fields: string[] }>(`/rules/index-fields/${indexPatternId}`),
  createException: (ruleId: string, data: RuleExceptionCreate) =>
    api.post<RuleException>(`/rules/${ruleId}/exceptions`, data),
  updateException: (ruleId: string, exceptionId: string, data: RuleExceptionUpdate) =>
    api.patch<RuleException>(`/rules/${ruleId}/exceptions/${exceptionId}`, data),
  deleteException: (ruleId: string, exceptionId: string, changeReason: string) =>
    api.delete(`/rules/${ruleId}/exceptions/${exceptionId}`, { change_reason: changeReason }),
  // Snooze
  snooze: (id: string, changeReason: string, hours?: number, indefinite?: boolean) =>
    api.post<{ success: boolean; snooze_until: string | null; snooze_indefinite: boolean; status: string }>(
      `/rules/${id}/snooze`,
      { hours, indefinite: indefinite ?? false, change_reason: changeReason }
    ),
  unsnooze: (id: string, changeReason: string) =>
    api.post<{ success: boolean; status: string }>(`/rules/${id}/unsnooze`, { change_reason: changeReason }),
  // Threshold settings
  updateThreshold: (
    id: string,
    enabled: boolean,
    changeReason: string,
    count?: number | null,
    windowMinutes?: number | null,
    groupBy?: string | null
  ) =>
    api.patch<{
      success: boolean;
      threshold_enabled: boolean;
      threshold_count: number | null;
      threshold_window_minutes: number | null;
      threshold_group_by: string | null;
    }>(`/rules/${id}/threshold`, {
      enabled,
      count: count ?? null,
      window_minutes: windowMinutes ?? null,
      group_by: groupBy ?? null,
      change_reason: changeReason,
    }),
  // Bulk operations
  bulkSnooze: (ruleIds: string[], changeReason: string, hours?: number, indefinite?: boolean) =>
    api.post<BulkOperationResult>('/rules/bulk/snooze', { rule_ids: ruleIds, change_reason: changeReason, hours, indefinite: indefinite ?? false }),
  bulkUnsnooze: (ruleIds: string[], changeReason: string) =>
    api.post<BulkOperationResult>('/rules/bulk/unsnooze', { rule_ids: ruleIds, change_reason: changeReason }),
  bulkDelete: (ruleIds: string[], changeReason: string) =>
    api.post<BulkOperationResult>('/rules/bulk/delete', { rule_ids: ruleIds, change_reason: changeReason }),
  bulkDeploy: (ruleIds: string[], changeReason: string) =>
    api.post<BulkOperationResult>('/rules/bulk/deploy', { rule_ids: ruleIds, change_reason: changeReason }),
  bulkUndeploy: (ruleIds: string[], changeReason: string) =>
    api.post<BulkOperationResult>('/rules/bulk/undeploy', { rule_ids: ruleIds, change_reason: changeReason }),
  checkDeploymentEligibility: (ruleIds: string[]) =>
    api.post<DeploymentEligibilityResult>('/rules/check-deployment-eligibility', { rule_ids: ruleIds }),
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
  // Historical testing
  testHistorical: async (ruleId: string, startDate: Date, endDate: Date, limit?: number) => {
    return api.post<{
      total_scanned: number
      total_matches: number
      matches: Array<{ _id: string; _index: string; _source: Record<string, unknown> }>
      truncated: boolean
      error?: string
    }>(`/rules/${ruleId}/test-historical`, {
      start_date: startDate.toISOString(),
      end_date: endDate.toISOString(),
      limit: limit || 500,
    })
  },
  // Get available fields for correlation
  getFields: (ruleId: string) =>
    api.get<{ fields: string[] }>(`/rules/${ruleId}/fields`),
}

// TI Indicator types for enrichment
export type TIIndicatorType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256'

export const TI_INDICATOR_TYPE_INFO: Record<TIIndicatorType, { label: string; description: string }> = {
  ip: { label: 'IP Address', description: 'IPv4 or IPv6 address' },
  domain: { label: 'Domain', description: 'Domain name or hostname' },
  url: { label: 'URL', description: 'Full URL' },
  hash_md5: { label: 'MD5 Hash', description: '32-character MD5 file hash' },
  hash_sha1: { label: 'SHA1 Hash', description: '40-character SHA1 file hash' },
  hash_sha256: { label: 'SHA256 Hash', description: '64-character SHA256 file hash' },
}

// Indicator types supported by each TI source
export const TI_SOURCE_SUPPORTED_TYPES: Record<TISourceType, TIIndicatorType[]> = {
  virustotal: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  abuseipdb: ['ip'],
  greynoise: ['ip'],
  threatfox: ['ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  misp: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  abuse_ch: ['ip', 'domain', 'url'],
  alienvault_otx: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  phishtank: ['url'],
}

// Field configuration for TI enrichment
export type TIFieldConfig = {
  field: string
  type: TIIndicatorType
}

// TI Source Config for per-index-pattern configuration
export type TISourceConfigForPattern = {
  enabled: boolean
  fields: TIFieldConfig[]
}

// TI config maps source name to its config
export type TIConfig = {
  [sourceName: string]: TISourceConfigForPattern
}

// Index Pattern mode types
export type IndexPatternMode = 'push' | 'pull'

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
  // Health alerting thresholds
  health_no_data_minutes: number | null
  health_error_rate_percent: number | null
  health_latency_ms: number | null
  health_alerting_enabled: boolean
  // GeoIP enrichment
  geoip_fields: string[]
  // TI enrichment config per source
  ti_config: TIConfig | null
  // IP allowlist for log shipping (null = allow all)
  allowed_ips: string[] | null
  // Rate limiting for log shipping
  rate_limit_enabled: boolean
  rate_limit_requests_per_minute: number | null
  rate_limit_events_per_minute: number | null
  // Detection mode: 'push' (real-time via /logs) or 'pull' (scheduled queries)
  mode: IndexPatternMode
  poll_interval_minutes: number
}

export type IndexPatternCreate = {
  name: string
  pattern: string
  percolator_index: string
  description?: string
  // Health alerting thresholds
  health_no_data_minutes?: number | null
  health_error_rate_percent?: number | null
  health_latency_ms?: number | null
  health_alerting_enabled?: boolean
  // GeoIP enrichment
  geoip_fields?: string[]
  // TI enrichment config per source
  ti_config?: TIConfig | null
  // IP allowlist for log shipping (null = allow all)
  allowed_ips?: string[] | null
  // Rate limiting for log shipping
  rate_limit_enabled?: boolean
  rate_limit_requests_per_minute?: number | null
  rate_limit_events_per_minute?: number | null
  // Detection mode
  mode?: IndexPatternMode
  poll_interval_minutes?: number
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
  getFields: (id: string) =>
    api.get<string[]>(`/index-patterns/${id}/fields`),
}

// Alert types
export type AlertStatus = 'new' | 'acknowledged' | 'resolved' | 'false_positive'

// TI Enrichment types for alerts
export type TISourceResult = {
  source: string
  indicator: string
  indicator_type: string
  success: boolean
  error?: string | null
  risk_level: string
  risk_score?: number | null
  categories: string[]
  tags: string[]
  malicious_count: number
  total_count: number
  country?: string | null
  country_code?: string | null
  asn?: string | null
  as_owner?: string | null
  first_seen?: string | null
  last_seen?: string | null
}

export type TIEnrichmentIndicator = {
  indicator: string
  indicator_type: string
  overall_risk_level: string
  overall_risk_score: number
  highest_risk_source?: string | null
  sources_queried: number
  sources_with_results: number
  sources_with_detections: number
  all_categories: string[]
  all_tags: string[]
  source_results?: TISourceResult[]
}

export type TIEnrichment = {
  sources_used: string[]
  indicators: TIEnrichmentIndicator[]
}

export type Alert = {
  alert_id: string
  rule_id: string
  rule_title: string
  severity: string
  tags: string[]
  status: AlertStatus
  log_document: Record<string, unknown>
  ti_enrichment?: TIEnrichment | null
  created_at: string
  updated_at: string
  acknowledged_by: string | null
  acknowledged_at: string | null
  owner_id?: string
  owner_username?: string
  owned_at?: string
  exception_created?: {
    exception_id: string
    field: string
    value: string
    match_type: string
    created_at: string
  }
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

// Query keys for React Query cache invalidation
export const ALERTS_QUERY_KEY = 'alerts'

// Alerts API
export const alertsApi = {
  list: (params?: {
    status?: AlertStatus
    severity?: string
    rule_id?: string
    owner?: string | null
    limit?: number
    offset?: number
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.status) searchParams.set('status', params.status)
    if (params?.severity) searchParams.set('severity', params.severity)
    if (params?.rule_id) searchParams.set('rule_id', params.rule_id)
    if (params?.owner) searchParams.set('owner', params.owner)
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
  delete: (id: string) =>
    api.delete(`/alerts/${id}`).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  bulkUpdateStatus: (data: { alert_ids: string[]; status: AlertStatus }) =>
    api.patch<{ success: boolean; updated_count: number }>('/alerts/bulk/status', data).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  bulkDelete: (data: { alert_ids: string[] }) =>
    api.post<{ success: boolean; deleted_count: number }>('/alerts/bulk/delete', data).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  assign: async (alertId: string): Promise<{ message: string; owner: string }> => {
    return api.post(`/alerts/${alertId}/assign`)
  },
  unassign: async (alertId: string): Promise<{ message: string }> => {
    return api.post(`/alerts/${alertId}/unassign`)
  },
  getRelated: (alertId: string, limit?: number) => {
    const params = new URLSearchParams()
    if (limit) params.set('limit', limit.toString())
    const query = params.toString()
    return api.get<RelatedAlertsResponse>(`/alerts/${alertId}/related${query ? `?${query}` : ''}`)
  },
}

// Alert Comments types
export interface AlertComment {
  id: string
  alert_id: string
  user_id: string
  username: string
  content: string
  created_at: string
  updated_at?: string
  is_deleted: boolean
}

// Alert Comments API
export const alertCommentsApi = {
  list: async (alertId: string): Promise<AlertComment[]> => {
    return api.get(`/alerts/${alertId}/comments`)
  },
  create: async (alertId: string, content: string): Promise<AlertComment> => {
    return api.post(`/alerts/${alertId}/comments`, { content })
  },
  update: async (alertId: string, commentId: string, content: string): Promise<AlertComment> => {
    return api.patch(`/alerts/${alertId}/comments/${commentId}`, { content })
  },
  delete: async (alertId: string, commentId: string): Promise<void> => {
    await api.delete(`/alerts/${alertId}/comments/${commentId}`)
  },
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
  totp_enabled?: boolean
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
  getLockStatus: (email: string) =>
    api.get<{email: string; locked: boolean; remaining_minutes: number | null}>(`/users/lock-status/${email}`),
  unlockUser: (userId: string) =>
    api.post<{success: boolean; email: string; message: string}>(`/users/${userId}/unlock`),
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
  sso_only?: boolean
}

// Login response type (for login that might require 2FA)
export type LoginResponse = {
  access_token?: string
  requires_2fa?: boolean
  '2fa_token'?: string
  requires_2fa_setup?: boolean
}

// Notification preferences type
export type NotificationPreferences = {
  browser_notifications: boolean
  severities: string[]
}

// Current user type
export type CurrentUser = {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  auth_method: 'local' | 'sso'
  must_change_password: boolean
  totp_enabled?: boolean
  permissions?: Record<string, boolean>
  notification_preferences?: NotificationPreferences
}

// 2FA types
export type TwoFactorSetupResponse = {
  qr_uri: string
  secret: string
}

export type TwoFactorVerifyResponse = {
  message: string
  backup_codes: string[]
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
  // Login methods
  loginRaw: (email: string, password: string) =>
    api.post<LoginResponse>('/auth/login', { email, password }),
  login2FA: (token: string, code: string) =>
    api.post<{ access_token: string }>('/auth/login/2fa', { token, code }),
  // 2FA methods
  setup2FA: () =>
    api.post<TwoFactorSetupResponse>('/auth/2fa/setup'),
  verify2FA: (code: string) =>
    api.post<TwoFactorVerifyResponse>('/auth/2fa/verify', { code }),
  disable2FA: (code: string) =>
    api.post<void>('/auth/2fa/disable', { code }),
  updateNotificationPreferences: (prefs: Partial<NotificationPreferences>) =>
    api.patch<{ notification_preferences: NotificationPreferences }>('/auth/me/notifications', prefs),
}

// SigmaHQ types
export type SigmaHQStatus = {
  cloned: boolean
  commit_hash: string | null
  rule_counts: Record<string, number> | null
  repo_url: string | null
}

export type SigmaHQSyncResponse = {
  success: boolean
  message: string
  commit_hash: string | null
  rule_counts: Record<string, number> | null
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
  getCategories: (ruleType: SigmaHQRuleType = 'detection') =>
    api.get<SigmaHQCategoryTree>(`/sigmahq/rules?rule_type=${ruleType}`),
  listRulesInCategory: (categoryPath: string, ruleType: SigmaHQRuleType = 'detection') =>
    api.get<SigmaHQRulesListResponse>(`/sigmahq/rules/list/${categoryPath}?rule_type=${ruleType}`),
  getRuleContent: (rulePath: string, ruleType: SigmaHQRuleType = 'detection') =>
    api.get<SigmaHQRuleContent>(`/sigmahq/rules/${rulePath}?rule_type=${ruleType}`),
  searchRules: (query: string, limit: number = 100, ruleType: SigmaHQRuleType = 'detection') =>
    api.post<SigmaHQRulesListResponse>('/sigmahq/search', { query, limit, rule_type: ruleType }),
  importRule: (rulePath: string, indexPatternId: string, ruleType: SigmaHQRuleType = 'detection') =>
    api.post<{ success: boolean; rule_id: string; title: string; message: string }>(
      '/sigmahq/import',
      { rule_path: rulePath, index_pattern_id: indexPatternId, rule_type: ruleType }
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
  export: async (
    format: 'csv' | 'json',
    filters: {
      action?: string
      resource_type?: string
      start_date?: string
      end_date?: string
    }
  ): Promise<Blob> => {
    const params = new URLSearchParams({ format })
    if (filters.action) params.set('action', filters.action)
    if (filters.resource_type) params.set('resource_type', filters.resource_type)
    if (filters.start_date) params.set('start_date', filters.start_date)
    if (filters.end_date) params.set('end_date', filters.end_date)

    const response = await fetch(`${API_BASE}/audit/export?${params}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('chad-token')}` },
    })
    if (!response.ok) throw new Error('Export failed')
    return response.blob()
  },
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

export type AITestResponse = {
  success: boolean
  provider: string
  model?: string | null
  error?: string | null
  last_tested?: string | null
  last_test_success?: boolean | null
}

// Field Mapping types
export type MappingOrigin = 'manual' | 'ai_suggested'

export type FieldMapping = {
  id: string
  sigma_field: string
  target_field: string
  index_pattern_id: string | null
  origin: MappingOrigin
  confidence: number | null
  created_by: string
  created_at: string
}

export type FieldMappingCreate = {
  sigma_field: string
  target_field: string
  index_pattern_id?: string | null
  origin?: MappingOrigin
  confidence?: number | null
}

export type FieldMappingUpdate = {
  target_field?: string
  origin?: MappingOrigin
  confidence?: number | null
}

export type AISuggestion = {
  sigma_field: string
  target_field: string | null
  confidence: number
  reason: string
}

// Field Mappings API
export const fieldMappingsApi = {
  list: (indexPatternId?: string | null) =>
    api.get<FieldMapping[]>(
      `/field-mappings${indexPatternId ? `?index_pattern_id=${indexPatternId}` : ''}`
    ),
  listGlobal: () =>
    api.get<FieldMapping[]>('/field-mappings?index_pattern_id='),
  create: (data: FieldMappingCreate) =>
    api.post<FieldMapping>('/field-mappings', data),
  update: (id: string, data: FieldMappingUpdate) =>
    api.put<FieldMapping>(`/field-mappings/${id}`, data),
  delete: (id: string) =>
    api.delete(`/field-mappings/${id}`),
  suggest: (data: {
    index_pattern_id: string
    sigma_fields: string[]
    logsource?: Record<string, string>
  }) => api.post<AISuggestion[]>('/field-mappings/suggest', data),
}

// Webhook types (notification webhooks, not settings webhooks)
export type WebhookProvider = 'generic' | 'discord' | 'slack'

export type Webhook = {
  id: string
  name: string
  url: string
  has_auth: boolean
  header_name: string | null
  provider: WebhookProvider
  enabled: boolean
  created_at: string
  updated_at: string
}

// Webhooks API
export const webhooksApi = {
  list: () => api.get<Webhook[]>('/webhooks'),
  create: (data: { name: string; url: string; header_name?: string; header_value?: string; provider?: WebhookProvider; enabled?: boolean }) =>
    api.post<Webhook>('/webhooks', data),
  update: (id: string, data: Partial<{ name: string; url: string; header_name: string; header_value: string; provider: WebhookProvider; enabled: boolean }>) =>
    api.patch<Webhook>(`/webhooks/${id}`, data),
  delete: (id: string) => api.delete(`/webhooks/${id}`),
  test: (id: string) => api.post<{ success: boolean; status_code?: number; error?: string }>(`/webhooks/${id}/test`),
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
    avg_detection_latency_ms: number
    avg_opensearch_query_latency_ms?: number
    max_opensearch_query_latency_ms?: number
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
  avg_detection_latency_ms: number
  alerts_generated: number
}

export type HealthSettings = {
  no_data_minutes: number
  error_rate_percent: number
  detection_latency_warning_ms: number
  detection_latency_critical_ms: number
  opensearch_latency_warning_ms: number
  opensearch_latency_critical_ms: number
  queue_warning: number
  queue_critical: number
}

export type HealthIntervals = {
  jira_interval_seconds: number
  sigmahq_interval_seconds: number
  mitre_attack_interval_seconds: number
  opensearch_interval_seconds: number
  ti_interval_seconds: number
}

// Related Alerts response type
export type RelatedAlertsResponse = {
  alert_id: string
  related_count: number
  clustering_enabled: boolean
  window_minutes: number | null
  alerts: Alert[]
}

// Alert Clustering types
export type AlertClusteringSettings = {
  enabled: boolean
  window_minutes: number
}

export type AlertCluster = {
  representative: Alert
  count: number
  alert_ids: string[]
  alerts: Alert[]  // All alerts in the cluster for expanded view
  time_range: [string | null, string | null]
}

export type ClusteredAlertListResponse = {
  total: number
  total_clusters: number
  clusters: AlertCluster[]
}

// Alert Clustering API
export const alertClusteringApi = {
  getSettings: () =>
    api.get<AlertClusteringSettings>('/settings/alert-clustering'),
  updateSettings: (data: AlertClusteringSettings) =>
    api.put<AlertClusteringSettings>('/settings/alert-clustering', data),
}

// Pull mode health types
export type PullModePatternHealth = {
  index_pattern_id: string
  index_pattern_name: string
  pattern: string
  mode: string
  poll_interval_minutes: number
  last_poll_at: string | null
  last_poll_status: string | null
  last_error: string | null
  status: HealthStatus
  issues: string[]
  metrics: {
    total_polls: number
    successful_polls: number
    failed_polls: number
    success_rate: number
    total_matches: number
    total_events_scanned: number
    last_poll_duration_ms: number | null
    avg_poll_duration_ms: number | null
    consecutive_failures: number
  }
}

export type PullModeHealth = {
  overall_status: HealthStatus
  summary: {
    total_patterns: number
    healthy_patterns: number
    warning_patterns: number
    critical_patterns: number
    total_polls: number
    total_matches: number
    total_events_scanned: number
  }
  patterns: PullModePatternHealth[]
}

// Health API
export const healthApi = {
  listIndices: () =>
    api.get<IndexHealth[]>('/health/indices'),
  getIndex: (id: string, hours = 24) =>
    api.get<IndexHealth>(`/health/indices/${id}?hours=${hours}`),
  getHistory: (id: string, hours = 24) =>
    api.get<HealthHistoryPoint[]>(`/health/indices/${id}/history?hours=${hours}`),
  getSettings: () =>
    api.get<HealthSettings>('/health/settings'),
  updateSettings: (data: Partial<HealthSettings>) =>
    api.put<HealthSettings>('/health/settings', data),
  getIntervals: () =>
    api.get<HealthIntervals>('/health/intervals'),
  updateIntervals: (data: HealthIntervals) =>
    api.put<HealthIntervals>('/health/intervals', data),
  getPullModeHealth: () =>
    api.get<PullModeHealth>('/health/pull-mode'),
}

// Notification settings types
export type SystemNotificationConfig = {
  event_type: string
  webhook_ids: string[]
}

export type AlertNotificationConfig = {
  webhook_id: string
  webhook_name: string
  severities: string[]
  enabled: boolean
}

export type NotificationSettings = {
  system_events: SystemNotificationConfig[]
  alert_notifications: AlertNotificationConfig[]
}

// Notifications API
export const notificationsApi = {
  get: () => api.get<NotificationSettings>('/notifications'),
  updateSystem: (event_type: string, webhook_ids: string[]) =>
    api.put<{ success: boolean }>('/notifications/system', { event_type, webhook_ids }),
  updateAlert: (webhook_id: string, severities: string[], enabled: boolean) =>
    api.put<{ success: boolean }>('/notifications/alerts', { webhook_id, severities, enabled }),
}

// GeoIP types
export type GeoIPSettings = {
  enabled: boolean
  has_license_key: boolean
  database_available: boolean
  database_info: {
    path: string
    size_mb: number
    modified_at: string
  } | null
  update_interval: string
}

export type GeoIPDownloadResponse = {
  success: boolean
  message?: string | null
  error?: string | null
  info?: Record<string, unknown> | null
}

export type GeoIPTestResponse = {
  ip: string
  is_public: boolean
  geo: Record<string, unknown> | null
}

// GeoIP API
export const geoipApi = {
  getSettings: () => api.get<GeoIPSettings>('/settings/geoip'),
  updateSettings: (data: { license_key?: string; update_interval?: string; enabled?: boolean }) =>
    api.put<GeoIPSettings>('/settings/geoip', data),
  downloadDatabase: () => api.post<GeoIPDownloadResponse>('/settings/geoip/download'),
  testLookup: (ip: string) => api.post<GeoIPTestResponse>(`/settings/geoip/test?ip=${ip}`),
}

// ATT&CK Coverage Map types
export type AttackTechnique = {
  id: string
  name: string
  tactic_id: string
  tactic_name: string
  parent_id: string | null
  is_subtechnique: boolean
}

export type TechniqueWithCoverage = AttackTechnique & {
  rule_count: number
}

export type TacticWithTechniques = {
  id: string
  name: string
  techniques: TechniqueWithCoverage[]
}

export type AttackMatrixResponse = {
  tactics: TacticWithTechniques[]
}

export type TechniqueCoverageStats = {
  total: number
  deployed: number
}

export type AttackCoverageResponse = {
  coverage: Record<string, TechniqueCoverageStats>
}

export type LinkedRule = {
  id: string
  title: string
  severity: string
  status: string
  index_pattern_name: string | null
}

export type TechniqueDetail = {
  id: string
  name: string
  tactic_id: string
  tactic_name: string
  parent_id: string | null
  description: string | null
  url: string | null
  platforms: string[] | null
  data_sources: string[] | null
  is_subtechnique: boolean
  updated_at: string
}

export type TechniqueDetailResponse = {
  technique: TechniqueDetail
  rules: LinkedRule[]
  sub_techniques: TechniqueWithCoverage[]
}

export type AttackSyncResponse = {
  success: boolean
  message: string
  techniques_updated: number
  new_techniques: number
  error: string | null
}

export type AttackSyncStatus = {
  last_sync: string | null
  next_scheduled: string | null
  sync_enabled: boolean
  technique_count: number
  frequency: string | null
}

// ATT&CK Coverage Map API
export const attackApi = {
  getMatrix: () => api.get<AttackMatrixResponse>('/attack/techniques'),
  getCoverage: (params?: {
    deployed_only?: boolean
    severity?: string[]
    index_pattern_id?: string
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.deployed_only) searchParams.set('deployed_only', 'true')
    if (params?.severity) {
      params.severity.forEach((s) => searchParams.append('severity', s))
    }
    if (params?.index_pattern_id) searchParams.set('index_pattern_id', params.index_pattern_id)
    const query = searchParams.toString()
    return api.get<AttackCoverageResponse>(`/attack/coverage${query ? `?${query}` : ''}`)
  },
  getTechnique: (
    id: string,
    params?: {
      deployed_only?: boolean
      severity?: string[]
      index_pattern_id?: string
    }
  ) => {
    const searchParams = new URLSearchParams()
    if (params?.deployed_only) searchParams.set('deployed_only', 'true')
    if (params?.severity) {
      params.severity.forEach((s) => searchParams.append('severity', s))
    }
    if (params?.index_pattern_id) searchParams.set('index_pattern_id', params.index_pattern_id)
    const query = searchParams.toString()
    return api.get<TechniqueDetailResponse>(`/attack/techniques/${id}${query ? `?${query}` : ''}`)
  },
  sync: () => api.post<AttackSyncResponse>('/attack/sync'),
  getSyncStatus: () => api.get<AttackSyncStatus>('/attack/sync/status'),
}

// Jira types
export type JiraConfig = {
  id: string
  jira_url: string
  email: string
  default_project: string
  default_issue_type: string
  is_enabled: boolean
  has_api_token: boolean
  alert_severities: string[]
}

export type JiraConfigStatus = {
  configured: boolean
  config: JiraConfig | null
}

export type JiraConfigUpdate = {
  jira_url: string
  email: string
  api_token?: string
  default_project: string
  default_issue_type: string
  is_enabled: boolean
  alert_severities: string[]
}

export type JiraTestResponse = {
  success: boolean
  error?: string | null
  server_title?: string | null
}

export type JiraProject = {
  id: string
  key: string
  name: string
}

export type JiraIssueType = {
  id: string
  name: string
  description: string
}

// Jira API
export const jiraApi = {
  getConfig: () => api.get<JiraConfigStatus>('/jira'),
  updateConfig: (data: JiraConfigUpdate) => api.put<JiraConfig>('/jira', data),
  deleteConfig: () => api.delete('/jira'),
  testConnection: (data: { jira_url: string; email: string; api_token: string }) =>
    api.post<JiraTestResponse>('/jira/test', data),
  testSavedConnection: () => api.post<JiraTestResponse>('/jira/test-saved'),
  getProjects: () => api.get<JiraProject[]>('/jira/projects'),
  getIssueTypes: (projectKey: string) => api.get<JiraIssueType[]>(`/jira/issue-types/${projectKey}`),
}

// Threat Intelligence types
export type TISourceType =
  | 'virustotal'
  | 'abuseipdb'
  | 'greynoise'
  | 'threatfox'
  | 'misp'
  | 'abuse_ch'
  | 'alienvault_otx'
  | 'phishtank'

export type TISourceConfig = {
  id: string
  source_type: TISourceType
  is_enabled: boolean
  has_api_key: boolean
  instance_url: string | null
  config: Record<string, unknown> | null
}

export type TISourcesStatus = {
  sources: TISourceConfig[]
}

export type TISourceConfigUpdate = {
  is_enabled: boolean
  api_key?: string | null
  instance_url?: string | null
  config?: Record<string, unknown> | null
}

export type TITestResponse = {
  success: boolean
  error?: string | null
}

// TI source display info
export const TI_SOURCE_INFO: Record<
  TISourceType,
  { name: string; description: string; requiresKey: boolean; requiresInstance: boolean; docsUrl: string; category: string }
> = {
  virustotal: {
    name: 'VirusTotal',
    description: 'File, IP, domain, and URL reputation from crowdsourced malware analysis',
    requiresKey: true,
    requiresInstance: false,
    docsUrl: 'https://docs.virustotal.com/reference/overview',
    category: 'general',
  },
  abuseipdb: {
    name: 'AbuseIPDB',
    description: 'IP reputation database with user-reported abuse data',
    requiresKey: true,
    requiresInstance: false,
    docsUrl: 'https://docs.abuseipdb.com/',
    category: 'ip',
  },
  greynoise: {
    name: 'GreyNoise',
    description: 'Internet scanner and mass exploitation detection',
    requiresKey: true,
    requiresInstance: false,
    docsUrl: 'https://docs.greynoise.io/',
    category: 'ip',
  },
  threatfox: {
    name: 'ThreatFox',
    description: 'Free IOC sharing platform by abuse.ch for malware-related indicators',
    requiresKey: false,
    requiresInstance: false,
    docsUrl: 'https://threatfox.abuse.ch/api/',
    category: 'malware',
  },
  misp: {
    name: 'MISP',
    description: 'Threat sharing platform for malware indicators and IOC collaboration',
    requiresKey: true,
    requiresInstance: true,
    docsUrl: 'https://www.misp-project.org/',
    category: 'malware',
  },
  abuse_ch: {
    name: 'abuse.ch',
    description: 'Malware and botnet tracking via URLhaus and Feodo Tracker',
    requiresKey: false,
    requiresInstance: false,
    docsUrl: 'https://abuse.ch/',
    category: 'malware',
  },
  alienvault_otx: {
    name: 'AlienVault OTX',
    description: 'Open threat exchange with community-contributed threat intelligence',
    requiresKey: true,
    requiresInstance: false,
    docsUrl: 'https://otx.alienvault.com/',
    category: 'general',
  },
  phishtank: {
    name: 'PhishTank',
    description: 'Community phishing URL database',
    requiresKey: false,
    requiresInstance: false,
    docsUrl: 'https://www.phishtank.com/',
    category: 'phishing',
  },
}

// Threat Intelligence API
export const tiApi = {
  listSources: () => api.get<TISourcesStatus>('/ti'),
  getSource: (sourceType: TISourceType) => api.get<TISourceConfig>(`/ti/${sourceType}`),
  updateSource: (sourceType: TISourceType, data: TISourceConfigUpdate) =>
    api.put<TISourceConfig>(`/ti/${sourceType}`, data),
  deleteSource: (sourceType: TISourceType) => api.delete(`/ti/${sourceType}`),
  testConnection: (sourceType: TISourceType, data: TISourceConfigUpdate) =>
    api.post<TITestResponse>(`/ti/${sourceType}/test`, data),
  testSavedConnection: (sourceType: TISourceType) =>
    api.post<TITestResponse>(`/ti/${sourceType}/test-saved`),
}

// Correlation Rules types
export type EntityFieldType = 'sigma' | 'direct'

export type CorrelationRule = {
  id: string
  name: string
  rule_a_id: string
  rule_b_id: string
  rule_a_title?: string
  rule_b_title?: string
  entity_field: string
  entity_field_type: EntityFieldType
  time_window_minutes: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  created_at: string
  updated_at: string
  created_by?: string
  last_edited_by?: string | null
  // Deployment tracking
  deployed_at?: string | null
  deployed_version?: number | null
  current_version: number
  needs_redeploy: boolean
  // Snooze tracking
  snooze_until?: string | null
  snooze_indefinite: boolean
  // Linked rule deployment status
  rule_a_deployed: boolean
  rule_b_deployed: boolean
}

export type CorrelationRuleCreate = {
  name: string
  rule_a_id: string
  rule_b_id: string
  entity_field: string
  entity_field_type?: EntityFieldType
  time_window_minutes: number
  severity: string
  change_reason: string
}

export type CorrelationRuleUpdate = {
  name?: string
  entity_field?: string
  entity_field_type?: EntityFieldType
  time_window_minutes?: number
  severity?: string
  change_reason: string
}

export type CorrelationRuleVersion = {
  id: string
  version_number: number
  name: string
  rule_a_id: string
  rule_b_id: string
  entity_field: string
  entity_field_type: EntityFieldType
  time_window_minutes: number
  severity: string
  changed_by: string
  changed_by_email?: string | null
  change_reason: string
  created_at: string
}

export type CorrelationRuleComment = {
  id: string
  correlation_rule_id: string
  user_id: string | null
  user_email: string | null
  content: string
  created_at: string
}

export type CorrelationActivityItem = {
  type: 'version' | 'deploy' | 'undeploy' | 'comment'
  timestamp: string
  user_email: string | null
  data: Record<string, unknown>
}

export type CorrelationRuleListResponse = {
  correlation_rules: CorrelationRule[]
  total: number
}

export type CommonLogFieldsResponse = {
  common_fields: string[]
  mapped_fields: Record<string, string>[]
}

export type SigmaFieldMappingInfo = {
  sigma_field: string
  rule_a_target: string
  rule_b_target: string
}

export type CommonSigmaFieldsResponse = {
  fields: SigmaFieldMappingInfo[]
}

// Correlation Rules API
export const correlationRulesApi = {
  list: (includeUndeployed = true) => {
    const params = new URLSearchParams()
    if (includeUndeployed) params.append('include_undeployed', 'true')
    return api.get<CorrelationRuleListResponse>(`/correlation-rules?${params}`)
  },
  get: (id: string) => api.get<CorrelationRule>(`/correlation-rules/${id}`),
  getCommonLogFields: (ruleAId: string, ruleBId: string) =>
    api.get<CommonLogFieldsResponse>(`/correlation-rules/common-log-fields?rule_a_id=${ruleAId}&rule_b_id=${ruleBId}`),
  getCommonSigmaFields: (ruleAId: string, ruleBId: string) =>
    api.get<CommonSigmaFieldsResponse>(`/correlation-rules/common-sigma-fields?rule_a_id=${ruleAId}&rule_b_id=${ruleBId}`),
  create: (data: CorrelationRuleCreate) => api.post<CorrelationRule>(`/correlation-rules`, data),
  update: (id: string, data: CorrelationRuleUpdate) => api.patch<CorrelationRule>(`/correlation-rules/${id}`, data),
  delete: (id: string) => api.delete(`/correlation-rules/${id}`),
  deploy: (id: string, changeReason: string) => api.post<CorrelationRule>(`/correlation-rules/${id}/deploy`, { change_reason: changeReason }),
  undeploy: (id: string, changeReason: string) => api.post<CorrelationRule>(`/correlation-rules/${id}/undeploy`, { change_reason: changeReason }),
  getVersions: (id: string) => api.get<CorrelationRuleVersion[]>(`/correlation-rules/${id}/versions`),
  getActivity: (id: string) => api.get<CorrelationActivityItem[]>(`/correlation-rules/${id}/activity`),
  addComment: (id: string, content: string) => api.post<CorrelationRuleComment>(`/correlation-rules/${id}/comments`, { content }),
  rollback: (id: string, versionNumber: number, changeReason: string) =>
    api.post<{ success: boolean; new_version_number: number; rolled_back_from: number }>(
      `/correlation-rules/${id}/rollback/${versionNumber}`,
      { change_reason: changeReason }
    ),
  snooze: (id: string, hours: number | null, indefinite: boolean, changeReason: string) =>
    api.post<{ success: boolean; snooze_until: string | null; snooze_indefinite: boolean }>(
      `/correlation-rules/${id}/snooze`,
      { hours, indefinite, change_reason: changeReason }
    ),
  unsnooze: (id: string, changeReason: string) =>
    api.post<{ success: boolean }>(`/correlation-rules/${id}/unsnooze`, { change_reason: changeReason }),
  bulkSnooze: (ruleIds: string[], hours: number | null, indefinite: boolean, changeReason: string) =>
    api.post<BulkOperationResult>(`/correlation-rules/bulk/snooze`, {
      rule_ids: ruleIds,
      hours,
      indefinite,
      change_reason: changeReason,
    }),
  bulkUnsnooze: (ruleIds: string[], changeReason: string) =>
    api.post<BulkOperationResult>(`/correlation-rules/bulk/unsnooze`, {
      rule_ids: ruleIds,
      change_reason: changeReason,
    }),
}

// Reports API
export type ReportFormat = 'pdf' | 'csv'

export type AlertSummaryRequest = {
  format: ReportFormat
  date_from?: string
  date_to?: string
  severity?: string[]
  index_pattern?: string
}

export type RuleCoverageRequest = {
  format: ReportFormat
}

export const reportsApi = {
  generateAlertSummary: async (request: AlertSummaryRequest): Promise<Blob> => {
    const token = localStorage.getItem('chad-token')
    const response = await fetch(`${API_BASE}/reports/alerts/summary`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(request),
    })
    if (!response.ok) {
      throw new Error('Failed to generate report')
    }
    return response.blob()
  },

  generateRuleCoverage: async (request: RuleCoverageRequest): Promise<Blob> => {
    const token = localStorage.getItem('chad-token')
    const response = await fetch(`${API_BASE}/reports/rules/coverage`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(request),
    })
    if (!response.ok) {
      throw new Error('Failed to generate report')
    }
    return response.blob()
  },
}

// Config Import/Export API
export type ImportMode = 'skip' | 'overwrite' | 'rename'

export type ImportSummary = {
  dry_run: boolean
  created: Record<string, number>
  updated: Record<string, number>
  skipped: Record<string, number>
  errors: string[]
}

export const configApi = {
  exportConfig: async (): Promise<Blob> => {
    const token = localStorage.getItem('chad-token')
    const response = await fetch(`${API_BASE}/export/config`, {
      method: 'GET',
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    })
    if (!response.ok) {
      throw new Error('Failed to export config')
    }
    return response.blob()
  },

  importConfig: async (
    file: File,
    mode: ImportMode = 'skip',
    dryRun: boolean = false
  ): Promise<ImportSummary> => {
    const token = localStorage.getItem('chad-token')
    const formData = new FormData()
    formData.append('file', file)

    const params = new URLSearchParams()
    params.append('mode', mode)
    params.append('dry_run', dryRun.toString())

    const response = await fetch(`${API_BASE}/export/config/import?${params}`, {
      method: 'POST',
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: formData,
    })
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Failed to import config')
    }
    return response.json()
  },
}

// Queue Settings types
export type QueueSettings = {
  max_queue_size: number
  warning_threshold: number
  critical_threshold: number
  backpressure_mode: 'reject' | 'drop'
  batch_size: number
  batch_timeout_seconds: number
  message_ttl_seconds: number
}

export type QueueSettingsUpdate = Partial<QueueSettings>

export type QueueStatsResponse = {
  total_depth: number
  queues: Record<string, number>
  dead_letter_count: number
}

export type DeadLetterMessage = {
  id: string
  original_stream: string
  original_id: string
  data: Record<string, unknown>
  reason: string
}

export type DeadLetterResponse = {
  count: number
  messages: DeadLetterMessage[]
}

// Queue API
export const queueApi = {
  getSettings: () =>
    api.get<QueueSettings>('/queue/settings'),
  updateSettings: (data: QueueSettingsUpdate) =>
    api.put<QueueSettings>('/queue/settings', data),
  getStats: () =>
    api.get<QueueStatsResponse>('/queue/stats'),
  getDeadLetter: (limit = 100) =>
    api.get<DeadLetterResponse>(`/queue/dead-letter?limit=${limit}`),
  clearDeadLetter: () =>
    api.delete('/queue/dead-letter'),
  deleteDeadLetterMessage: (messageId: string) =>
    api.delete(`/queue/dead-letter/${messageId}`),
}

