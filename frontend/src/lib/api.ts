import { getErrorMessage, logError, isApiError, isLegacyError } from './errors'
import { getActiveEnvironmentId } from '@/stores/environment-store'
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

    // Scope the request to the active environment. When no env is selected the
    // header is omitted and the backend falls back to the default env (today's
    // behaviour — header is optional and back-compat).
    const envId = getActiveEnvironmentId()
    if (envId) {
      headers['X-CHAD-Environment'] = envId
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
      let error = await response.json().catch(() => ({ detail: `Request failed with status ${response.status}` }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: `Request failed with status ${response.status}` }
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
      let error = await response.json().catch(() => ({ detail: `Request failed with status ${response.status}` }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: `Request failed with status ${response.status}` }
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
      let error = await response.json().catch(() => ({ detail: `Request failed with status ${response.status}` }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: `Request failed with status ${response.status}` }
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
      let error = await response.json().catch(() => ({ detail: `Request failed with status ${response.status}` }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: `Request failed with status ${response.status}` }
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
      let error = await response.json().catch(() => ({ detail: `Request failed with status ${response.status}` }))
      // If JSON parsed but isn't a recognized format, use fallback
      if (!isApiError(error) && !isLegacyError(error)) {
        error = { detail: `Request failed with status ${response.status}` }
      }
      logError(error, 'PUT ' + path)
      throw new Error(getErrorMessage(error))
    }
    return response.json()
  }
}

export const api = new ApiClient()

/**
 * Low-level POST that preserves the HTTP status alongside the parsed body.
 * Used by deploy paths that must distinguish a normal 200 result from the
 * 202 "pending_approval" response returned when dual-control gating is on.
 */
async function postRaw(
  path: string,
  data: unknown,
  context: string
): Promise<{ status: number; body: any }> {
  const token = localStorage.getItem('chad-token')
  const envId = getActiveEnvironmentId()
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(envId ? { 'X-CHAD-Environment': envId } : {}),
    },
    body: JSON.stringify(data),
  })
  if (!response.ok) {
    let error = await response.json().catch(() => ({ detail: 'Request failed' }))
    if (!isApiError(error) && !isLegacyError(error)) {
      error = { detail: 'Request failed' }
    }
    logError(error, context)
    throw new Error(getErrorMessage(error))
  }
  return { status: response.status, body: await response.json() }
}

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
  enforce_mfa?: boolean
  api_key_rate_limit: number
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
  checkForUpdatesNow: () =>
    api.post<UpdateCheckResponse>('/settings/version/check-now', {}),
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
  // Rule settings
  getRuleSettings: () =>
    api.get<{ deployment_alert_threshold: number }>('/rules/settings'),
  updateRuleSettings: (data: { deployment_alert_threshold: number }) =>
    api.put<{ deployment_alert_threshold: number }>('/rules/settings', data),
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

export type ExceptionPreviewClause = {
  field: string
  operator?: ExceptionOperator
  value: string
}

export type ExceptionPreviewResult = {
  total_matches: number
  suppressed: number
  remaining: number
  error?: string
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
export type RuleSource = 'user' | 'sigmahq' | 'misp'
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
  // True when an open (pending) dual-control deployment request exists for this
  // rule. Optional: only present when the backend includes it on the list/detail
  // response; absent on older responses (treat undefined as "no open request").
  has_open_request?: boolean
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

// 202 body returned by deploy endpoints when dual-control approval is required
export type PendingApprovalResponse = {
  status: 'pending_approval'
  deployment_request_id: string
  message: string
}

// Discriminated result for deploy/bulk-deploy/unsnooze: either the rule applied
// immediately (gate OFF) or a deployment request was filed for review (gate ON).
export type DeployResult =
  | { pendingApproval: false; result: RuleDeployResponse }
  | { pendingApproval: true; requestId: string; message: string }

export type BulkDeployResult =
  | { pendingApproval: false; result: BulkOperationResult }
  | { pendingApproval: true; requestId: string; message: string }

export type UnsnoozeResult =
  | { pendingApproval: false; result: { success: boolean; status: string } }
  | { pendingApproval: true; requestId: string; message: string }

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

// Deploy preview (consolidated preflight) types — see GET /rules/{id}/deploy-preview.
// Consolidates check-deployment-eligibility + validate + (optional) test-historical.
export type DeployPreviewEligibility = {
  // True when the rule's fields are all mapped / it is otherwise deployable.
  eligible: boolean
  // Human-readable reason when not eligible (e.g. unmapped fields).
  reason?: string | null
  // Fields that have no mapping for the target index pattern, if any.
  unmapped_fields?: string[]
}

// Optional 24h historical dry-run summary folded into the preview.
export type DeployPreviewDryRun = {
  total_scanned: number
  total_matches: number
  truncated: boolean
  error?: string | null
}

export type DeployPreviewResponse = {
  // DSL currently live in the percolator for this rule, or null if undeployed / pull-mode.
  current_deployed_query: string | null
  // Freshly translated current YAML (with mappings applied).
  proposed_query: string
  validation: {
    success: boolean
    errors: ValidationError[]
  }
  eligibility: DeployPreviewEligibility
  needs_redeploy: boolean
  deployed_version: number | null
  current_version: number
  // Optional — may be omitted/lazy by the backend.
  dry_run?: DeployPreviewDryRun | null
}

// Live bulk-deploy progress message broadcast over /ws during a bulk deploy.
export type DeployProgressStatus = 'queued' | 'deploying' | 'success' | 'failed'

export type DeployProgressMessage = {
  type: 'deploy_progress'
  rule_id: string
  rule_title: string
  status: DeployProgressStatus
  error?: string | null
  batch_id?: string | null
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
  test: (yaml_content: string, sample_logs: Record<string, unknown>[], index_pattern_id?: string) =>
    api.post<RuleTestResponse>('/rules/test', { yaml_content, sample_logs, index_pattern_id: index_pattern_id || null }),
  deploy: async (id: string, changeReason: string): Promise<DeployResult> => {
    const envId = getActiveEnvironmentId()
    const response = await fetch(`${API_BASE}/rules/${id}/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(localStorage.getItem('chad-token')
          ? { Authorization: `Bearer ${localStorage.getItem('chad-token')}` }
          : {}),
        ...(envId ? { 'X-CHAD-Environment': envId } : {}),
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
    const body = await response.json()
    // 202 = dual-control gate is ON; a deployment request was filed for review.
    if (response.status === 202 && body?.status === 'pending_approval') {
      return { pendingApproval: true, requestId: body.deployment_request_id, message: body.message }
    }
    return { pendingApproval: false, result: body as RuleDeployResponse }
  },
  undeploy: (id: string, changeReason: string) =>
    api.post<{ success: boolean }>(`/rules/${id}/undeploy`, { change_reason: changeReason }),
  getLinkedCorrelations: (id: string, deployedOnly: boolean = false) =>
    api.get<{ correlations: { id: string; name: string; deployed: boolean }[] }>(`/rules/${id}/linked-correlations?deployed_only=${deployedOnly}`),
  rollback: (id: string, version: number, reason: string) =>
    api.post<{ success: boolean; new_version_number: number }>(`/rules/${id}/rollback/${version}`, { change_reason: reason }),
  // Consolidated deploy preview: validation + eligibility + current/proposed DSL
  // (+ optional dry-run) in one read-only call. Backed by GET deploy-preview.
  deployPreview: (id: string) =>
    api.get<DeployPreviewResponse>(`/rules/${id}/deploy-preview`),
  // Roll the rule back to a prior (last deployed) version AND redeploy in one step.
  // Returns 200 (applied) or 202 (pending approval) — same gate as deploy().
  rollbackRedeploy: async (id: string, version: number, changeReason: string): Promise<DeployResult> => {
    const { status, body } = await postRaw(
      `/rules/${id}/rollback-redeploy/${version}`,
      { change_reason: changeReason },
      'rollbackRedeploy'
    )
    // 202 = dual-control gate is ON; a deployment request was filed for review.
    if (status === 202 && body?.status === 'pending_approval') {
      return { pendingApproval: true, requestId: body.deployment_request_id, message: body.message }
    }
    return { pendingApproval: false, result: body as RuleDeployResponse }
  },
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
  unsnooze: async (id: string, changeReason: string): Promise<UnsnoozeResult> => {
    const { status, body } = await postRaw(`/rules/${id}/unsnooze`, { change_reason: changeReason }, 'unsnooze')
    // 202 = dual-control gate is ON; unsnooze (a re-deploy) was filed for review.
    if (status === 202 && body?.status === 'pending_approval') {
      return { pendingApproval: true, requestId: body.deployment_request_id, message: body.message }
    }
    return { pendingApproval: false, result: body as { success: boolean; status: string } }
  },
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
  bulkDeploy: async (ruleIds: string[], changeReason: string): Promise<BulkDeployResult> => {
    const { status, body } = await postRaw('/rules/bulk/deploy', { rule_ids: ruleIds, change_reason: changeReason }, 'bulkDeploy')
    // 202 = dual-control gate is ON; a single batch request was filed for all rules.
    if (status === 202 && body?.status === 'pending_approval') {
      return { pendingApproval: true, requestId: body.deployment_request_id, message: body.message }
    }
    return { pendingApproval: false, result: body as BulkOperationResult }
  },
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
  // Exception suppression preview: how many past events a candidate would suppress
  previewException: (
    ruleId: string,
    startDate: Date,
    endDate: Date,
    clauses: ExceptionPreviewClause[],
    limit?: number,
  ) =>
    api.post<ExceptionPreviewResult>(`/rules/${ruleId}/exceptions/preview`, {
      start_date: startDate.toISOString(),
      end_date: endDate.toISOString(),
      limit: limit ?? 500,
      clauses: clauses.map((c) => ({
        field: c.field,
        operator: c.operator ?? 'equals',
        value: c.value,
      })),
    }),
  // Get available fields for correlation
  getFields: (ruleId: string) =>
    api.get<{ fields: string[] }>(`/rules/${ruleId}/fields`),
}

// Dual-control deployment approval types
export type DeploymentRequestStatus =
  | 'pending'
  | 'approved'
  | 'applied'
  | 'rejected'
  | 'cancelled'
  | 'stale'
  | 'failed'

export type DeploymentRequestResponse = {
  id: string
  status: string
  requested_by: string
  requester_email: string | null
  reviewed_by: string | null
  reviewer_email: string | null
  change_reason: string
  review_note: string | null
  team_id: string | null
  created_at: string
  reviewed_at: string | null
  applied_at: string | null
  item_count: number
  rule_titles: string[]
  age_seconds: number
  // Populated when this request is a promotion into a specific target env (the
  // dual-control `target_environment_id` seam). Null/absent for plain deploys —
  // older backends omit it entirely, so treat undefined as "no target env".
  target_environment_id?: string | null
  // Maker-checker hardening (I3): quorum progress + approval SLA. Older backends
  // omit these; treat undefined as a 1-approver request with no deadline.
  required_approvals?: number
  approvals_count?: number
  approval_deadline?: string | null
  is_overdue?: boolean
}

export type DeploymentRequestApprovalInfo = {
  approver_id: string
  approver_email: string | null
  note: string | null
  created_at: string
}

export type DeploymentRequestItemDetail = {
  id: string
  kind: 'sigma' | 'correlation'
  rule_id: string | null
  correlation_rule_id: string | null
  rule_title: string | null
  version_number: number
  apply_status: 'ok' | 'failed' | 'skipped' | null
  apply_error: string | null
  proposed_yaml: string | null
  deployed_yaml: string | null
  is_stale: boolean
}

export type DeploymentRequestDetailResponse = DeploymentRequestResponse & {
  items: DeploymentRequestItemDetail[]
  approvals?: DeploymentRequestApprovalInfo[]
}

export type DeploymentRequestStats = {
  pending: number
  approved: number
  applied: number
  rejected: number
  cancelled: number
  stale: number
  failed: number
  avg_review_seconds: number | null
}

// Deployment Requests API (dual-control / maker-checker)
export const deploymentRequestsApi = {
  list: (statusFilter?: DeploymentRequestStatus) =>
    api.get<DeploymentRequestResponse[]>(
      `/deployment-requests${statusFilter ? `?status_filter=${statusFilter}` : ''}`
    ),
  get: (id: string) =>
    api.get<DeploymentRequestDetailResponse>(`/deployment-requests/${id}`),
  getStats: () =>
    api.get<DeploymentRequestStats>('/deployment-requests/stats'),
  create: (ruleIds: string[], changeReason: string) =>
    api.post<DeploymentRequestResponse>('/deployment-requests', {
      rule_ids: ruleIds,
      change_reason: changeReason,
    }),
  approve: (id: string) =>
    api.post<DeploymentRequestDetailResponse>(`/deployment-requests/${id}/approve`, {}),
  reject: (id: string, reviewNote: string) =>
    api.post<DeploymentRequestDetailResponse>(`/deployment-requests/${id}/reject`, {
      review_note: reviewNote,
    }),
  cancel: (id: string) =>
    api.post<DeploymentRequestResponse>(`/deployment-requests/${id}/cancel`, {}),
  // Re-file a fresh PENDING request from a rejected/stale/cancelled one (I3).
  resubmit: (id: string) =>
    api.post<DeploymentRequestResponse>(`/deployment-requests/${id}/resubmit`, {}),
}

// Governance / deployment settings (admin) — lives under notification settings
export type DeploymentGovernanceSettings = {
  mandatory_rule_comments: boolean
  mandatory_comments_deployed_only: boolean
  require_deploy_approval: boolean
}

export const notificationSettingsApi = {
  // Admin read of all governance toggles
  get: () =>
    api.get<DeploymentGovernanceSettings>('/notifications/settings'),
  // Any authenticated user — exposes require_deploy_approval for gating UI
  getPublic: () =>
    api.get<{ mandatory_rule_comments: boolean; require_deploy_approval: boolean }>(
      '/notifications/settings/public'
    ),
  // PUT requires all three fields
  update: (data: DeploymentGovernanceSettings) =>
    api.put<{ success: boolean }>('/notifications/settings', data),
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

// Health override thresholds for index patterns
export type HealthOverridesConfig = {
  detection_latency_warning_ms?: number
  detection_latency_critical_ms?: number
  error_rate_percent?: number
  no_data_minutes?: number
  queue_warning?: number
  queue_critical?: number
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
  // Health alerting thresholds
  health_no_data_minutes: number | null
  health_error_rate_percent: number | null
  health_latency_ms: number | null
  health_alerting_enabled: boolean
  // Per-pattern health overrides
  health_overrides?: HealthOverridesConfig | null
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
  // Timestamp field for pull mode time filtering (must be a date field in the index)
  timestamp_field: string
  // IOC Detection (Push Mode)
  ioc_detection_enabled: boolean
  ioc_field_mappings: Record<string, string[]> | null
  // Audit: email of user who last edited this pattern
  last_edited_by: string | null
}

export type IndexPatternCreate = {
  name: string
  pattern: string
  percolator_index: string
  description?: string | null
  // Health alerting thresholds
  health_no_data_minutes?: number | null
  health_error_rate_percent?: number | null
  health_latency_ms?: number | null
  health_alerting_enabled?: boolean
  // Per-pattern health overrides
  health_overrides?: HealthOverridesConfig | null
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
  timestamp_field?: string
  // IOC Detection (Push Mode)
  ioc_detection_enabled?: boolean
  ioc_field_mappings?: Record<string, string[]> | null
}

export type IndexPatternUpdate = Partial<IndexPatternCreate> & {
  change_reason?: string  // For audit logging
}

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
  getTimeFields: (id: string) =>
    api.get<string[]>(`/index-patterns/${id}/time-fields`),
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
  ioc_matches?: IOCMatch[] | null
  created_at: string
  updated_at: string
  acknowledged_by: string | null
  acknowledged_at: string | null
  owner_id?: string
  owner_username?: string
  owned_at?: string
  // SLA: stamped by the breach-scan job once an open alert passes its target.
  sla_breached?: boolean
  sla_due_at?: string | null
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
  cached?: boolean
  opensearch_available?: boolean
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
    exclude_ioc?: boolean
    exclude_status?: AlertStatus[]
    cluster?: boolean
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.status) searchParams.set('status', params.status)
    if (params?.severity) searchParams.set('severity', params.severity)
    if (params?.rule_id) searchParams.set('rule_id', params.rule_id)
    if (params?.owner) searchParams.set('owner', params.owner)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.offset) searchParams.set('offset', params.offset.toString())
    if (params?.exclude_ioc) searchParams.set('exclude_ioc', 'true')
    if (params?.exclude_status?.length)
      searchParams.set('exclude_status', params.exclude_status.join(','))
    if (params?.cluster === false) searchParams.set('cluster', 'false')
    const query = searchParams.toString()
    return api.get<AlertListResponse>(`/alerts${query ? `?${query}` : ''}`)
  },
  get: (id: string) =>
    api.get<Alert>(`/alerts/${id}`),
  getCounts: (params?: { exclude_ioc?: boolean }) => {
    const query = params?.exclude_ioc ? '?exclude_ioc=true' : ''
    return api.get<AlertCountsResponse>(`/alerts/counts${query}`)
  },
  updateStatus: (id: string, status: AlertStatus) =>
    api.patch<{ success: boolean; status: AlertStatus }>(`/alerts/${id}/status`, { status }),
  delete: (id: string, changeReason?: string) =>
    api.delete(`/alerts/${id}${changeReason ? `?change_reason=${encodeURIComponent(changeReason)}` : ''}`).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  bulkUpdateStatus: (data: { alert_ids: string[]; status: AlertStatus; change_reason?: string }) =>
    api.post<{ success: boolean; updated_count: number }>('/alerts/bulk/status', data).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  bulkDelete: (data: { alert_ids: string[]; change_reason?: string }) =>
    api.post<{ success: boolean; deleted_count: number }>('/alerts/bulk/delete', data).then(() => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
    }),
  // Set status on ALL alerts matching a filter in one server-side
  // update_by_query — for clearing large backlogs without enumerating ids.
  bulkUpdateStatusByQuery: (data: {
    new_status: AlertStatus
    change_reason?: string
    filters: { status?: string; severity?: string; rule_id?: string; exclude_ioc?: boolean; exclude_status?: AlertStatus[] }
  }) =>
    api.post<{ updated: number }>('/alerts/bulk/status-by-query', data).then((r) => {
      queryClient.invalidateQueries({ queryKey: [ALERTS_QUERY_KEY] })
      return r
    }),
  // Omit assigneeId to self-assign; pass a user id to assign a teammate.
  assign: async (alertId: string, assigneeId?: string): Promise<{ message: string; owner: string }> => {
    return api.post(`/alerts/${alertId}/assign`, assigneeId ? { assignee_id: assigneeId } : {})
  },
  unassign: async (alertId: string): Promise<{ message: string }> => {
    return api.post(`/alerts/${alertId}/unassign`)
  },
  // Users the current actor may assign alerts to (their team + self).
  assignableUsers: async (): Promise<{ id: string; email: string }[]> => {
    return api.get(`/alerts/assignable-users`)
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
  rule_id?: string
}

export type IOCMatchStats = {
  total: number
  today: number
  by_threat_level: Record<string, number>
  by_type: Record<string, number>
  top_iocs: Array<{ value: string; count: number }>
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
  recent_ioc_alerts?: RecentAlert[]
  generated_at: string
  ioc_matches?: IOCMatchStats
}

export type RulePrecisionRow = {
  rule_id: string
  rule_title: string
  total: number
  resolved: number
  false_positive: number
  open: number
  precision_pct: number
  fp_rate_pct: number
  alerts_per_day: number
}
export type RulePrecisionResponse = {
  rules: RulePrecisionRow[]
  window_days: number
  opensearch_available: boolean
}

// Stats API
export const statsApi = {
  getDashboard: () =>
    api.get<DashboardStats>('/stats/dashboard'),
  getHealth: () =>
    api.get<{ status: string; opensearch?: unknown; error?: string }>('/stats/health'),
  getRulePrecision: (days = 30) =>
    api.get<RulePrecisionResponse>(`/stats/rule-precision?days=${days}`),
}

// IOC Stats API
export const iocStatsApi = {
  getStats: () =>
    api.get<IOCMatchStats>('/stats/ioc-matches'),
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
  // Sign a user out everywhere (bump token_version) — I4 session revocation.
  revokeSessions: (userId: string) =>
    api.post<{ success: boolean; message: string }>(`/users/${userId}/revoke-sessions`, {}),
  // Explicit admin-initiated promotion of a local account to SSO (sets SSO
  // auth + provenance, removes the local password). Enables SSO login for it.
  promoteToSso: (userId: string) =>
    api.post<UserInfo>(`/users/${userId}/promote-to-sso`),
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
// One enabled provider, as surfaced by GET /auth/sso/status for the login page.
export type SsoStatusProvider = {
  id: string
  name: string
}

export type SsoStatus = {
  // Extended multi-provider status: the list of enabled providers the login
  // page renders one button per. Optional for back-compat with older backends
  // that only emitted the single-provider scalar fields below.
  providers?: SsoStatusProvider[]
  // True when SSO-only enforcement is on (login page hides the password form).
  // Newer field name; `sso_only` kept as a legacy alias.
  sso_enforced?: boolean
  // --- Legacy single-provider fields (still emitted for back-compat) ---
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
  mfa_enforced?: boolean
  mfa_required?: boolean
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
  // Break-glass: invalidate every active session org-wide (I4).
  revokeAllSessions: () =>
    api.post<{ message: string }>('/auth/revoke-all-sessions', {}),
  // SSO login is handled by redirect, not API call. With multi-provider OIDC the
  // login flow is scoped to a provider id; the legacy zero-arg form is kept for
  // back-compat with single-provider deployments.
  getSsoLoginUrl: (providerId?: string) =>
    providerId
      ? `${API_BASE}/auth/sso/login?provider=${encodeURIComponent(providerId)}`
      : `${API_BASE}/auth/sso/login`,
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

// Team types (resource-scoped RBAC). Teams own rules/index-patterns and are the
// target of group->team->role mappings.
export type Team = {
  id: string
  name: string
  description: string | null
  created_at: string
  updated_at: string
}

// Teams API (admin)
export const teamsApi = {
  list: () =>
    api.get<Team[]>('/teams'),
}

// --- Gated bidirectional GitOps inbound import (I6) ---
export type GitImportItem = {
  path: string
  title: string | null
  status: 'new' | 'modified' | 'unchanged'
  rule_id: string | null
}
export type GitImportPreview = { items: GitImportItem[]; total: number }
export type GitImportResult = {
  updated: { path: string; rule_id: string; version: number }[]
  skipped: { path: string; reason: string }[]
}
export const gitopsApi = {
  getInbound: () => api.get<{ enabled: boolean }>('/gitops/inbound'),
  setInbound: (enabled: boolean) => api.put<{ enabled: boolean }>('/gitops/inbound', { enabled }),
  importPreview: (envId: string) =>
    api.post<GitImportPreview>(`/gitops/environments/${envId}/import-preview`, {}),
  importApply: (envId: string, paths: string[]) =>
    api.post<GitImportResult>(`/gitops/environments/${envId}/import`, { paths }),
}

// --- Scheduled reporting + compliance (F5) ---
export type ReportSchedule = {
  id: string
  name: string
  report_type: string
  cadence: string
  framework: string | null
  delivery_type: string
  delivery_target: string | null
  delivery_header_name: string | null
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_at: string
  updated_at: string
}
export type ReportScheduleCreate = {
  name: string
  report_type: string
  cadence: string
  framework?: string | null
  delivery_type?: string
  delivery_target?: string | null
  delivery_header_name?: string | null
  delivery_header_value?: string | null
  enabled?: boolean
}
export type ReportPreview = {
  generated_at: string
  type: string
  framework?: string
  framework_name?: string
  sections: Record<string, unknown>[]
}
export const reportSchedulesApi = {
  list: () => api.get<ReportSchedule[]>('/report-schedules'),
  create: (data: ReportScheduleCreate) => api.post<ReportSchedule>('/report-schedules', data),
  update: (id: string, data: Partial<ReportScheduleCreate>) =>
    api.put<ReportSchedule>(`/report-schedules/${id}`, data),
  remove: (id: string) => api.delete(`/report-schedules/${id}`),
  run: (id: string) => api.post<{ delivered: boolean; report: ReportPreview }>(`/report-schedules/${id}/run`, {}),
  preview: (reportType: string, framework?: string) => {
    const q = new URLSearchParams({ report_type: reportType })
    if (framework) q.set('framework', framework)
    return api.get<ReportPreview>(`/report-schedules/preview?${q.toString()}`)
  },
}

// --- Organizations (multi-tenant / MSSP) ---
export type Organization = {
  id: string
  name: string
  slug: string
  plan: string
  suspended_at: string | null
  deleted_at: string | null
  description: string | null
  created_at: string
  updated_at: string
}
export type OrganizationCreate = {
  name: string
  slug: string
  plan?: string
  description?: string | null
}
export const organizationsApi = {
  list: () => api.get<Organization[]>('/organizations'),
  create: (data: OrganizationCreate) => api.post<Organization>('/organizations', data),
  update: (id: string, data: { name?: string; plan?: string; description?: string; suspended?: boolean }) =>
    api.put<Organization>(`/organizations/${id}`, data),
  remove: (id: string) => api.delete(`/organizations/${id}`),
}

// --- Saved views (named, reusable list filter presets) ---
export type SavedViewResource = 'alerts' | 'ioc_matches' | 'rules' | 'correlation'

export type SavedView = {
  id: string
  name: string
  resource: SavedViewResource
  owner_id: string
  team_id: string | null
  is_shared: boolean
  is_default: boolean
  filters: Record<string, unknown>
  created_at: string
  updated_at: string
}

export type SavedViewCreate = {
  name: string
  resource: SavedViewResource
  filters: Record<string, unknown>
  is_shared?: boolean
  is_default?: boolean
}

export type SavedViewUpdate = {
  name?: string
  filters?: Record<string, unknown>
  is_shared?: boolean
  is_default?: boolean
}

export const savedViewsApi = {
  list: (resource: SavedViewResource) =>
    api.get<SavedView[]>(`/saved-views?resource=${encodeURIComponent(resource)}`),
  create: (data: SavedViewCreate) =>
    api.post<SavedView>('/saved-views', data),
  update: (id: string, data: SavedViewUpdate) =>
    api.put<SavedView>(`/saved-views/${id}`, data),
  remove: (id: string) =>
    api.delete(`/saved-views/${id}`),
}

// --- Case management (investigation workspace) ---
export type CaseStatus = 'open' | 'investigating' | 'contained' | 'closed'

export type CaseSummary = {
  id: string
  number: number
  title: string
  description: string | null
  status: CaseStatus
  severity: string
  owner_id: string | null
  owner_email: string | null
  team_id: string | null
  created_by: string | null
  sla_due_at: string | null
  sla_breached: boolean
  closed_at: string | null
  tags: string[] | null
  alert_count: number
  created_at: string
  updated_at: string
}

export type CaseAlertLink = {
  id: string
  alert_id: string
  alert_title: string | null
  alert_severity: string | null
  added_by: string | null
  added_at: string
}

export type CaseEvent = {
  id: string
  event_type: string
  actor_id: string | null
  actor_email: string | null
  message: string
  event_metadata: Record<string, unknown> | null
  created_at: string
}

export type CaseComment = {
  id: string
  content: string
  user_id: string
  user_email: string | null
  created_at: string
  updated_at: string | null
}

export type CaseDetail = CaseSummary & {
  alerts: CaseAlertLink[]
  events: CaseEvent[]
  comments: CaseComment[]
}

export type CaseCreate = {
  title: string
  description?: string | null
  severity?: string
  owner_id?: string | null
  tags?: string[] | null
  alert_ids?: string[]
}

export const casesApi = {
  list: (params: { status?: string; owner?: string; severity?: string; search?: string; limit?: number; offset?: number } = {}) => {
    const q = new URLSearchParams()
    if (params.status) q.set('status', params.status)
    if (params.owner) q.set('owner', params.owner)
    if (params.severity) q.set('severity', params.severity)
    if (params.search) q.set('search', params.search)
    if (params.limit != null) q.set('limit', String(params.limit))
    if (params.offset != null) q.set('offset', String(params.offset))
    const qs = q.toString()
    return api.get<{ cases: CaseSummary[]; total: number }>(`/cases${qs ? `?${qs}` : ''}`)
  },
  get: (id: string) => api.get<CaseDetail>(`/cases/${id}`),
  create: (data: CaseCreate) => api.post<CaseSummary>('/cases', data),
  update: (id: string, data: { title?: string; description?: string; severity?: string; tags?: string[] }) =>
    api.put<CaseSummary>(`/cases/${id}`, data),
  setStatus: (id: string, statusValue: CaseStatus, note?: string) =>
    api.post<CaseSummary>(`/cases/${id}/status`, { status: statusValue, note }),
  assign: (id: string, ownerId: string | null) =>
    api.post<CaseSummary>(`/cases/${id}/assign`, { owner_id: ownerId }),
  addAlerts: (id: string, alertIds: string[]) =>
    api.post<CaseSummary>(`/cases/${id}/alerts`, { alert_ids: alertIds }),
  removeAlert: (id: string, alertId: string) =>
    api.delete(`/cases/${id}/alerts/${alertId}`),
  addComment: (id: string, content: string) =>
    api.post<CaseComment>(`/cases/${id}/comments`, { content }),
  deleteComment: (id: string, commentId: string) =>
    api.delete(`/cases/${id}/comments/${commentId}`),
}

// --- SLA policy (per-severity triage time targets, in minutes) ---
export type SlaSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type SlaPolicy = {
  enabled: boolean
  targets_minutes: Record<SlaSeverity, number>
}

export const slaApi = {
  get: () => api.get<SlaPolicy>('/sla-policy'),
  update: (policy: SlaPolicy) => api.put<SlaPolicy>('/sla-policy', policy),
}

// ============================================================================
// AI Detection Copilot API (F3)
// ============================================================================

export type GenerateRuleRequest = {
  description: string
  logsource_hint?: string | null
}

export type GenerateRuleResponse = {
  yaml: string
  explanation: string
}

export type SummarizeAlertResponse = {
  summary: string
  recommended_actions: string[]
}

export type ExceptionSuggestion = {
  field: string
  operator: string
  value: unknown
  rationale: string
  risk: string
}

export type SuggestExceptionsResponse = {
  suggestions: ExceptionSuggestion[]
}

export const aiCopilotApi = {
  generateRule: (data: GenerateRuleRequest) =>
    api.post<GenerateRuleResponse>('/ai/copilot/generate-rule', data),
  summarizeAlert: (alertDocument: Record<string, unknown>) =>
    api.post<SummarizeAlertResponse>('/ai/copilot/summarize-alert', {
      alert_document: alertDocument,
    }),
  suggestExceptions: (data: {
    rule_yaml: string
    false_positive_examples: Record<string, unknown>[]
  }) => api.post<SuggestExceptionsResponse>('/ai/copilot/suggest-exceptions', data),
}

// --- Detection-as-Code CI (rule lint + FP backtest + coverage gate) ---

export interface RuleCICheck {
  name: string // lint | field_validation | fp_backtest | coverage
  status: 'pass' | 'warn' | 'fail' | 'skipped'
  detail: string
  data: Record<string, unknown>
}

export interface RuleCIReport {
  passed: boolean
  checks: RuleCICheck[]
  summary: string
}

export interface RuleCICheckOptions {
  index_pattern_id?: string
  fp_threshold?: number
  backtest_days?: number
  run_backtest?: boolean
}

export const ruleCiApi = {
  // Run CI over an arbitrary (possibly unsaved) rule YAML.
  check: (params: { yaml_content: string } & RuleCICheckOptions) =>
    api.post<RuleCIReport>('/rule-ci/check', {
      yaml_content: params.yaml_content,
      index_pattern_id: params.index_pattern_id || null,
      fp_threshold: params.fp_threshold ?? null,
      backtest_days: params.backtest_days ?? null,
      run_backtest: params.run_backtest ?? true,
    }),
  // Run CI over a stored rule (loads its YAML + index pattern server-side).
  checkStored: (ruleId: string, options?: RuleCICheckOptions) =>
    api.post<RuleCIReport>(`/rule-ci/${ruleId}/check`, {
      yaml_content: ' ',
      index_pattern_id: options?.index_pattern_id || null,
      fp_threshold: options?.fp_threshold ?? null,
      backtest_days: options?.backtest_days ?? null,
      run_backtest: options?.run_backtest ?? true,
    }),
}

// --- Audit hardening settings (I5: retention, SIEM forward, PII redaction) ---
export type AuditForwardConfig = {
  enabled: boolean
  format: string
  url: string | null
  header_name: string | null
  has_header_value: boolean
}
export type AuditSettings = {
  retention_days: number
  forward: AuditForwardConfig
  redaction: { enabled: boolean; fields: string[] }
}
export type AuditSettingsUpdate = {
  retention_days: number
  forward: { enabled: boolean; format: string; url?: string | null; header_name?: string | null; header_value?: string | null }
  redaction: { enabled: boolean; fields: string[] }
}
export const auditSettingsApi = {
  get: () => api.get<AuditSettings>('/audit-settings'),
  update: (data: AuditSettingsUpdate) => api.put<AuditSettings>('/audit-settings', data),
  testForward: () => api.post<{ forwarded: number }>('/audit-settings/test-forward', {}),
}

// --- Environment types (Model B: one rule identity, per-env deployment state) ---
// An Environment is a team-owned scope for rule *deployments* (separate
// percolator namespace + pinned version/status per env). The active env is sent
// as X-CHAD-Environment on every request; absent → backend uses the default env.
export type Environment = {
  id: string
  name: string
  team_id: string | null
  is_default: boolean
  require_deploy_approval: boolean
  description: string | null
  opensearch_index_prefix: string | null
  color: string | null
  // Per-env aggregate counts (rules visible to the team / deployed into this env).
  rule_count: number
  deployed_count: number
  // Optional metadata some backends include; tolerated when absent.
  last_deploy_at?: string | null
}

export type EnvironmentCreate = {
  name: string
  description?: string | null
  require_deploy_approval?: boolean
  opensearch_index_prefix?: string | null
  color?: string | null
}

export type EnvironmentUpdate = Partial<EnvironmentCreate> & {
  is_default?: boolean
}

// --- Git config-as-code sync (one-way push). Only off/push are wired. ---
export type GitOpsMode = 'off' | 'push'

export type EnvGitConfig = {
  git_repo_url: string | null
  git_branch: string
  gitops_mode: string
  git_provider: string | null
  has_token: boolean
}

export type EnvGitConfigUpdate = {
  git_repo_url?: string | null
  git_branch?: string
  // Write-only: send to rotate the token, omit to keep the stored one.
  git_token?: string | null
  gitops_mode: GitOpsMode
  git_provider?: string | null
}

export type EnvGitTestResult = { success: boolean; error?: string | null }

// --- Promotion types (advance a target env's pinned version to the source's) ---
// Request body for POST /environments/{targetId}/promote.
export type PromoteRequest = {
  rule_ids: string[]
  // The env the pinned version is taken FROM (the active env in the UI).
  source_environment_id: string
  change_reason: string
}

// Per-rule outcome when the promotion applied immediately (target env gate OFF).
export type PromoteRuleResult = {
  rule_id: string
  status: string
  reason?: string | null
}

// Discriminated result for promote(): either it applied immediately (gate OFF)
// returning per-rule results, or a deployment request was filed for review
// (target env require_deploy_approval is on / 202).
export type PromoteResult =
  | { pendingApproval: false; results: PromoteRuleResult[] }
  | { pendingApproval: true; requestId: string; message: string }

// Environments API. List is team-scoped server-side (returns the envs the
// current user's team(s) can see). Mutations require manage_environments/admin.
export const environmentsApi = {
  list: () =>
    api.get<Environment[]>('/environments'),
  get: (id: string) =>
    api.get<Environment>(`/environments/${id}`),
  create: (data: EnvironmentCreate) =>
    api.post<Environment>('/environments', data),
  update: (id: string, data: EnvironmentUpdate) =>
    api.patch<Environment>(`/environments/${id}`, data),
  delete: (id: string) =>
    api.delete(`/environments/${id}`),
  // Mark this env as the team default (unsets the prior default server-side).
  setDefault: (id: string) =>
    api.patch<Environment>(`/environments/${id}`, { is_default: true }),
  // Promote the pinned source-env version of each rule into the target env.
  // Returns 200 with per-rule results (applied) or 202 pending_approval when
  // the target env's require_deploy_approval gate is on — same seam as deploy().
  promote: async (targetId: string, body: PromoteRequest): Promise<PromoteResult> => {
    const { status, body: data } = await postRaw(
      `/environments/${targetId}/promote`,
      body,
      'promote'
    )
    // 202 = target env requires approval; a deployment request was filed.
    if (status === 202 && data?.status === 'pending_approval') {
      return {
        pendingApproval: true,
        requestId: data.deployment_request_id,
        message: data.message,
      }
    }
    return { pendingApproval: false, results: (data?.results ?? []) as PromoteRuleResult[] }
  },
  // Git config-as-code sync (one-way push). The token is write-only; the
  // response masks it as has_token.
  git: {
    get: (id: string) => api.get<EnvGitConfig>(`/environments/${id}/git`),
    update: (id: string, data: EnvGitConfigUpdate) =>
      api.put<EnvGitConfig>(`/environments/${id}/git`, data),
    test: (id: string) =>
      api.post<EnvGitTestResult>(`/environments/${id}/git/test`, {}),
    disconnect: (id: string) => api.delete(`/environments/${id}/git`),
  },
}

// --- SSO / OIDC provider types ---
export type SsoTokenAuthMethod = 'client_secret_post' | 'client_secret_basic'

// One group->team->role mapping row, embedded in the provider payload (there is
// no separate group-mappings endpoint — they live on the provider).
export type SsoGroupMapping = {
  group_value: string
  team_id: string | null
  role: string
}

// A provider row. The client secret is write-only: never returned by the API,
// so reads expose only `client_secret_set` and the secret is sent on writes.
export type SsoProvider = {
  id: string
  name: string
  enabled: boolean
  issuer_url: string
  client_id: string
  // True when a secret is already stored (lets the editor show "leave blank to
  // keep existing"). The plaintext secret is never returned.
  client_secret_set?: boolean
  token_auth_method: SsoTokenAuthMethod
  scopes: string
  default_role: string
  default_team_id: string | null
  require_email_verified: boolean
  // Group sync
  group_sync_enabled: boolean
  groups_claim: string
  groups_scope: string
  role_claim: string
  // Group->team->role mappings are embedded directly on the provider.
  group_mappings: SsoGroupMapping[]
  // Test-connection provenance
  last_tested_at: string | null
  last_test_success: boolean | null
}

// Create/update payload. client_secret is only included when the admin enters a
// new one; omit it to keep the stored secret unchanged. group_mappings, when
// present, replaces the stored mappings.
export type SsoProviderInput = {
  name: string
  enabled: boolean
  issuer_url: string
  client_id: string
  client_secret?: string
  token_auth_method: SsoTokenAuthMethod
  scopes: string
  default_role: string
  default_team_id?: string | null
  require_email_verified: boolean
  group_sync_enabled: boolean
  groups_claim: string
  groups_scope: string
  role_claim: string
  group_mappings: SsoGroupMapping[]
}

export type SsoTestConnectionResponse = {
  success: boolean
  error?: string | null
}

// SSO enforcement (SSO-only login) is a global GUI flag.
export type SsoEnforcement = {
  sso_enforced: boolean
}

// SSO / OIDC provider admin API. Group mappings are embedded in the provider
// payload (read from provider.group_mappings, written inside create/update).
export const ssoApi = {
  listProviders: () =>
    api.get<SsoProvider[]>('/auth/sso/providers'),
  createProvider: (data: SsoProviderInput) =>
    api.post<SsoProvider>('/auth/sso/providers', data),
  updateProvider: (id: string, data: SsoProviderInput) =>
    api.put<SsoProvider>(`/auth/sso/providers/${id}`, data),
  deleteProvider: (id: string) =>
    api.delete(`/auth/sso/providers/${id}`),
  // Discovery-probe test for a saved provider. Mirrors the OpenSearch/AI
  // "Test Connection" pattern.
  testConnection: (id: string) =>
    api.post<SsoTestConnectionResponse>(`/auth/sso/providers/${id}/test`, {}),
  // Global SSO-only enforcement flag.
  getEnforcement: () =>
    api.get<SsoEnforcement>('/auth/sso/enforcement'),
  updateEnforcement: (sso_enforced: boolean) =>
    api.put<SsoEnforcement>('/auth/sso/enforcement', { sso_enforced }),
}

// --- SCIM 2.0 types ---
// Config read: enabled flag + whether a bearer token has been generated. The
// SCIM base URL is derived on the client (origin + '/api/scim/v2'), not fetched.
export type ScimConfig = {
  enabled: boolean
  token_configured: boolean
}

// One-time token reveal. Returned only by generateToken, never persisted in a
// readable form server-side.
export type ScimTokenResponse = {
  token: string
}

// SCIM 2.0 admin API
export const scimApi = {
  getConfig: () =>
    api.get<ScimConfig>('/scim/config'),
  // Toggle SCIM via a query param (no JSON body).
  setEnabled: (enabled: boolean) =>
    api.post<ScimConfig>(`/scim/enable?enabled=${enabled}`, {}),
  // Generate/regenerate the bearer token; returns the 64-hex token once.
  generateToken: () =>
    api.post<ScimTokenResponse>('/scim/token', {}),
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
  // Tamper-evidence hash-chain fields. Nullable: legacy rows written before the
  // chain existed keep NULL hashes (forward-only chain).
  prev_hash: string | null
  hash: string | null
}

export type AuditLogListResponse = {
  items: AuditLogEntry[]
  total: number
  limit: number
  offset: number
}

// Result of an audit export: the file blob plus whether the backend capped the
// result set at 10k rows (signalled via the X-Audit-Export-Truncated header).
export type AuditExportResult = {
  blob: Blob
  truncated: boolean
}

// Envelope returned by GET /audit/export/chain — the verifiable hash chain.
export type AuditChainExport = {
  verifier_version: string
  exported_at: string
  rows: AuditLogEntry[]
}

// System Log types
export type SystemLogEntry = {
  id: string
  timestamp: string
  level: 'ERROR' | 'WARNING'
  category: 'opensearch' | 'alerts' | 'pull_mode' | 'integrations' | 'background'
  service: string
  message: string
  details: Record<string, unknown> | null
  created_at: string
}

export type SystemLogListResponse = {
  items: SystemLogEntry[]
  total: number
  limit: number
  offset: number
}

export type SystemLogStatsResponse = {
  errors_24h: number
  warnings_24h: number
  by_category: Record<string, { errors: number; warnings: number }>
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
  ): Promise<AuditExportResult> => {
    const params = new URLSearchParams({ format })
    if (filters.action) params.set('action', filters.action)
    if (filters.resource_type) params.set('resource_type', filters.resource_type)
    if (filters.start_date) params.set('start_date', filters.start_date)
    if (filters.end_date) params.set('end_date', filters.end_date)

    const response = await fetch(`${API_BASE}/audit/export?${params}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('chad-token')}` },
    })
    if (!response.ok) throw new Error('Export failed')
    // Backend sets X-Audit-Export-Truncated: true when the 10k cap is hit.
    const truncated = response.headers.get('X-Audit-Export-Truncated') === 'true'
    return { blob: await response.blob(), truncated }
  },
  // Verifiable hash-chain export — returns the chain envelope as a downloadable
  // JSON blob plus the truncation flag, mirroring export() above.
  exportChain: async (): Promise<AuditExportResult> => {
    const response = await fetch(`${API_BASE}/audit/export/chain`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('chad-token')}` },
    })
    if (!response.ok) throw new Error('Export failed')
    const truncated = response.headers.get('X-Audit-Export-Truncated') === 'true'
    return { blob: await response.blob(), truncated }
  },
}

// System Logs API
export const systemLogsApi = {
  list: async (params?: {
    start_time?: string
    end_time?: string
    level?: string
    category?: string
    search?: string
    limit?: number
    offset?: number
  }): Promise<SystemLogListResponse> => {
    const searchParams = new URLSearchParams()
    if (params?.start_time) searchParams.set('start_time', params.start_time)
    if (params?.end_time) searchParams.set('end_time', params.end_time)
    if (params?.level) searchParams.set('level', params.level)
    if (params?.category) searchParams.set('category', params.category)
    if (params?.search) searchParams.set('search', params.search)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.offset) searchParams.set('offset', params.offset.toString())

    const query = searchParams.toString()
    return api.get<SystemLogListResponse>(`/system-logs${query ? `?${query}` : ''}`)
  },

  getStats: async (): Promise<SystemLogStatsResponse> => {
    return api.get<SystemLogStatsResponse>('/system-logs/stats')
  },

  purge: async (before: string): Promise<{ deleted_count: number }> => {
    // Use fetch directly since api.delete returns void but this endpoint returns data
    const response = await fetch(`${API_BASE}/system-logs?before=${encodeURIComponent(before)}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    })
    if (!response.ok) {
      throw new Error('Failed to purge system logs')
    }
    return response.json()
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
export type MappingOrigin = 'MANUAL' | 'AI_SUGGESTED'

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

export type AutoMapResultItem = {
  sigma_field: string
  target_field: string | null
  method: string
  created: boolean
}

export type AutoMapResponse = {
  mapped: number
  skipped: number
  results: AutoMapResultItem[]
}

export type ScorecardResponse = {
  resolvable: number
  total: number
  family: string
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
  autoMap: (data: {
    index_pattern_id: string
    sigma_fields: string[]
    family?: string
  }) => api.post<AutoMapResponse>('/field-mappings/auto-map', data),
  scorecard: (data: {
    index_pattern_id: string
    sigma_fields: string[]
    family?: string
  }) => api.post<ScorecardResponse>('/field-mappings/scorecard', data),
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
  mode: 'push' | 'pull'
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
  data_freshness_warning_minutes: number
  data_freshness_critical_minutes: number
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

// Data freshness types for pull mode
export type DataFreshnessStatus = 'fresh' | 'stale' | 'no_data' | 'no_timestamp' | 'error'

export type DataFreshness = {
  status: DataFreshnessStatus
  last_event_at?: string
  age_minutes?: number
  threshold_minutes?: number
  message?: string
  index?: string
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
  notes: string[]
  has_enabled_rules: boolean
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
  data_freshness?: DataFreshness
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

export type PullModeSettings = {
  max_retries: number
  retry_delay_seconds: number
  consecutive_failures_warning: number
  consecutive_failures_critical: number
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
  getPullModeSettings: () =>
    api.get<PullModeSettings>('/health/pull-mode/settings'),
  updatePullModeSettings: (data: PullModeSettings) =>
    api.put<PullModeSettings>('/health/pull-mode/settings', data),
  getOpenSearchStatus: () =>
    api.get<{
      available: boolean
      circuit_state: 'closed' | 'open' | 'half_open'
      failure_count: number
      last_failure_time: number | null
    }>('/health/opensearch'),
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
  include_ioc_alerts?: boolean
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
  updateAlert: (webhook_id: string, severities: string[], enabled: boolean, include_ioc_alerts?: boolean) =>
    api.put<{ success: boolean }>('/notifications/alerts', { webhook_id, severities, enabled, include_ioc_alerts: include_ioc_alerts ?? false }),
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
  // TI automation: MISP auto-sighting toggle + enrichment cache TTL.
  getAutomation: () => api.get<TIAutomationSettings>('/ti/automation/config'),
  updateAutomation: (data: Partial<TIAutomationSettings>) =>
    api.put<TIAutomationSettings>('/ti/automation/config', data),
}

export type TIAutomationSettings = {
  misp_auto_push: boolean
  cache_ttl_seconds: number
}

// MISP Integration Types
export type MISPConnectionStatus = {
  configured: boolean
  connected: boolean
  error?: string
  instance_url?: string
}

export type MISPEventSummary = {
  id: string
  uuid?: string
  info: string
  date: string
  threat_level: string
  threat_level_id: number
  ioc_count: number
  ioc_summary: Record<string, number>
  tags: string[]
}

export type MISPAttribute = {
  id: string
  type: string
  value: string
  comment?: string
  to_ids: boolean
  on_warning_list: boolean
  warning_list_name?: string
}

export type MISPEventIOCs = {
  event_id: string
  event_info: string
  iocs_by_type: Record<string, MISPAttribute[]>
}

export type MISPIOCsPage = {
  iocs: MISPAttribute[]
  page: number
  limit: number
  has_more: boolean
}

export type MISPImportRequest = {
  event_id: string
  ioc_type: string
  ioc_values: string[]
  index_pattern_id: string | null
}

export type MISPImportResponse = {
  success: boolean
  rule_id: string
  title: string
  message: string
}

export type MISPImportedRuleInfo = {
  misp_url: string
  misp_event_id: string
  misp_event_uuid?: string
  misp_event_info?: string
  misp_event_date?: string
  misp_event_threat_level?: string
  ioc_type: string
  ioc_count: number
  imported_at: string
  last_checked_at?: string
  has_updates: boolean
}

// MISP Sync Types
export type MISPSyncStatus = {
  last_sync_at: string | null
  iocs_synced: number
  sync_duration_ms: number
  redis_ioc_count: number
  opensearch_ioc_count: number
  error_message: string | null
}

export type MISPSyncConfig = {
  enabled: boolean
  interval_minutes: number
  threat_levels: string[]
  max_age_days: number
  ttl_days: number
  tags: string[] | null
  ioc_types: string[] | null
}

export type MISPSyncTriggerResponse = {
  success: boolean
  iocs_fetched: number
  iocs_cached: number
  iocs_indexed: number
  duration_ms: number
  error: string | null
}

// MISP Feedback Types
export type MISPSightingRequest = {
  attribute_uuid: string
  source?: string
  is_false_positive: boolean
}

export type MISPSightingResponse = {
  success: boolean
  sighting_id: string | null
  error: string | null
}

export type MISPEventAttribute = {
  type: string
  value: string
  to_ids?: boolean
}

export type MISPEventRequest = {
  alert_id?: string | null
  info: string
  threat_level: number
  distribution: number
  tags: string[]
  attributes: MISPEventAttribute[]
}

export type MISPEventResponse = {
  success: boolean
  event_id: string | null
  event_uuid: string | null
  error: string | null
}

// IOC Match type (from Push Mode detection)
export type IOCMatch = {
  ioc_type: string
  value: string
  field_name: string
  misp_event_id: string
  misp_event_uuid: string | null
  misp_attribute_uuid: string | null
  misp_event_info: string | null
  threat_level: string
  tags: string[]
}

// MISP API
export const mispApi = {
  getStatus: () =>
    api.get<MISPConnectionStatus>('/misp/status'),
  searchEvents: (params: {
    limit?: number
    date_from?: string
    date_to?: string
    threat_levels?: string
    search_term?: string
  }) => {
    const searchParams = new URLSearchParams()
    if (params.limit) searchParams.set('limit', params.limit.toString())
    if (params.date_from) searchParams.set('date_from', params.date_from)
    if (params.date_to) searchParams.set('date_to', params.date_to)
    if (params.threat_levels) searchParams.set('threat_levels', params.threat_levels)
    if (params.search_term) searchParams.set('search_term', params.search_term)
    return api.get<MISPEventSummary[]>(`/misp/events?${searchParams}`)
  },
  getEventIOCs: (eventId: string, params?: {
    enforce_warninglist?: boolean
    to_ids?: boolean
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.enforce_warninglist !== undefined) {
      searchParams.set('enforce_warninglist', params.enforce_warninglist.toString())
    }
    if (params?.to_ids !== undefined) {
      searchParams.set('to_ids', params.to_ids.toString())
    }
    return api.get<MISPEventIOCs>(`/misp/events/${eventId}/iocs?${searchParams}`)
  },
  getEventIOCsByType: (eventId: string, iocType: string, params?: {
    limit?: number
    page?: number
    search?: string
    to_ids?: boolean
  }) => {
    const searchParams = new URLSearchParams()
    if (params?.limit !== undefined) {
      searchParams.set('limit', params.limit.toString())
    }
    if (params?.page !== undefined) {
      searchParams.set('page', params.page.toString())
    }
    if (params?.search) {
      searchParams.set('search', params.search)
    }
    if (params?.to_ids !== undefined) {
      searchParams.set('to_ids', params.to_ids.toString())
    }
    return api.get<MISPIOCsPage>(`/misp/events/${eventId}/iocs/${encodeURIComponent(iocType)}?${searchParams}`)
  },
  getSupportedTypes: () =>
    api.get<{ types: string[] }>('/misp/supported-types'),
  importRule: (request: MISPImportRequest) =>
    api.post<MISPImportResponse>('/misp/import-rule', request),
  getRuleMISPInfo: (ruleId: string) =>
    api.get<MISPImportedRuleInfo | null>(`/misp/rules/${ruleId}/misp-info`),
}

// MISP Sync API
export const mispSyncApi = {
  getStatus: () =>
    api.get<MISPSyncStatus>('/misp/sync/status'),
  trigger: () =>
    api.post<MISPSyncTriggerResponse>('/misp/sync/trigger'),
  getConfig: () =>
    api.get<MISPSyncConfig>('/misp/sync/config'),
  updateConfig: (config: Partial<MISPSyncConfig>) =>
    api.put<MISPSyncConfig>('/misp/sync/config', config),
}

// MISP Feedback API
export const mispFeedbackApi = {
  recordSighting: (data: MISPSightingRequest) =>
    api.post<MISPSightingResponse>('/misp/feedback/sighting', data),
  createEvent: (data: MISPEventRequest) =>
    api.post<MISPEventResponse>('/misp/feedback/event', data),
}

// Correlation Rules types
export type EntityFieldType = 'sigma' | 'direct'

export type CorrelationRule = {
  id: string
  name: string
  description?: string | null
  rule_a_id: string
  rule_b_id: string
  rule_a_title?: string
  rule_b_title?: string
  entity_field: string
  entity_field_type: EntityFieldType
  time_window_minutes: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  status: 'deployed' | 'undeployed' | 'snoozed'
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
  retryDeadLetter: () =>
    api.post<{ status: string; count: number }>('/queue/dead-letter/retry'),
  retryDeadLetterMessage: (messageId: string) =>
    api.post<{ status: string; message_id: string }>(
      `/queue/dead-letter/${messageId}/retry`,
    ),
}

// Enrichment Webhook types
export type EnrichmentWebhookMethod = 'POST' | 'GET'

export type EnrichmentWebhook = {
  id: string
  name: string
  url: string
  namespace: string
  method: EnrichmentWebhookMethod
  header_name: string | null
  has_credentials: boolean
  timeout_seconds: number
  max_concurrent_calls: number
  cache_ttl_seconds: number
  is_active: boolean
  include_ioc_alerts: boolean
  created_at: string
  updated_at: string
}

export type EnrichmentWebhookCreate = {
  name: string
  url: string
  namespace: string
  method?: EnrichmentWebhookMethod
  header_name?: string
  header_value?: string
  timeout_seconds?: number
  max_concurrent_calls?: number
  cache_ttl_seconds?: number
  is_active?: boolean
  include_ioc_alerts?: boolean
}

export type EnrichmentWebhookUpdate = Partial<Omit<EnrichmentWebhookCreate, 'namespace'>>

export type EnrichmentWebhookTestRequest = {
  url: string
  method?: EnrichmentWebhookMethod
  header_name?: string
  header_value?: string
  timeout_seconds?: number
}

export type EnrichmentWebhookTestResponse = {
  success: boolean
  status_code?: number
  response_body?: Record<string, unknown> | null
  duration_ms?: number
  error?: string
}

// Index Pattern Enrichment Config types
export type IndexPatternEnrichmentConfig = {
  webhook_id: string
  webhook_name: string
  webhook_namespace: string
  field_to_send: string
  is_enabled: boolean
}

// Backend returns array directly
export type IndexPatternEnrichmentsResponse = IndexPatternEnrichmentConfig[]

export type IndexPatternEnrichmentsUpdate = {
  enrichments: Array<{
    webhook_id: string
    field_to_send: string
    is_enabled: boolean
  }>
}

// Enrichment Webhooks API
export const enrichmentWebhooksApi = {
  list: () => api.get<EnrichmentWebhook[]>('/enrichment-webhooks'),
  get: (id: string) => api.get<EnrichmentWebhook>(`/enrichment-webhooks/${id}`),
  create: (data: EnrichmentWebhookCreate) =>
    api.post<EnrichmentWebhook>('/enrichment-webhooks', data),
  update: (id: string, data: EnrichmentWebhookUpdate) =>
    api.patch<EnrichmentWebhook>(`/enrichment-webhooks/${id}`, data),
  delete: (id: string) => api.delete(`/enrichment-webhooks/${id}`),
  test: (id: string) =>
    api.post<EnrichmentWebhookTestResponse>(`/enrichment-webhooks/${id}/test`),
  testUrl: (data: EnrichmentWebhookTestRequest) =>
    api.post<EnrichmentWebhookTestResponse>('/enrichment-webhooks/test', data),
}

// Index Pattern Enrichments API
export const indexPatternEnrichmentsApi = {
  get: (indexPatternId: string) =>
    api.get<IndexPatternEnrichmentsResponse>(`/index-patterns/${indexPatternId}/enrichments`),
  update: (indexPatternId: string, data: IndexPatternEnrichmentsUpdate) =>
    api.put<IndexPatternEnrichmentsResponse>(`/index-patterns/${indexPatternId}/enrichments`, data),
}


