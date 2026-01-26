/**
 * Staging system for rule changes
 *
 * Allows changes to exceptions, field mappings, and correlation rules
 * to be staged locally and saved in a batch.
 */

export type StagedChangeType = 'rule_field' | 'exception' | 'field_mapping' | 'correlation' | 'threshold'
export type StagedChangeAction = 'create' | 'update' | 'delete' | 'enable' | 'disable'

export interface StagedChange {
  id: string
  type: StagedChangeType
  action: StagedChangeAction
  entity: string
  data: ExceptionChangeData | FieldMappingChangeData | CorrelationChangeData | ThresholdChangeData | Record<string, unknown>
  originalData?: ExceptionChangeData | FieldMappingChangeData | CorrelationChangeData | ThresholdChangeData | Record<string, unknown>
  timestamp: Date
}

export interface RuleStagingState {
  stagedChanges: StagedChange[]
  hasUnsavedChanges: boolean
}

export interface ExceptionChangeData {
  rule_id: string
  field?: string
  operator?: string
  value?: string
  reason?: string
  is_active?: boolean
}

export interface FieldMappingChangeData {
  sigma_field: string
  log_field: string
  index_pattern_id: string
}

export interface CorrelationChangeData {
  correlation_rule_id: string
  enabled: boolean
}

export interface ThresholdChangeData {
  threshold_enabled?: boolean
  threshold_count?: number
  threshold_window_minutes?: number
  threshold_group_by?: string
}
