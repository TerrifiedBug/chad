/**
 * React hook for staging rule changes
 *
 * Provides functionality to stage, unstage, and manage pending changes
 * to exceptions, field mappings, and correlation rules before batch saving.
 */

import { useState, useCallback } from 'react'
import type {
  StagedChange,
  StagedChangeType,
  StagedChangeAction,
} from '@/types/staging'

export function useRuleStaging(_ruleId: string) {
  const [stagedChanges, setStagedChanges] = useState<StagedChange[]>([])

  const hasUnsavedChanges = stagedChanges.length > 0

  const stageChange = useCallback((
    type: StagedChangeType,
    action: StagedChangeAction,
    entity: string,
    data: unknown,
    originalData?: unknown
  ) => {
    const change: StagedChange = {
      id: `${type}-${action}-${entity}-${Date.now()}`,
      type,
      action,
      entity,
      data,
      originalData,
      timestamp: new Date()
    }

    setStagedChanges(prev => [...prev, change])
  }, [])

  const unstageChange = useCallback((changeId: string) => {
    setStagedChanges(prev => prev.filter(c => c.id !== changeId))
  }, [])

  const clearStagedChanges = useCallback(() => {
    setStagedChanges([])
  }, [])

  const getChangesByType = useCallback((type: StagedChangeType) => {
    return stagedChanges.filter(c => c.type === type)
  }, [stagedChanges])

  const getChangesByEntity = useCallback((entity: string) => {
    return stagedChanges.filter(c => c.entity === entity)
  }, [stagedChanges])

  return {
    stagedChanges,
    hasUnsavedChanges,
    stageChange,
    unstageChange,
    clearStagedChanges,
    getChangesByType,
    getChangesByEntity
  }
}
